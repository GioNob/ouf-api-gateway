import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from jsonschema import Draft202012Validator, FormatChecker

from tools.compile_config import ROOT


class DispatchError(RuntimeError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail

    def problem(self) -> dict:
        return {"type": f"urn:ouf:problem:{self.code.lower()}", "title": self.code, "status": self.status, "code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class TrustedIdentity:
    service_principal_id: str
    principal_id: str
    tenant_id: str
    actor_type: str
    authentication_context_ref: str
    authorization_decision_ref: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class BackendResponse:
    status: int
    body: bytes
    headers: dict[str, str]


class UpstreamPort(Protocol):
    def execute(self, service: str, path: str, body: bytes, headers: dict[str, str], timeout_seconds: int) -> BackendResponse: ...


class MCPDispatcher:
    FORWARDED_RESPONSE_HEADERS = frozenset({"content-type", "retry-after", "x-backend-request-id"})
    REQUIRED_HEADERS = ("X-Correlation-ID", "Idempotency-Key", "X-Tool-Attempt-ID")

    def __init__(self, compiled: dict, upstream: UpstreamPort, schema_path: Path | None = None):
        self.upstream = upstream
        self.schema = json.loads((schema_path or ROOT / "schemas" / "mcp-gateway-dispatch-v1.json").read_text())
        self.routes = {}
        for route in compiled["routes"]:
            capability = route.get("x-ouf-capability", {})
            policy = route.get("x-ouf-policy", {})
            is_mcp_route = (
                capability.get("toolEligible")
                and route.get("labels", {}).get("exposure") == "internal"
                and policy.get("identity") == "M2M"
                and "ouf-mcp-server" in policy.get("allowedServiceIdentities", [])
            )
            if is_mcp_route:
                capability_id = capability["capabilityId"]
                if capability_id in self.routes:
                    raise DispatchError(503, "AMBIGUOUS_CAPABILITY_BINDING", capability_id)
                self.routes[capability_id] = route

    def dispatch(self, raw_body: bytes, request_headers: dict[str, str], identity: TrustedIdentity) -> BackendResponse:
        headers = {name.lower(): value for name, value in request_headers.items()}
        try:
            envelope = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DispatchError(400, "INVALID_MCP_GATEWAY_REQUEST", "invalid JSON") from exc
        errors = sorted(Draft202012Validator(self.schema, format_checker=FormatChecker()).iter_errors(envelope), key=lambda error: list(error.path))
        if errors:
            raise DispatchError(400, "INVALID_MCP_GATEWAY_REQUEST", errors[0].message)
        route = self.routes.get(envelope["CapabilityID"])
        if route is None:
            raise DispatchError(404, "CAPABILITY_BINDING_NOT_FOUND", envelope["CapabilityID"])
        capability = route["x-ouf-capability"]
        policy = route["x-ouf-policy"]
        if len(raw_body) > policy["maxRequestBytes"]:
            raise DispatchError(413, "REQUEST_TOO_LARGE", "request exceeds route limit")
        expected_binding = f"capability://{capability['capabilityId']}"
        if envelope["GatewayBindingRef"] != expected_binding:
            raise DispatchError(409, "CAPABILITY_BINDING_MISMATCH", "logical binding does not match capability")
        if envelope["OperationClass"] != capability["operationType"]:
            raise DispatchError(409, "CAPABILITY_BINDING_MISMATCH", "operation class does not match published capability")
        if envelope["Owner"] != capability["owner"]:
            raise DispatchError(409, "CAPABILITY_BINDING_MISMATCH", "owner does not match published capability")
        if identity.service_principal_id not in policy["allowedServiceIdentities"]:
            raise DispatchError(403, "CAPABILITY_ACCESS_DENIED", "service identity is not allowed")
        if policy["allowedActorTypes"] and identity.actor_type not in policy["allowedActorTypes"]:
            raise DispatchError(403, "CAPABILITY_ACCESS_DENIED", "actor type is not allowed")
        if capability["humanRequired"] and identity.actor_type != "HUMAN_USER":
            raise DispatchError(403, "TRUSTED_HUMAN_REQUIRED", "MCP identities cannot invoke this capability")
        if policy["requiredScope"] not in identity.scopes:
            raise DispatchError(403, "CAPABILITY_ACCESS_DENIED", "required scope is absent")
        body_identity = envelope["Identity"]
        trusted = (identity.service_principal_id, identity.principal_id, identity.tenant_id, identity.actor_type, identity.authentication_context_ref)
        claimed = (body_identity["ServicePrincipalID"], body_identity["PrincipalID"], body_identity["TenantID"], body_identity["ActorType"], body_identity["AuthenticationContextRef"])
        if claimed != trusted:
            raise DispatchError(403, "IDENTITY_CONTEXT_MISMATCH", "body identity differs from authenticated context")
        if envelope["AuthorizationDecisionRef"] != identity.authorization_decision_ref:
            raise DispatchError(403, "AUTHORIZATION_CONTEXT_MISMATCH", "decision reference differs from authenticated context")
        for name in self.REQUIRED_HEADERS:
            if not headers.get(name.lower()):
                raise DispatchError(400, "MISSING_GOVERNANCE_HEADER", name)
        if headers["x-correlation-id"] != envelope["CorrelationID"] or headers["idempotency-key"] != envelope["IdempotencyKey"] or headers["x-tool-attempt-id"] != envelope["AttemptID"]:
            raise DispatchError(409, "GOVERNANCE_CONTEXT_MISMATCH", "headers and admitted attempt differ")
        downstream_headers = {
            "Content-Type": "application/json",
            "X-Correlation-ID": envelope["CorrelationID"],
            "Idempotency-Key": envelope["IdempotencyKey"],
            "X-Tool-Attempt-ID": envelope["AttemptID"],
            "X-OUF-Capability-ID": capability["capabilityId"],
            "X-OUF-Actor-Type": identity.actor_type,
            "X-OUF-Principal-ID": identity.principal_id,
            "X-OUF-Tenant-ID": identity.tenant_id,
            "X-OUF-Authorization-Decision-Ref": envelope["AuthorizationDecisionRef"],
        }
        response = self.upstream.execute(route["service_id"], route["plugins"]["proxy-rewrite"]["uri"], json.dumps(envelope["Arguments"], separators=(",", ":")).encode(), downstream_headers, policy["timeoutSeconds"])
        safe_headers = {name: value for name, value in response.headers.items() if name.lower() in self.FORWARDED_RESPONSE_HEADERS}
        return BackendResponse(response.status, response.body, safe_headers)
