import json
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

from jsonschema import Draft202012Validator

from tools.compile_config import ROOT
from tools.mcp_dispatch import BackendResponse, DispatchError, TrustedIdentity


class RecoveryUpstreamPort(Protocol):
    def recover(self, service: str, path: str, headers: dict[str, str], timeout_seconds: int) -> BackendResponse: ...


class MCPRecoveryMediator:
    def __init__(self, compiled: dict, upstream: RecoveryUpstreamPort, service_identity: str, schema_path: Path | None = None):
        self.upstream = upstream
        self.service_identity = service_identity
        self.schema = json.loads((schema_path or ROOT / "schemas" / "mcp-gateway-recovery-v1.json").read_text())
        self.bindings = {}
        for route in compiled["routes"]:
            binding = route.get("x-ouf-recovery-binding")
            capability = route.get("x-ouf-capability", {})
            if not binding or not capability.get("toolEligible"):
                continue
            capability_id = capability["capabilityId"]
            candidate = (binding, route["x-ouf-policy"])
            if capability_id in self.bindings and self.bindings[capability_id] != candidate:
                raise DispatchError(503, "AMBIGUOUS_RECOVERY_BINDING", capability_id)
            self.bindings[capability_id] = candidate

    def recover(self, raw_body: bytes, request_headers: dict[str, str], identity: TrustedIdentity) -> BackendResponse:
        if identity.service_principal_id != self.service_identity or "mcp.attempt.recover" not in identity.scopes:
            raise DispatchError(403, "RECOVERY_ACCESS_DENIED", "MCP recovery workload identity is not authorized")
        try:
            request = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DispatchError(400, "INVALID_RECOVERY_REQUEST", "invalid JSON") from exc
        errors = sorted(Draft202012Validator(self.schema).iter_errors(request), key=lambda error: list(error.path))
        if errors:
            raise DispatchError(400, "INVALID_RECOVERY_REQUEST", errors[0].message)
        binding_and_policy = self.bindings.get(request["CapabilityID"])
        if binding_and_policy is None:
            raise DispatchError(404, "RECOVERY_BINDING_NOT_FOUND", request["CapabilityID"])
        binding, policy = binding_and_policy
        if request["Owner"] != binding["owner"]:
            raise DispatchError(409, "RECOVERY_BINDING_MISMATCH", "owner does not match the capability registry")
        correlation = next((value for name, value in request_headers.items() if name.lower() == "x-correlation-id"), "")
        if not correlation or correlation != request["CorrelationID"]:
            raise DispatchError(409, "GOVERNANCE_CONTEXT_MISMATCH", "correlation header and recovery request differ")
        path = binding["pathTemplate"].replace("{backendRequestId}", quote(request["BackendRequestID"], safe=""))
        response = self.upstream.recover(binding["service"], path, {
            "Accept": "application/json",
            "X-Correlation-ID": correlation,
            "X-OUF-Capability-ID": request["CapabilityID"],
            "X-OUF-Recovery-For": request["BackendRequestID"],
        }, policy["timeoutSeconds"])
        if response.status != 200:
            raise DispatchError(503, "OWNER_RECOVERY_UNAVAILABLE", "owner outcome is not authoritatively available")
        if len(response.body) > 65536:
            raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "owner evidence exceeds the bounded response size")
        try:
            evidence = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "owner returned invalid JSON") from exc
        allowed = {"BackendRequestID", "Outcome", "OutcomeCode", "ResultRef", "ActualToolCalls", "ActualResultBytes"}
        if set(evidence) - allowed or evidence.get("BackendRequestID") != request["BackendRequestID"]:
            raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "owner evidence does not match backend request")
        if evidence.get("Outcome") not in {"SUCCEEDED", "FAILED", "NOT_DISPATCHED", "UNKNOWN"}:
            raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "owner outcome is not recognized")
        for field in ("OutcomeCode", "ResultRef"):
            if not isinstance(evidence.get(field, ""), str) or len(evidence.get(field, "")) > 512:
                raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "owner evidence metadata is invalid")
        for field in ("ActualToolCalls", "ActualResultBytes"):
            if isinstance(evidence.get(field, 0), bool) or not isinstance(evidence.get(field, 0), int) or evidence.get(field, 0) < 0:
                raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "owner cost is invalid")
        if evidence["Outcome"] == "NOT_DISPATCHED" and (evidence.get("OutcomeCode") != "OWNER_PROVES_NO_DISPATCH" or evidence.get("ActualToolCalls", 0) != 0 or evidence.get("ActualResultBytes", 0) != 0):
            raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "no-dispatch outcome lacks authoritative zero-cost proof")
        if evidence["Outcome"] == "UNKNOWN" and (evidence.get("ActualToolCalls", 0) != 0 or evidence.get("ActualResultBytes", 0) != 0):
            raise DispatchError(502, "INVALID_OWNER_EVIDENCE", "unknown outcome cannot assert actual cost")
        normalized = {
            "BackendRequestID": evidence["BackendRequestID"],
            "Outcome": evidence["Outcome"],
            "OutcomeCode": evidence.get("OutcomeCode", ""),
            "ResultRef": evidence.get("ResultRef", ""),
            "ActualToolCalls": evidence.get("ActualToolCalls", 0),
            "ActualResultBytes": evidence.get("ActualResultBytes", 0),
        }
        return BackendResponse(200, json.dumps(normalized, separators=(",", ":")).encode(), {"Content-Type": "application/json"})
