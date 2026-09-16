import json
from pathlib import Path
from typing import Protocol

from jsonschema import Draft202012Validator

from tools.compile_config import ROOT
from tools.mcp_dispatch import BackendResponse, DispatchError, TrustedIdentity


class EvidenceInboxPort(Protocol):
    def ingest(self, service: str, path: str, body: bytes, headers: dict[str, str], timeout_seconds: int) -> BackendResponse: ...


class MCPEvidenceIngressMediator:
    """Governed owner -> MCP Evidence Inbox boundary.

    BackendOwner is derived from trusted workload identity. A payload owner is
    accepted only as a consistency assertion and can never select the owner.
    """

    OWNER_BY_SERVICE = {
        "ouf-udp-object-resolution": "udp-object-resolution",
    }
    MCP_SERVICE = "ouf-mcp-server"
    MCP_PATH = "/internal/evidence/v1/owner-results"
    REQUIRED_SCOPE = "mcp.evidence.submit"

    def __init__(self, inbox: EvidenceInboxPort, schema_path: Path | None = None):
        self.inbox = inbox
        self.schema = json.loads((schema_path or ROOT / "schemas" / "mcp-evidence-ingress-v1.json").read_text())

    def ingest(self, raw_body: bytes, request_headers: dict[str, str], identity: TrustedIdentity) -> BackendResponse:
        owner = self.OWNER_BY_SERVICE.get(identity.service_principal_id)
        if owner is None or self.REQUIRED_SCOPE not in identity.scopes:
            raise DispatchError(403, "EVIDENCE_ACCESS_DENIED", "owner workload is not authorized for evidence ingress")
        if len(raw_body) > 1048576:
            raise DispatchError(413, "EVIDENCE_TOO_LARGE", "evidence payload exceeds ingress bound")
        try:
            value = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DispatchError(400, "INVALID_EVIDENCE", "invalid JSON") from exc
        errors = sorted(Draft202012Validator(self.schema).iter_errors(value), key=lambda error: list(error.path))
        if errors:
            raise DispatchError(400, "INVALID_EVIDENCE", errors[0].message)
        if value.get("BackendOwner", owner) != owner:
            raise DispatchError(409, "EVIDENCE_OWNER_MISMATCH", "payload owner differs from trusted workload identity")
        if value["Kind"] == "OWNER_PROVES_NO_DISPATCH":
            if value["TerminalState"] != "FAILED" or value["OutcomeCode"] != "DISPATCH_NOT_STARTED" or value["ActualDistinctObjects"] != 0 or value["ObjectHashes"] or value.get("ResultRef"):
                raise DispatchError(400, "INVALID_EVIDENCE", "no-dispatch evidence must be canonical zero-cost proof")
        elif not value.get("ResultRef"):
            raise DispatchError(400, "INVALID_EVIDENCE", "owner result requires ResultRef")
        versions = {item.split(":", 1)[0] for item in value["ObjectHashes"]}
        if versions - {"v1"}:
            raise DispatchError(400, "UNSUPPORTED_OBJECT_HASH_VERSION", "object hash version is not admitted")
        correlation = next((v for k, v in request_headers.items() if k.lower() == "x-correlation-id"), "")
        if not correlation:
            raise DispatchError(400, "MISSING_CORRELATION_ID", "correlation id is required")
        canonical = {
            "ClaimedOwner": owner,
            "BackendRequestID": value["BackendRequestID"],
            "Kind": value["Kind"],
            "TerminalState": value["TerminalState"],
            "OutcomeCode": value["OutcomeCode"],
            "ResultRef": value.get("ResultRef", ""),
            "ActualDistinctObjects": value["ActualDistinctObjects"],
            "ObjectHashes": sorted(value["ObjectHashes"]),
        }
        body = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
        response = self.inbox.ingest(self.MCP_SERVICE, self.MCP_PATH, body, {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Correlation-ID": correlation,
            "X-OUF-Trusted-Backend-Owner": owner,
            "X-OUF-Source-Service": identity.service_principal_id,
        }, 3)
        if response.status not in {200, 201, 409}:
            raise DispatchError(503, "EVIDENCE_INBOX_UNAVAILABLE", "MCP Evidence Inbox unavailable")
        return response
