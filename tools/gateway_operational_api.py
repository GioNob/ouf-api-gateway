from __future__ import annotations

import json
from dataclasses import asdict

from tools.operational_incidents import SQLiteOperationalIncidentStore


class GatewayOperationalOwnerAPI:
    """Private owner API contract behind Gateway mediation.

    The HTTP hosting adapter may vary; this class freezes trust, bounded-query and
    redaction semantics independently from APISIX or a future control-plane server.
    """

    INCIDENTS_PATH = "/api/internal/v1/gateway/operations/incidents"
    SUMMARY_PATH = "/api/internal/v1/gateway/operations/summary"

    def __init__(self, store: SQLiteOperationalIncidentStore, *, summary_authorizer=None, tenant_id=None):
        self.store = store
        self.summary_authorizer = summary_authorizer
        self.tenant_id = tenant_id

    def handle(self, path: str, headers: dict[str, str], body: bytes | str | None = None) -> tuple[int, dict]:
        if headers.get("X-OUF-Gateway-Verified") != "true":
            return 401, {"code": "TRUSTED_GATEWAY_CONTEXT_REQUIRED"}
        if not headers.get("X-OUF-Principal-ID") or not headers.get("X-OUF-Authorization-Decision-Ref"):
            return 403, {"code": "VERIFIED_AUTHORIZATION_CONTEXT_REQUIRED"}
        query = self._query(body)
        limit = query.get("limit", 50)
        if type(limit) is not int or limit < 1 or limit > 100:
            return 400, {"code": "OPERATIONAL_LIMIT_INVALID"}
        if path == self.INCIDENTS_PATH:
            state = query.get("state")
            try:
                items = self.store.list_incidents(lifecycle_state=state, limit=limit)
            except ValueError:
                return 400, {"code": "OPERATIONAL_STATE_INVALID"}
            return 200, {"items": [asdict(item) for item in items], "partial": False}
        if path == self.SUMMARY_PATH:
            # This legacy store is not tenant-partitioned. Bind it to one deployment
            # tenant explicitly and require a local policy adapter; a Gateway
            # decision header alone never grants access to platform incidents.
            if not self.tenant_id or self.summary_authorizer is None:
                return 503, {"code": "OWNER_AUTHORIZATION_UNAVAILABLE"}
            if headers.get("X-OUF-Tenant-ID") != self.tenant_id:
                return 403, {"code": "NOT_AUTHORIZED"}
            resource = {"resourceType": "capability", "tenantId": self.tenant_id,
                        "module": "GATEWAY", "detailLevel": "TENANT_OPERATIONAL"}
            try:
                allowed = self.summary_authorizer(headers, "ouf.gateway.operations.summary", resource)
            except Exception:
                return 503, {"code": "OWNER_AUTHORIZATION_UNAVAILABLE"}
            if allowed is not True:
                return 403, {"code": "NOT_AUTHORIZED"}
            if query.get("sourceId") is not None:
                return 400, {"code": "SOURCE_FILTER_NOT_SUPPORTED"}
            try:
                summary = self.store.summary(limit=limit, since=query.get("since"))
            except ValueError:
                return 400, {"code": "OPERATIONAL_WINDOW_INVALID"}
            if self.store.has_restricted_incidents():
                summary["items"] = [i for i in summary["items"] if i["visibility_class"] in {"PUBLIC_OPERATIONAL", "TENANT_OPERATIONAL"}]
                summary.update(partial=True, status="UNKNOWN", authorization="REDACTED")
                summary.pop("openIncidents", None); summary.pop("recoveringIncidents", None)
            return 200, summary
        return 404, {"code": "OWNER_OPERATION_NOT_FOUND"}

    @staticmethod
    def _query(body: bytes | str | None) -> dict:
        if body in (None, b"", ""):
            return {}
        try:
            value = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {"limit": 0}
        return value if isinstance(value, dict) else {"limit": 0}
