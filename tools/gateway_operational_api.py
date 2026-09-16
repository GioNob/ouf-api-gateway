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

    def __init__(self, store: SQLiteOperationalIncidentStore):
        self.store = store

    def handle(self, path: str, headers: dict[str, str], body: bytes | str | None = None) -> tuple[int, dict]:
        if headers.get("X-OUF-Gateway-Verified") != "true":
            return 401, {"code": "TRUSTED_GATEWAY_CONTEXT_REQUIRED"}
        if not headers.get("X-OUF-Principal-ID") or not headers.get("X-OUF-Authorization-Decision-Ref"):
            return 403, {"code": "VERIFIED_AUTHORIZATION_CONTEXT_REQUIRED"}
        query = self._query(body)
        limit = query.get("limit", 50)
        if not isinstance(limit, int) or limit < 1 or limit > 100:
            return 400, {"code": "OPERATIONAL_LIMIT_INVALID"}
        if path == self.INCIDENTS_PATH:
            state = query.get("state")
            try:
                items = self.store.list_incidents(lifecycle_state=state, limit=limit)
            except ValueError:
                return 400, {"code": "OPERATIONAL_STATE_INVALID"}
            return 200, {"items": [asdict(item) for item in items], "partial": False}
        if path == self.SUMMARY_PATH:
            return 200, self.store.summary(limit=limit)
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
