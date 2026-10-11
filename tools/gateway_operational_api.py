from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict

from tools.operational_bookmarks import PublicationBookmarks
from tools.operational_cursor import CursorRejected, MAX_BYTES
from tools.operational_incidents import SQLiteOperationalIncidentStore


class GatewayOperationalOwnerAPI:
    """Private reference owner adapter. Hosting MUST inject current local policy.

    owner_authorize(headers, capability, resource) resolves verified identity and
    evaluates fresh owner policy. Coarse headers are never a fine-grained grant.
    Missing integration fails closed. The callback returns identity, policyRef,
    allowed, permittedDetailLevel and the exact evaluated resource.
    """
    INCIDENTS_PATH = "/api/internal/v1/gateway/operations/incidents"
    SUMMARY_PATH = "/api/internal/v1/gateway/operations/summary"

    def __init__(self, store: SQLiteOperationalIncidentStore, owner_authorize=None):
        self.store, self.owner_authorize = store, owner_authorize
        self.bookmarks = PublicationBookmarks(store)

    def handle(self, path: str, headers: dict[str, str], body: bytes | str | None = None) -> tuple[int, dict]:
        if headers.get("X-OUF-Gateway-Verified") != "true":
            return 401, {"code": "TRUSTED_GATEWAY_CONTEXT_REQUIRED"}
        if not headers.get("X-OUF-Principal-ID") or not headers.get("X-OUF-Authorization-Decision-Ref"):
            return 403, {"code": "VERIFIED_AUTHORIZATION_CONTEXT_REQUIRED"}
        if path not in {self.INCIDENTS_PATH, self.SUMMARY_PATH}:
            return 404, {"code": "OWNER_OPERATION_NOT_FOUND"}
        try:
            query = self._query(body, path == self.INCIDENTS_PATH)
            capability = "ouf.gateway.operations.incidents" if path == self.INCIDENTS_PATH else "ouf.gateway.operations.summary"
            identity, policy_ref = self._decision(headers, capability)

            def visible(item):
                try:
                    row_identity, row_policy = self._decision(headers, capability, item["incident_id"], item.get("endpoint_ref"))
                except CursorRejected as exc:
                    if exc.status == 403:
                        return False
                    raise
                if row_identity != identity or row_policy != policy_ref:
                    raise CursorRejected(409, "OPERATIONAL_POLICY_CHANGED")
                return True

            if query.get("coverage") or "resumeFrom" in query:
                def collection(current_identity, current_policy):
                    fresh_identity, fresh_policy = self._decision(headers, capability)
                    if fresh_identity != current_identity or fresh_policy != current_policy:
                        raise CursorRejected(409, "OPERATIONAL_POLICY_CHANGED")
                    return True
                bookmarks = self.bookmarks.with_authorization(collection)
                if "resumeFrom" in query:
                    result = bookmarks.resume(query["resumeFrom"], identity, policy_ref, visible, query.get("limit", 50))
                elif "cursor" in query:
                    result = bookmarks.page(query["cursor"], identity, policy_ref, visible)
                else:
                    result = bookmarks.start({k: v for k, v in query.items() if k not in {"snapshot", "coverage"}}, identity, policy_ref, visible)
            elif query.get("snapshot") or "cursor" in query:
                result = self.store.cursors.page(query, identity, policy_ref, visible)
            else:
                limit, since = query.get("limit", 50), query.get("since")
                if path == self.SUMMARY_PATH:
                    items = self.store.list_incidents(limit=limit + 1, since=since)
                    result = {"module": "GATEWAY", "items": [asdict(i) for i in items[:limit]], "partial": False,
                              "truncated": len(items) > limit, "priorityProfile": "ouf.incident-priority.v1"}
                else:
                    items = self.store.list_incidents(lifecycle_state=query.get("state"), limit=limit + 1, since=since)
                    result = {"module": "GATEWAY", "items": [asdict(i) for i in items[:limit]], "partial": False,
                              "truncated": len(items) > limit, "priorityProfile": "ouf.incident-priority.v1"}
                original = result["items"]
                result["items"] = [item for item in original if visible(item)]
                if path == self.SUMMARY_PATH:
                    states = {item["lifecycle_state"] for item in result["items"]}
                    result["status"] = "DEGRADED" if "OPEN" in states else ("RECOVERING" if "RECOVERING" in states else "HEALTHY")
                    if result["truncated"]:
                        result["partial"] = True
                        result["status"] = "UNKNOWN"
                if len(result["items"]) != len(original):
                    result["partial"] = True
                    result["unavailable"] = [{"module": "GATEWAY", "reason": "REDACTED_BY_CURRENT_POLICY"}]
                    # A collection grant alone does not justify counters once an
                    # incident decision explicitly denies a resource.
                    for key in ("openIncidents", "recoveringIncidents"):
                        result.pop(key, None)
                    if path == self.SUMMARY_PATH:
                        result["status"] = "UNKNOWN"
            if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_BYTES:
                raise CursorRejected(503, "OPERATIONAL_RESPONSE_CAPACITY")
            return 200, result
        except CursorRejected as exc:
            return exc.status, {"code": exc.code}
        except sqlite3.OperationalError:
            return 503, {"code": "OPERATIONAL_STORE_UNAVAILABLE", "retryable": True}
        except Exception:
            # Unknown failures are not classified as transient or disclosed.
            return 503, {"code": "OPERATIONAL_OWNER_UNAVAILABLE", "retryable": False}

    def _decision(self, headers, capability, incident_id=None, endpoint_ref=None):
        if self.owner_authorize is None:
            raise CursorRejected(503, "OWNER_LOCAL_AUTHORIZATION_UNAVAILABLE")
        tenant = headers.get("X-OUF-Tenant-ID")
        if not tenant:
            raise CursorRejected(403, "TENANT_CONTEXT_REQUIRED")
        resource = {"type": "operational", "id": incident_id, "tenant": tenant,
                    "attributes": {"module": "GATEWAY", "incidentScope": "PLATFORM", "detailLevel": "RESTRICTED_OPERATIONAL"}}
        if endpoint_ref:
            resource["attributes"]["endpointRef"] = endpoint_ref
        decision = self.owner_authorize(dict(headers), capability, resource)
        if not isinstance(decision, dict) or decision.get("allowed") is not True:
            raise CursorRejected(403, "OWNER_CAPABILITY_DENIED")
        identity = decision.get("identity")
        if not isinstance(identity, dict) or identity.get("principal") != headers["X-OUF-Principal-ID"] or identity.get("tenant") != tenant or identity.get("actor") not in {"HUMAN", "SERVICE", "AI_AGENT"}:
            raise CursorRejected(403, "OWNER_IDENTITY_UNPROVEN")
        if decision.get("resource") != resource or decision.get("permittedDetailLevel") != "RESTRICTED_OPERATIONAL" or not isinstance(decision.get("policyRef"), str) or not decision["policyRef"]:
            raise CursorRejected(403, "OWNER_RESOURCE_GRANT_UNPROVEN")
        return identity, decision["policyRef"]

    def _query(self, body, incidents):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result
        try:
            if body in (None, b"", ""):
                query = {}
            else:
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="strict")
                if not isinstance(body, str) or len(body.encode()) > 65536:
                    raise ValueError("size")
                query = json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
            allowed = {"limit", "since", "state", "snapshot", "cursor", "coverage", "resumeFrom"} if incidents else {"limit", "since"}
            if not isinstance(query, dict) or set(query) - allowed or any(v is None for v in query.values()):
                raise ValueError("shape")
            if "coverage" in query and query["coverage"] is not True:
                raise ValueError("coverage")
            if "resumeFrom" in query:
                if set(query) - {"resumeFrom", "limit"}:
                    raise ValueError("resume shape")
                if not isinstance(query["resumeFrom"], str) or str(uuid.UUID(query["resumeFrom"])) != query["resumeFrom"] or uuid.UUID(query["resumeFrom"]).int == 0:
                    raise ValueError("resume")
            elif "cursor" in query:
                expected = {"cursor", "coverage"} if "coverage" in query else {"cursor"}
                if set(query) != expected or not isinstance(query["cursor"], str):
                    raise ValueError("cursor")
                if "coverage" in query and (str(uuid.UUID(query["cursor"])) != query["cursor"] or uuid.UUID(query["cursor"]).int == 0):
                    raise ValueError("cursor")
            elif "coverage" in query:
                if query.get("snapshot") is not True or set(query) - {"snapshot", "coverage", "state", "limit"}:
                    raise ValueError("coverage shape")
            if "snapshot" in query and type(query["snapshot"]) is not bool:
                raise ValueError("snapshot")
        except (ValueError, TypeError, UnicodeError):
            raise CursorRejected(400, "OPERATIONAL_QUERY_INVALID")
        if type(query.get("limit", 50)) is not int or not 1 <= query.get("limit", 50) <= 100:
            raise CursorRejected(400, "OPERATIONAL_LIMIT_INVALID")
        if "state" in query and (not isinstance(query["state"], str) or query["state"] not in {"OPEN", "RECOVERING", "RESOLVED"}):
            raise CursorRejected(400, "OPERATIONAL_STATE_INVALID")
        if "since" in query:
            try:
                query["since"] = self.store._since(query["since"])
            except (ValueError, TypeError):
                raise CursorRejected(400, "OPERATIONAL_SINCE_INVALID")
        return query
