"""HTTP owner bookmark contract, without a deployment authorizer."""
import json
import tempfile
import unittest
from pathlib import Path
from tools.gateway_operational_api import GatewayOperationalOwnerAPI
from tools.operational_incidents import SQLiteOperationalIncidentStore

class OwnerBookmarkHTTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "owner.sqlite"
        self.store = SQLiteOperationalIncidentStore(self.path)
        self.headers = {"X-OUF-Gateway-Verified": "true", "X-OUF-Principal-ID": "operator",
                        "X-OUF-Tenant-ID": "tenant", "X-OUF-Authorization-Decision-Ref": "current"}
        self.allowed = True
        self.row_allowed = True
        self.policy = "policy:1"
        self.decisions = []
        def authorize(headers, capability, resource):
            self.decisions.append((capability, resource))
            return {"allowed": self.allowed and (not resource["id"] or self.row_allowed),
                    "identity": {"principal": headers["X-OUF-Principal-ID"],
                                 "tenant": headers["X-OUF-Tenant-ID"], "actor": "HUMAN",
                                 "authenticationContextRef": headers["X-OUF-Authorization-Decision-Ref"]},
                    "policyRef": self.policy, "resource": resource,
                    "permittedDetailLevel": "RESTRICTED_OPERATIONAL"}
        self.authorize = authorize
        self.api = GatewayOperationalOwnerAPI(self.store, authorize)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def incident(self, key):
        return self.store.open_incident(dedup_key=key, event_type="DEPENDENCY_UNAVAILABLE",
            severity="ERROR", error_code="REMOTE_UNAVAILABLE", impact_summary="Unavailable dependency",
            correlation_id=key, endpoint_ref="gateway://dependency")

    def call(self, query, headers=None, path=None):
        return self.api.handle(path or self.api.INCIDENTS_PATH, headers or self.headers,
                               json.dumps(query) if not isinstance(query, str) else query)

    def test_transport_reopens_and_recaptures_current_publications(self):
        first = self.incident("first")
        code, body = self.call({"snapshot": True, "coverage": True, "limit": 1})
        self.assertEqual(code, 200)
        bookmark = body["publicationBookmark"]
        self.assertFalse(body["consultationRecorded"])
        self.store.close()
        self.store = SQLiteOperationalIncidentStore(self.path)
        self.api = GatewayOperationalOwnerAPI(self.store, self.authorize)
        latest = self.incident("later")
        headers = dict(self.headers, **{"X-OUF-Authorization-Decision-Ref": "new-login"})
        code, resumed = self.call({"resumeFrom": bookmark, "limit": 1}, headers)
        self.assertEqual(code, 200)
        self.assertEqual([x["incident_id"] for x in resumed["items"]], [latest.incident_id])
        self.assertEqual(resumed["coverage"]["parentBookmark"], bookmark)
        self.assertFalse(resumed["consultationRecorded"])
        self.assertNotEqual(first.incident_id, latest.incident_id)

    def test_page_chain_requires_coverage_optin_and_current_row_grant(self):
        for key in ["a", "b"]:
            self.incident(key)
        code, first = self.call({"snapshot": True, "coverage": True, "limit": 1})
        self.assertEqual(code, 200)
        self.assertNotIn("publicationBookmark", first)
        next_query = {"cursor": first["nextCursor"], "coverage": True}
        self.row_allowed = False
        code, redacted = self.call(next_query)
        self.assertEqual(code, 200)
        self.assertTrue(redacted["partial"])
        self.assertNotIn("publicationBookmark", redacted)
        self.row_allowed = True
        code, final = self.call(next_query)
        self.assertEqual(code, 200)
        self.assertIn("publicationBookmark", final)
        code, replay = self.call(next_query)
        self.assertEqual(final["publicationBookmark"], replay["publicationBookmark"])

    def test_revocation_identity_and_policy_never_use_bookmark_as_grant(self):
        _, first = self.call({"snapshot": True, "coverage": True})
        resume = {"resumeFrom": first["publicationBookmark"]}
        self.allowed = False
        self.assertEqual(self.call(resume)[0], 403)
        self.allowed = True
        headers = dict(self.headers, **{"X-OUF-Principal-ID": "other"})
        self.assertEqual(self.call(resume, headers)[0], 404)
        self.policy = "policy:2"
        self.assertEqual(self.call(resume)[0], 409)

    def test_closed_modes_reject_ambiguity_before_owner_io(self):
        token = "11111111-1111-4111-8111-111111111111"
        invalid = [{"coverage": True}, {"snapshot": True, "coverage": False},
            {"snapshot": True, "coverage": True, "since": "2026-10-11T00:00:00Z"},
            {"resumeFrom": token, "state": "OPEN"}, {"resumeFrom": token, "coverage": True},
            {"resumeFrom": token, "cursor": token}, {"resumeFrom": None},
            {"resumeFrom": "00000000-0000-0000-0000-000000000000"},
            {"resumeFrom": token.upper()}, {"cursor": token, "coverage": True, "limit": 1},
            '{"resumeFrom":"'+token+'","resumeFrom":"'+token+'"}']
        # Use a UUID containing hex letters to exercise canonical casing.
        invalid[-3] = {"resumeFrom": "11111111-AAAA-4111-8111-111111111111"}
        for query in invalid:
            with self.subTest(query=query):
                self.assertEqual(self.call(query)[0], 400)
        self.assertEqual(self.decisions, [])
        self.assertEqual(self.call({"snapshot": True, "coverage": True}, path=self.api.SUMMARY_PATH)[0], 400)

    def test_legacy_snapshot_and_missing_sdk_are_distinct(self):
        _, legacy = self.call({"snapshot": True})
        self.assertNotIn("bookmarkProfile", legacy)
        self.assertEqual(self.call({"cursor": legacy["cursor"], "coverage": True})[0], 404)
        self.api = GatewayOperationalOwnerAPI(self.store)
        self.assertEqual(self.call({"snapshot": True, "coverage": True})[0], 503)

    def test_request_scoped_authorizer_is_not_replaced_by_other_view(self):
        calls = []
        allow = self.api.bookmarks.with_authorization(lambda identity, policy: calls.append("allow") or True)
        deny = self.api.bookmarks.with_authorization(lambda identity, policy: False)
        identity = {"principal": "operator", "tenant": "tenant", "actor": "HUMAN"}
        from tools.operational_cursor import CursorRejected
        with self.assertRaises(CursorRejected):
            deny.start({}, identity, self.policy, lambda item: True)
        self.assertIn("publicationBookmark", allow.start({}, identity, self.policy, lambda item: True))
        self.assertTrue(calls)
        self.assertIsNone(self.api.bookmarks.authorize_collection)

if __name__ == "__main__":
    unittest.main()
