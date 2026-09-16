import json

import pytest

from tools.mcp_dispatch import BackendResponse, DispatchError, TrustedIdentity
from tools.mcp_evidence_ingress import MCPEvidenceIngressMediator


class FakeInbox:
    def __init__(self, response=None):
        self.calls = []
        self.response = response or BackendResponse(201, b'{"EvidenceRef":"evidence-1","Replay":false}', {"Content-Type": "application/json"})

    def ingest(self, *args):
        self.calls.append(args)
        return self.response


def identity(service="ouf-udp-object-resolution", scopes=frozenset({"mcp.evidence.submit"})):
    return TrustedIdentity(service, "owner-worker", "tenant-internal", "SERVICE", "authn-owner", "decision-owner", scopes)


def evidence(**changes):
    value = {
        "BackendRequestID": "udp-request-1", "Kind": "OWNER_RESULT", "TerminalState": "SUCCEEDED",
        "OutcomeCode": "SUCCEEDED", "ResultRef": "result://udp/1", "ActualDistinctObjects": 1,
        "ObjectHashes": ["v1:hmac-sha256:" + "A" * 43],
    }
    value.update(changes)
    return json.dumps(value).encode()


def test_owner_is_derived_from_trusted_identity_and_forwarded_canonically():
    inbox = FakeInbox()
    result = MCPEvidenceIngressMediator(inbox).ingest(evidence(), {"X-Correlation-ID": "corr-1"}, identity())
    assert result.status == 201
    service, path, body, headers, timeout = inbox.calls[0]
    assert (service, path, timeout) == ("ouf-mcp-server", "/internal/evidence/v1/owner-results", 3)
    forwarded = json.loads(body)
    assert forwarded["ClaimedOwner"] == "udp-object-resolution"
    assert headers["X-OUF-Trusted-Backend-Owner"] == "udp-object-resolution"


def test_forged_owner_fails_before_mcp_network():
    inbox = FakeInbox()
    with pytest.raises(DispatchError) as caught:
        MCPEvidenceIngressMediator(inbox).ingest(evidence(BackendOwner="attacker"), {"X-Correlation-ID": "corr-1"}, identity())
    assert caught.value.code == "EVIDENCE_OWNER_MISMATCH" and inbox.calls == []


def test_wrong_workload_or_scope_fails_before_mcp_network():
    for current in (identity(service="attacker"), identity(scopes=frozenset())):
        inbox = FakeInbox()
        with pytest.raises(DispatchError) as caught:
            MCPEvidenceIngressMediator(inbox).ingest(evidence(), {"X-Correlation-ID": "corr-1"}, current)
        assert caught.value.code == "EVIDENCE_ACCESS_DENIED" and inbox.calls == []


def test_unadmitted_hash_version_fails_closed():
    inbox = FakeInbox()
    with pytest.raises(DispatchError) as caught:
        MCPEvidenceIngressMediator(inbox).ingest(evidence(ObjectHashes=["v2:hmac-sha256:" + "A" * 43]), {"X-Correlation-ID": "corr-1"}, identity())
    assert caught.value.code == "UNSUPPORTED_OBJECT_HASH_VERSION" and inbox.calls == []


def test_owner_proves_no_dispatch_is_canonical_and_zero_cost():
    inbox = FakeInbox()
    raw = evidence(Kind="OWNER_PROVES_NO_DISPATCH", TerminalState="FAILED", OutcomeCode="DISPATCH_NOT_STARTED", ResultRef="", ActualDistinctObjects=0, ObjectHashes=[])
    MCPEvidenceIngressMediator(inbox).ingest(raw, {"X-Correlation-ID": "corr-1"}, identity())
    assert json.loads(inbox.calls[0][2])["Kind"] == "OWNER_PROVES_NO_DISPATCH"


@pytest.mark.parametrize("response", [
    BackendResponse(200, b'{"EvidenceRef":"same","Replay":true}', {}),
    BackendResponse(409, b'{"code":"EVIDENCE_INGRESS_CONFLICT"}', {}),
])
def test_mcp_replay_and_conflict_semantics_are_preserved(response):
    result = MCPEvidenceIngressMediator(FakeInbox(response)).ingest(evidence(), {"X-Correlation-ID": "corr-1"}, identity())
    assert result.status == response.status and result.body == response.body
