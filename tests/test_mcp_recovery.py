import json

import pytest

from tools.compile_config import ROOT, compile_config
from tools.mcp_dispatch import BackendResponse, DispatchError, TrustedIdentity
from tools.mcp_recovery import MCPRecoveryMediator


class FakeRecoveryUpstream:
    def __init__(self, response=None):
        self.calls = []
        self.response = response or BackendResponse(200, json.dumps({
            "BackendRequestID": "udp-request-1", "Outcome": "SUCCEEDED", "OutcomeCode": "SUCCEEDED",
            "ResultRef": "result://udp/1", "ActualToolCalls": 1, "ActualResultBytes": 42,
        }).encode(), {"Content-Type": "application/json"})

    def recover(self, *args):
        self.calls.append(args)
        return self.response


def request(value=None):
    value = value or json.loads((ROOT / "tests/fixtures/mcp-recovery-request.json").read_text())
    return json.dumps(value).encode()


def identity(service="ouf-mcp-server", scopes=frozenset({"mcp.attempt.recover"})):
    return TrustedIdentity(service, "agent-1", "tenant-1", "MCP_SERVER", "authn-1", "decision-1", scopes)


def mediator(upstream):
    return MCPRecoveryMediator(compile_config(ROOT / "ouf-config"), upstream)


def test_recovery_uses_only_registry_owned_service_and_path():
    upstream = FakeRecoveryUpstream()
    result = mediator(upstream).recover(request(), {"X-Correlation-ID": "correlation-recovery-1"}, identity())
    assert result.status == 200
    assert json.loads(result.body)["Outcome"] == "SUCCEEDED"
    service, path, headers, timeout = upstream.calls[0]
    assert (service, path, timeout) == ("ouf-udp-object-resolution", "/internal/v1/attempt-outcomes/udp-request-1", 3)
    assert headers["X-OUF-Recovery-For"] == "udp-request-1"


@pytest.mark.parametrize("mutation,code", [
    (lambda value: value.update(Owner="attacker"), "RECOVERY_BINDING_MISMATCH"),
    (lambda value: value.update(CapabilityID="urban.unknown"), "RECOVERY_BINDING_NOT_FOUND"),
    (lambda value: value.update(BackendRequestID="../../attacker"), "INVALID_RECOVERY_REQUEST"),
])
def test_untrusted_binding_fails_before_owner_network(mutation, code):
    value = json.loads((ROOT / "tests/fixtures/mcp-recovery-request.json").read_text())
    mutation(value)
    upstream = FakeRecoveryUpstream()
    with pytest.raises(DispatchError) as caught:
        mediator(upstream).recover(request(value), {"X-Correlation-ID": value["CorrelationID"]}, identity())
    assert caught.value.code == code and upstream.calls == []


def test_recovery_requires_workload_scope_and_matching_correlation():
    for current_identity, correlation in ((identity(scopes=frozenset()), "correlation-recovery-1"), (identity(), "forged")):
        upstream = FakeRecoveryUpstream()
        with pytest.raises(DispatchError):
            mediator(upstream).recover(request(), {"X-Correlation-ID": correlation}, current_identity)
        assert upstream.calls == []


@pytest.mark.parametrize("response", [
    BackendResponse(404, b"{}", {}),
    BackendResponse(500, b"{}", {}),
    BackendResponse(200, b'{"BackendRequestID":"other","Outcome":"SUCCEEDED"}', {}),
    BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"MAGIC"}', {}),
    BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"FAILED","ActualToolCalls":-1}', {}),
    BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"NOT_DISPATCHED","OutcomeCode":"NOT_FOUND"}', {}),
    BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"NOT_DISPATCHED","OutcomeCode":"OWNER_PROVES_NO_DISPATCH","ActualToolCalls":1}', {}),
    BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"UNKNOWN","ActualResultBytes":1}', {}),
    BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"FAILED","OutcomeCode":7}', {}),
    BackendResponse(200, b" " * 65537, {}),
])
def test_non_authoritative_or_incoherent_owner_response_is_never_terminal(response):
    upstream = FakeRecoveryUpstream(response)
    with pytest.raises(DispatchError) as caught:
        mediator(upstream).recover(request(), {"X-Correlation-ID": "correlation-recovery-1"}, identity())
    assert caught.value.code in {"OWNER_RECOVERY_UNAVAILABLE", "INVALID_OWNER_EVIDENCE"}


def test_owner_proves_no_dispatch_is_preserved_exactly():
    response = BackendResponse(200, b'{"BackendRequestID":"udp-request-1","Outcome":"NOT_DISPATCHED","OutcomeCode":"OWNER_PROVES_NO_DISPATCH"}', {})
    result = mediator(FakeRecoveryUpstream(response)).recover(request(), {"X-Correlation-ID": "correlation-recovery-1"}, identity())
    evidence = json.loads(result.body)
    assert evidence["Outcome"] == "NOT_DISPATCHED" and evidence["OutcomeCode"] == "OWNER_PROVES_NO_DISPATCH"
    assert evidence["ActualToolCalls"] == 0 and evidence["ActualResultBytes"] == 0


def test_recovery_accepts_installation_specific_mcp_service_identity():
    custom_service="ente-x-mcp-workload"
    upstream=FakeRecoveryUpstream()
    current=MCPRecoveryMediator(
        compile_config(ROOT/"ouf-config"),
        upstream,
        service_identity=custom_service,
    )
    result=current.recover(
        request(),
        {"X-Correlation-ID":"correlation-recovery-1"},
        identity(service=custom_service),
    )
    assert result.status==200 and len(upstream.calls)==1
