from pathlib import Path
import json

from tools.compile_config import compile_config
from tools.mcp_dispatch import BackendResponse, MCPDispatcher, TrustedIdentity, DispatchError
from tests.test_mcp_dispatch import fixture, headers, FakeUpstream
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_review_projection_is_delegated_human_read_and_confirmation_is_ths_only():
    routes = compile_config(ROOT / "ouf-config")["routes"]
    by_id = {route["id"]: route for route in routes}
    mcp = by_id["mcp-resolution-issue-read"]
    assert mcp["methods"] == ["POST"]
    assert mcp["uri"] == "/internal/capabilities/v1/execute/resolution.issue.read"
    assert mcp["x-ouf-policy"]["allowedActorTypes"] == ["HUMAN"]
    assert mcp["x-ouf-capability"]["humanRequired"] is False
    assert mcp["x-ouf-policy"]["allowedServiceIdentities"] == ["installation://iam.workloadClients.mcpServer"]
    assert mcp["plugins"]["proxy-rewrite"]["uri"] == "/api/udp/v1/governance/internal/resolution/issues/package"

    read = by_id["ths-resolution-package-read"]
    confirm = by_id["ths-resolution-package-confirm"]
    assert read["methods"] == ["GET"]
    assert confirm["methods"] == ["POST"]
    assert all(route["x-ouf-policy"]["identity"] == "OIDC" for route in (read, confirm))
    assert all(route["x-ouf-policy"]["allowedActorTypes"] == ["HUMAN"] for route in (read, confirm))
    assert confirm["x-ouf-capability"]["toolEligible"] is False
    assert not any(route["uri"].startswith("/internal/capabilities/v1/execute/resolution.match.approve") for route in routes)


def test_delegated_human_can_read_package_but_cannot_dispatch_confirmation():
    data = fixture()
    data.update(GatewayBindingRef="capability://resolution.issue.read", CapabilityID="resolution.issue.read",
                OperationClass="READ", Arguments={})
    data["Identity"]["ActorType"] = "HUMAN"
    identity = TrustedIdentity("ouf-mcp-server", "agent-1", "tenant-1", "HUMAN", "authn-1",
                               "decision-1", frozenset({"resolution.issue.read"}))
    upstream = FakeUpstream(BackendResponse(200, b'{"issues":[]}', {"Content-Type": "application/json"}))
    dispatcher = MCPDispatcher(compile_config(ROOT / "ouf-config"), upstream, service_identity="ouf-mcp-server")
    result = dispatcher.dispatch(json.dumps(data).encode(), headers(data), identity)
    assert result.status == 200
    assert upstream.calls[0][:2] == ("ouf-udp-object-resolution", "/api/udp/v1/governance/internal/resolution/issues/package")
    data["CapabilityID"] = "resolution.match.approve"
    data["GatewayBindingRef"] = "capability://resolution.match.approve"
    data["OperationClass"] = "COMMAND"
    with pytest.raises(DispatchError, match="resolution.match.approve"):
        dispatcher.dispatch(json.dumps(data).encode(), headers(data), identity)
    assert len(upstream.calls) == 1
