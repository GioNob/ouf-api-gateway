from pathlib import Path

from tools.compile_config import compile_config


ROOT = Path(__file__).resolve().parents[1]


def test_review_projection_is_delegated_human_read_and_confirmation_is_ths_only():
    routes = compile_config(ROOT / "ouf-config")["routes"]
    by_id = {route["id"]: route for route in routes}
    mcp = by_id["mcp-resolution-issue-read"]
    assert mcp["methods"] == ["POST"]
    assert mcp["uri"] == "/internal/capabilities/v1/execute/resolution.issue.read"
    assert mcp["x-ouf-policy"]["allowedActorTypes"] == ["HUMAN"]
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
