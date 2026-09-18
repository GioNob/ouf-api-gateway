from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_gateway_operational_producer_capabilities_are_private_and_non_tool():
    expected = {
        "ouf.gateway.operations.incidents": ("operations.incident.read", "/api/internal/v1/gateway/operations/incidents"),
        "ouf.gateway.operations.summary": ("operations.status.read", "/api/internal/v1/gateway/operations/summary"),
    }
    source = load("ouf-config/source-runtime/gateway-control-plane-operations.yaml")
    assert source["spec"]["endpointRef"] == "service://ouf-gateway-control-plane"
    for capability_id, (scope, backend_path) in expected.items():
        capability = load(f"ouf-config/capabilities/{capability_id}.yaml")
        assert capability["spec"]["owner"] == "gateway"
        assert capability["spec"]["scope"] == scope
        assert capability["spec"]["mcp"]["toolEligible"] is False
        suffix = "incidents" if capability_id.endswith("incidents") else "summary"
        route = load(f"ouf-config/routes/northbound/mcp-gateway-operations-{suffix}.yaml")
        assert route["spec"]["exposure"] == "internal"
        assert route["spec"]["policy"]["allowedServiceIdentities"] == ["installation://iam.workloadClients.mcpServer"]
        assert route["spec"]["backendBinding"]["service"] == "ouf-gateway-control-plane"
        assert route["spec"]["backendBinding"]["path"] == backend_path
        assert route["spec"]["backendBinding"]["path"] != "/mcp"
