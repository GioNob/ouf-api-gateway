from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_direct_ingestion_operational_tools_remain_owner_bound():
    expected = {
        "ouf.ingestion.status": ("ingestion.operations.read", "mcp-ingestion-status", "/api/internal/v1/ingestion/operations/status"),
        "ouf.ingestion.history": ("ingestion.operations.read", "mcp-ingestion-history", "/api/internal/v1/ingestion/operations/history"),
        "ouf.operations.explain": ("operations.incident.explain", "mcp-operations-explain", "/api/internal/v1/ingestion/operations/incidents/explain"),
    }
    for capability_id, (scope, route_name, backend_path) in expected.items():
        capability = load(f"ouf-config/capabilities/{capability_id}.yaml")
        assert capability["spec"]["scope"] == scope
        assert capability["spec"]["mcp"]["toolEligible"] is True
        route = load(f"ouf-config/routes/northbound/{route_name}.yaml")
        assert route["spec"]["sourceRef"] == "ingestion-runtime-operations@1.0.0"
        assert route["spec"]["backendBinding"]["service"] == "ouf-ingestion-runtime"
        assert route["spec"]["backendBinding"]["path"] == backend_path


def test_global_operational_tools_are_mcp_owned_and_channel_neutral():
    expected = {
        "ouf.operations.incidents": ("operations.incident.read", "/api/internal/v1/mcp/operations/incidents", "/api/v1/operations/incidents"),
        "ouf.operations.summary": ("operations.status.read", "/api/internal/v1/mcp/operations/summary", "/api/v1/operations/summary"),
    }
    for capability_id, (scope, owner_path, public_path) in expected.items():
        capability = load(f"ouf-config/capabilities/{capability_id}.yaml")
        assert capability["spec"]["owner"] == "mcp"
        assert capability["spec"]["scope"] == scope
        assert capability["spec"]["mcp"]["toolEligible"] is True
        suffix = capability_id.rsplit(".", 1)[-1]
        mcp_route = load(f"ouf-config/routes/northbound/mcp-operations-{suffix}.yaml")
        api_route = load(f"ouf-config/routes/northbound/api-operations-{suffix}.yaml")
        for route in (mcp_route, api_route):
            assert route["spec"]["sourceRef"] == "mcp-server-operations@1.0.0"
            assert route["spec"]["backendBinding"]["service"] == "ouf-mcp-server"
            assert route["spec"]["backendBinding"]["path"] == owner_path
            assert route["spec"]["backendBinding"]["path"] != "/mcp"
        assert api_route["spec"]["match"]["path"] == public_path
        assert api_route["spec"]["policy"]["identity"] == "OIDC"


def test_ingestion_producer_primitives_are_internal_and_not_tools():
    expected = {
        "ouf.ingestion.operations.incidents": "/api/internal/v1/ingestion/operations/incidents",
        "ouf.ingestion.operations.summary": "/api/internal/v1/ingestion/operations/summary",
    }
    for capability_id, backend_path in expected.items():
        capability = load(f"ouf-config/capabilities/{capability_id}.yaml")
        assert capability["spec"]["owner"] == "ingestion"
        assert capability["spec"]["mcp"]["toolEligible"] is False
        suffix = capability_id.rsplit(".", 1)[-1]
        route = load(f"ouf-config/routes/northbound/mcp-ingestion-operations-{suffix}-producer.yaml")
        assert route["spec"]["exposure"] == "internal"
        assert route["spec"]["policy"]["allowedServiceIdentities"] == ["installation://iam.workloadClients.mcpServer"]
        assert route["spec"]["backendBinding"]["path"] == backend_path


def test_compiled_operational_routes_preserve_owner_boundaries():
    from tools.compile_config import compile_config
    compiled = compile_config(ROOT / "ouf-config")
    routes = {r["id"]: r for r in compiled["routes"]}
    assert routes["mcp-operations-incidents"]["service_id"] == "ouf-mcp-server"
    assert routes["mcp-operations-summary"]["service_id"] == "ouf-mcp-server"
    assert routes["mcp-ingestion-operations-incidents-producer"]["service_id"] == "ouf-ingestion-runtime"
    assert routes["mcp-ingestion-operations-summary-producer"]["service_id"] == "ouf-ingestion-runtime"
    assert routes["mcp-gateway-operations-incidents"]["service_id"] == "ouf-gateway-control-plane"
    assert routes["mcp-gateway-operations-summary"]["service_id"] == "ouf-gateway-control-plane"


def test_policy_bundle_read_allows_only_governed_workloads():
    route = load("ouf-config/routes/northbound/mcp-authorization-policy-bundle-read.yaml")
    assert route["spec"]["capabilityRef"] == "authorization.bundle.read@1.0.0"
    assert route["spec"]["policy"]["identity"] == "M2M"
    assert route["spec"]["policy"]["allowedActorTypes"] == ["SERVICE"]
    assert route["spec"]["policy"]["allowedServiceIdentities"] == [
        "installation://iam.workloadClients.mcpServer",
        "installation://iam.workloadClients.ingestion",
        "installation://iam.workloadClients.udp",
    ]
    assert "*" not in route["spec"]["policy"]["allowedServiceIdentities"]
