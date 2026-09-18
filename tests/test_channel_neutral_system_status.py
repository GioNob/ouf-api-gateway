from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_system_status_is_channel_neutral_and_not_mcp_protocol_backed():
    capability = load("ouf-config/capabilities/ouf.system.status.yaml")
    source = load("ouf-config/source-runtime/mcp-server-operations.yaml")
    mcp_route = load("ouf-config/routes/northbound/mcp-system-status.yaml")
    api_route = load("ouf-config/routes/northbound/api-system-status.yaml")

    assert capability["spec"]["owner"] == "mcp"
    assert capability["spec"]["scope"] == "operations.status.read"
    assert source["spec"]["endpointRef"] == "service://ouf-mcp-server"

    for route in (mcp_route, api_route):
        spec = route["spec"]
        assert spec["capabilityRef"] == "ouf.system.status@1.0.0"
        assert spec["sourceRef"] == "mcp-server-operations@1.0.0"
        assert spec["backendBinding"]["service"] == "ouf-mcp-server"
        assert spec["backendBinding"]["path"] == "/api/internal/v1/mcp/operations/status"
        assert spec["backendBinding"]["path"] != "/mcp"
        assert spec["policy"]["maxRequestBytes"] <= 65536

    assert mcp_route["spec"]["exposure"] == "internal"
    assert mcp_route["spec"]["policy"]["identity"] == "M2M"
    assert mcp_route["spec"]["policy"]["allowedServiceIdentities"] == ["installation://iam.workloadClients.mcpServer"]
    assert api_route["spec"]["exposure"] == "public"
    assert api_route["spec"]["policy"]["identity"] == "OIDC"
    assert api_route["spec"]["match"]["path"] == "/api/v1/operations/system/status"


def test_compiled_routes_share_capability_and_owner_backend():
    from tools.compile_config import compile_config
    compiled = compile_config(ROOT / "ouf-config")
    routes = {r["id"]: r for r in compiled["routes"]}
    internal = routes["mcp-system-status"]
    public = routes["api-system-status"]
    for route in (internal, public):
        assert route["x-ouf-capability"]["capabilityId"] == "ouf.system.status"
        assert route["x-ouf-capability"]["owner"] == "mcp"
        assert route["service_id"] == "ouf-mcp-server"
        assert route["plugins"]["proxy-rewrite"]["uri"] == "/api/internal/v1/mcp/operations/status"
        assert route["x-ouf-policy"]["requiredScope"] == "operations.status.read"
    assert internal["x-ouf-policy"]["identity"] == "M2M"
    assert public["x-ouf-policy"]["identity"] == "OIDC"
