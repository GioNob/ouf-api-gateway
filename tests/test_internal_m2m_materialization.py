import pytest
from pathlib import Path

from tools.compile_config import compile_config
from tools.apply_installation_projection import apply_projection
from tools.materialize_apisix_internal_m2m_routes import MaterializationError, materialize
from ops.apisix.deploy_internal_m2m_routes import probe_path, validate_routes

ROOT=Path(__file__).resolve().parents[1]
ROUTE_IDS=["r2b-publication-resolution","r2b-semantic-reference"]

def projection():
    return {
        "installationId":"ouf-lab-netcup-01",
        "revision":3,
        "checksum":"sha256:test",
        "iam":{"workloadClients":{
            "mcpServer":"ouf-mcp-server",
            "ingestion":"ouf-ingestion",
            "udp":"ouf-udp",
            "semantic":"ouf-semantic",
        }},
        "mcp":{"environment":{"MCP_OIDC_CLIENT_ID":"ouf-mcp-server"}},
        "gateway":{
            "requiredAudience":"ouf-api-gateway",
            "issuerUrl":"https://auth.ouf-lab.it/realms/ouf",
            "publicApiBaseUrl":"https://api.ouf-lab.it",
        },
    }

def selected(runtime):
    return {r["id"]:r for r in runtime["routes"] if r["id"] in ROUTE_IDS}

def test_r2b_workload_routes_compile_with_installation_refs_and_backend_binding():
    runtime=compile_config(ROOT/"ouf-config")
    routes=selected(runtime)
    assert set(routes)==set(ROUTE_IDS)
    for route in routes.values():
        assert route["x-ouf-policy"]["allowedServiceIdentities"]==[
            "installation://iam.workloadClients.ingestion",
            "installation://iam.workloadClients.udp",
        ]
        assert route["x-ouf-policy"]["allowedActorTypes"]==["SERVICE"]
        assert route["x-ouf-backend-binding"]["port"]==8080

def test_projection_and_materialization_use_live_workload_clients_and_scopes():
    compiled=compile_config(ROOT/"ouf-config")
    resolved=apply_projection(compiled,projection())
    routes=selected(resolved)
    for route in routes.values():
        assert route["x-ouf-policy"]["allowedServiceIdentities"]==["ouf-ingestion","ouf-udp"]

    result=materialize(resolved,ROUTE_IDS,"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    assert [r["id"] for r in result["routes"]]==ROUTE_IDS

    publication=result["routes"][0]
    semantic=result["routes"][1]
    assert publication["plugins"]["openid-connect"]["required_scopes"]==["ouf.onboarding.configuration.read"]
    assert semantic["plugins"]["openid-connect"]["required_scopes"]==["ouf.semantic.read"]
    assert publication["upstream"]["nodes"]=={"ouf-onboarding:8080":1}
    assert semantic["upstream"]["nodes"]=={"ouf-semantic-registry:8080":1}
    assert "proxy-rewrite" not in publication["plugins"]
    assert semantic["plugins"]["proxy-rewrite"]["uri"]=="/api/semantic/v1/references:resolve"
    guard=semantic["plugins"]["serverless-post-function"]["functions"][0]
    assert "ouf-ingestion" in guard and "ouf-udp" in guard and "SERVICE" in guard
    validate_routes(result["routes"])

def test_materialization_rejects_unprojected_service_identity():
    compiled=compile_config(ROOT/"ouf-config")
    compiled["x-ouf-installation"]={
        "installationId":"lab",
        "revision":1,
        "checksum":"sha256:test",
        "issuerUrl":"https://auth.example.invalid/realms/ouf",
        "gatewayAudience":"gateway",
    }
    with pytest.raises(MaterializationError,match="must be projected"):
        materialize(compiled,[ROUTE_IDS[0]],"$ENV://OIDC_SECRET")

def test_deployer_probe_preserves_bounded_namespace():
    assert probe_path("/api/onboarding/v1/runtime/publications/*")=="/api/onboarding/v1/runtime/publications/probe"
    assert probe_path("/api/semantic/v1/references:resolve")=="/api/semantic/v1/references:resolve"

def test_managed_file_read_is_a_governed_workload_route():
    compiled=compile_config(ROOT/"ouf-config")
    resolved=apply_projection(compiled,projection())
    result=materialize(resolved,["onboarding-managed-file-read"],"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    route=result["routes"][0]
    assert route["uri"]=="/internal/object-storage/v1/content"
    assert route["upstream"]["nodes"]=={"ouf-onboarding:8080":1}
    assert route["plugins"]["proxy-rewrite"]["uri"]=="/api/internal/v1/onboarding/managed-files/content"
    assert route["plugins"]["openid-connect"]["required_scopes"]==["ouf.internal.object-storage.read"]
    guard=route["plugins"]["serverless-post-function"]["functions"][0]
    assert "ouf-onboarding" in guard and "ouf-ingestion" in guard and "SERVICE" in guard
    validate_routes(result["routes"])
