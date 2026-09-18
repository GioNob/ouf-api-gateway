import json
from pathlib import Path

import pytest

from tools.compile_config import compile_config
from tools.apply_installation_projection import apply_projection
from tools.materialize_apisix_runtime import MaterializationError, materialize

ROOT = Path(__file__).resolve().parents[1]


def resolved_runtime():
    compiled = compile_config(ROOT / "ouf-config")
    projection = json.loads((ROOT / "tests" / "fixtures" / "installation-projection-lab.json").read_text())
    return apply_projection(compiled, projection)


def test_mcp_compiler_preserves_backend_coordinates():
    runtime = resolved_runtime()
    route = next(r for r in runtime["routes"] if r["id"] == "public-mcp-endpoint")
    assert route["x-ouf-backend-binding"] == {
        "service": "ouf-mcp-server",
        "port": 8080,
        "path": "/mcp",
    }


def test_materializes_oidc_protected_mcp_route_and_oauth_discovery():
    runtime = resolved_runtime()
    result = materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")

    assert result["installationId"] == "ouf-lab-netcup-01"
    assert len(result["routes"]) == 2

    route = next(r for r in result["routes"] if r["id"] == "public-mcp-endpoint")
    assert route["id"] == "public-mcp-endpoint"
    assert route["uri"] == "/mcp"
    assert route["methods"] == ["POST"]
    assert route["upstream"] == {
        "type": "roundrobin",
        "scheme": "http",
        "nodes": {"ouf-mcp-server:8080": 1},
    }

    validation = route["plugins"]["request-validation"]
    assert validation["max_req_body_size"] == 1048576
    assert validation["body_schema"] == {
        "anyOf": [{"type": "object"}, {"type": "array"}]
    }

    oidc = route["plugins"]["openid-connect"]
    assert oidc["client_id"] == "ouf-api-gateway"
    assert oidc["client_secret"] == "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET"
    assert oidc["discovery"] == "https://auth.ouf-lab.it/realms/ouf/.well-known/openid-configuration"
    assert oidc["bearer_only"] is True
    assert oidc["use_jwks"] is True
    assert oidc["ssl_verify"] is True
    assert oidc["required_scopes"] == ["mcp.connect"]
    assert oidc["claim_validator"]["audience"] == {
        "required": True,
        "match_with_client_id": True,
    }

    challenge = route["plugins"]["response-rewrite"]
    assert challenge["vars"] == [["status", "==", 401]]
    assert challenge["headers"]["set"]["WWW-Authenticate"] == (
        'Bearer resource_metadata="https://api.ouf-lab.it/.well-known/oauth-protected-resource", '
        'scope="mcp.connect"'
    )

    pre = route["plugins"]["serverless-pre-function"]["functions"][0]
    post = route["plugins"]["serverless-post-function"]["functions"][0]
    assert "X-OUF-Gateway-Verified" in pre
    assert "clear_header" in pre
    assert "X-OUF-Gateway-Verified" in post
    assert "X-OUF-Tenant-ID" in post
    assert "X-OUF-Granted-Scopes" in post
    assert "ngx.req.clear_header('Authorization')" in post

    metadata_route = next(
        r for r in result["routes"]
        if r["id"] == "public-mcp-oauth-protected-resource"
    )
    assert metadata_route["uri"] == "/.well-known/oauth-protected-resource"
    assert metadata_route["methods"] == ["GET"]
    assert "upstream" not in metadata_route
    mocking = metadata_route["plugins"]["mocking"]
    assert mocking["response_status"] == 200
    assert mocking["content_type"] == "application/json"
    assert mocking["with_mock_header"] is False
    assert json.loads(mocking["response_example"]) == {
        "authorization_servers": ["https://auth.ouf-lab.it/realms/ouf"],
        "bearer_methods_supported": ["header"],
        "resource": "https://api.ouf-lab.it/mcp",
        "resource_name": "OUF MCP Server",
        "scopes_supported": ["mcp.connect"],
    }
    assert mocking["response_headers"] == {
        "Cache-Control": "public, max-age=300",
        "X-Content-Type-Options": "nosniff",
    }


def test_materializer_never_embeds_plain_oidc_secret():
    runtime = resolved_runtime()
    with pytest.raises(MaterializationError, match="secret reference"):
        materialize(runtime, "plaintext-secret")


def test_materializer_fails_closed_without_resolved_installation():
    runtime = resolved_runtime()
    runtime.pop("x-ouf-installation")
    with pytest.raises(MaterializationError, match="installation"):
        materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")


def test_materializer_fails_closed_if_public_mcp_backend_contract_changes():
    runtime = resolved_runtime()
    route = next(r for r in runtime["routes"] if r["id"] == "public-mcp-endpoint")
    route["x-ouf-backend-binding"]["port"] = 0
    with pytest.raises(MaterializationError, match="backend port"):
        materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")


@pytest.mark.parametrize(
    "field,value",
    [
        ("publicApiBaseUrl", "http://api.ouf-lab.it"),
        ("publicApiBaseUrl", "https://api.ouf-lab.it/unexpected"),
        ("issuerUrl", "http://auth.ouf-lab.it/realms/ouf"),
    ],
)
def test_materializer_rejects_noncanonical_oauth_urls(field, value):
    runtime = resolved_runtime()
    runtime["x-ouf-installation"][field] = value
    with pytest.raises(MaterializationError, match="canonical HTTPS URL"):
        materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
