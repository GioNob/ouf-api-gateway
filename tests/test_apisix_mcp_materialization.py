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


def test_materializes_single_oidc_protected_mcp_route():
    runtime = resolved_runtime()
    result = materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")

    assert result["installationId"] == "ouf-lab-netcup-01"
    assert len(result["routes"]) == 1

    route = result["routes"][0]
    assert route["id"] == "public-mcp-endpoint"
    assert route["uri"] == "/mcp"
    assert route["methods"] == ["POST"]
    assert route["upstream"] == {
        "type": "roundrobin",
        "scheme": "http",
        "nodes": {"ouf-mcp-server:8080": 1},
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

    pre = route["plugins"]["serverless-pre-function"]["functions"][0]
    post = route["plugins"]["serverless-post-function"]["functions"][0]
    assert "X-OUF-Gateway-Verified" in pre
    assert "clear_header" in pre
    assert "X-OUF-Gateway-Verified" in post
    assert "X-OUF-Tenant-ID" in post
    assert "X-OUF-Granted-Scopes" in post
    assert "ngx.req.clear_header('Authorization')" in post


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
