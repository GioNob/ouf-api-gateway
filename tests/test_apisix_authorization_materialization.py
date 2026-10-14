import json
from pathlib import Path

import pytest

from tools.compile_config import compile_config
from tools.apply_installation_projection import apply_projection
from tools.materialize_apisix_authorization_runtime import MaterializationError, materialize

ROOT = Path(__file__).resolve().parents[1]

def resolved_runtime():
    compiled = compile_config(ROOT / "ouf-config")
    projection = json.loads((ROOT / "tests" / "fixtures" / "installation-projection-lab.json").read_text())
    return apply_projection(compiled, projection)

def test_materializes_authorization_bundle_route():
    result = materialize(resolved_runtime(), "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    assert len(result["routes"]) == 1
    route = result["routes"][0]
    assert route["id"] == "mcp-authorization-policy-bundle-read"
    assert route["uri"] == "/internal/capabilities/v1/authorization/policy-bundle/active"
    assert route["methods"] == ["GET"]
    assert route["upstream"]["nodes"] == {"ouf-onboarding:8080": 1}
    oidc = route["plugins"]["openid-connect"]
    assert oidc["client_id"] == "ouf-api-gateway"
    assert oidc["required_scopes"] == ["authorization.bundle.read"]
    assert oidc["claim_validator"]["audience"]["match_with_client_id"] is True
    pre = route["plugins"]["serverless-pre-function"]["functions"][0]
    post = route["plugins"]["serverless-post-function"]["functions"][0]
    assert "X-OUF-Gateway-Verified" in pre
    assert "clear_header" in pre
    assert "ouf-mcp-server" in post
    assert "ouf-ingestion" in post
    assert "ouf-udp" in post
    assert "allowed_services" in post
    assert "ngx.req.clear_header('Authorization')" not in post

def test_authorization_materializer_rejects_plain_secret():
    with pytest.raises(MaterializationError, match="secret reference"):
        materialize(resolved_runtime(), "plain-secret")

def test_authorization_materializer_requires_resolved_gateway_audience():
    runtime = resolved_runtime()
    del runtime["x-ouf-installation"]["gatewayAudience"]
    with pytest.raises(MaterializationError, match="gatewayAudience"):
        materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")

def test_authorization_materializer_rejects_unbound_service_identity():
    runtime = resolved_runtime()
    route = next(r for r in runtime["routes"] if r["id"] == "mcp-authorization-policy-bundle-read")
    route["x-ouf-policy"]["allowedServiceIdentities"] = []
    with pytest.raises(MaterializationError, match="service identities"):
        materialize(runtime, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
