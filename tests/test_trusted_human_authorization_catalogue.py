import json
from pathlib import Path

import pytest

from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.materialize_apisix_runtime import MaterializationError
from tools.materialize_trusted_human_authorization_runtime import (
    CAPABILITY,
    MAX_BODY,
    METHODS,
    NAMESPACE,
    materialize,
)

ROOT = Path(__file__).resolve().parents[1]


def runtime():
    compiled = compile_config(ROOT / "ouf-config")
    projection = json.loads((ROOT / "tests" / "fixtures" / "installation-projection-lab.json").read_text())
    return apply_projection(compiled, projection)


def test_contract_compiles_as_bounded_human_only_namespace():
    rt = runtime()
    routes = [
        r for r in rt["routes"]
        if r.get("uri") == NAMESPACE and (r.get("labels") or {}).get("exposure") == "public"
    ]
    assert len(routes) == 4
    assert {tuple(r["methods"]) for r in routes} == {(m,) for m in METHODS}
    for route in routes:
        assert route["x-ouf-capability"]["capabilityId"] == CAPABILITY
        assert route["x-ouf-capability"]["owner"] == "authorization"
        assert route["x-ouf-capability"]["humanRequired"] is True
        assert route["x-ouf-capability"]["toolEligible"] is False
        assert route["x-ouf-policy"]["identity"] == "OIDC"
        assert route["x-ouf-policy"]["requiredScope"] == CAPABILITY
        assert route["x-ouf-policy"]["allowedActorTypes"] == ["HUMAN"]
        assert route["x-ouf-policy"]["maxRequestBytes"] == MAX_BODY
        assert route["service_id"] == "ouf-onboarding"
        assert "proxy-rewrite" not in route["plugins"]


def test_materialization_preserves_path_and_bearer_for_owner_revalidation():
    doc = materialize(runtime(), "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    assert len(doc["routes"]) == 4
    assert {tuple(r["methods"]) for r in doc["routes"]} == {(m,) for m in METHODS}
    for route in doc["routes"]:
        assert route["uri"] == NAMESPACE
        assert route["upstream"]["nodes"] == {"ouf-onboarding:8080": 1}
        assert route["plugins"]["client-control"]["max_body_size"] == MAX_BODY
        oidc = route["plugins"]["openid-connect"]
        assert oidc["required_scopes"] == [CAPABILITY]
        assert oidc["claim_validator"]["audience"]["match_with_client_id"] is True
        pre = route["plugins"]["serverless-pre-function"]["functions"][0]
        assert "X-OUF-Gateway-Verified" in pre and "clear_header" in pre
        assert "Authorization" not in pre
        assert "serverless-post-function" not in route["plugins"]


def test_materializer_rejects_plain_oidc_secret():
    with pytest.raises(MaterializationError, match="secret reference"):
        materialize(runtime(), "plain-secret")


def test_materializer_rejects_actor_drift():
    rt = runtime()
    route = next(r for r in rt["routes"] if r.get("uri") == NAMESPACE)
    route["x-ouf-policy"]["allowedActorTypes"] = ["AI_AGENT"]
    with pytest.raises(MaterializationError, match="HUMAN only"):
        materialize(rt, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
