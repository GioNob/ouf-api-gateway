import json
from pathlib import Path

from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.materialize_trusted_human_onboarding_runtime import ROUTE_IDS, materialize

ROOT=Path(__file__).resolve().parents[1]


def projection():
    return json.loads((ROOT/"tests/fixtures/installation-projection-lab.json").read_text())


def runtime():
    return apply_projection(compile_config(ROOT/"ouf-config"),projection())


def test_materializes_bounded_human_onboarding_routes():
    doc=materialize(runtime(),"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    assert {r["id"] for r in doc["routes"]}==set(ROUTE_IDS)
    for route in doc["routes"]:
        assert route["upstream"]["nodes"]=={"ouf-onboarding:8080":1}
        assert route["plugins"]["openid-connect"]["required_scopes"]==["ouf.onboarding.configuration.write"]
        assert route["plugins"]["openid-connect"]["set_access_token_header"] is False
        assert "ouf_actor_type" in route["plugins"]["serverless-post-function"]["functions"][0]
        assert route["plugins"]["client-control"]["max_body_size"]<=5242880
    assert any(r["uri"]=="/api/onboarding/v1/sources" for r in doc["routes"])
    assert any(r["uri"]=="/api/onboarding/v1/sources/*" for r in doc["routes"])
    assert any(r["uri"]=="/api/trusted-human/v1/approval-challenges/*" for r in doc["routes"])


def test_ingestion_compatibility_route_is_separate_m2m_boundary():
    routes={r["id"]:r for r in runtime()["routes"]}
    route=routes["r4a-onboarding-ingestion-compatibility"]
    assert route["uri"]=="/api/internal/v1/onboarding/compatibility/ingestion-runtime"
    assert route["methods"]==["POST"]
    assert route["x-ouf-policy"]["identity"]=="M2M"
    assert route["x-ouf-policy"]["requiredScope"]=="ouf.ingestion.configuration.attest"
    assert route["x-ouf-policy"]["allowedServiceIdentities"]==["ouf-ingestion"]
    assert route["x-ouf-policy"]["allowedActorTypes"]==["SERVICE"]
