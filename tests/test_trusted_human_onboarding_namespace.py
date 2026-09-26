import json
from pathlib import Path
import pytest

from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.materialize_trusted_human_onboarding_runtime import ROUTE_IDS, materialize, MaterializationError
from ops.apisix.deploy_trusted_human_onboarding import apply

ROOT=Path(__file__).resolve().parents[1]


def projection():
    return json.loads((ROOT/"tests/fixtures/installation-projection-lab.json").read_text())


def runtime():
    return apply_projection(compile_config(ROOT/"ouf-config"),projection())


def test_materializes_bounded_human_onboarding_routes():
    doc=materialize(runtime(),"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    assert {r["id"] for r in doc["routes"]}==set(ROUTE_IDS)
    scopes={
        "trusted-human-managed-file-upload":"ouf.managed-source.file.upload",
        "trusted-human-managed-file-actions-post":"ouf.managed-source.file.profile",
        "trusted-human-managed-file-preview-get":"ouf.managed-source.preview",
    }
    for route in doc["routes"]:
        assert route["upstream"]["nodes"]=={"ouf-onboarding:8080":1}
        assert route["plugins"]["openid-connect"]["required_scopes"]==[
            scopes.get(route["id"],"ouf.onboarding.configuration.write")]
        assert route["plugins"]["openid-connect"]["set_access_token_header"] is False
        assert "ouf_actor_type" in route["plugins"]["serverless-post-function"]["functions"][0]
        assert route["plugins"]["client-control"]["max_body_size"]<=(10485760 if route["id"]=="trusted-human-managed-file-upload" else 5242880)
    assert any(r["uri"]=="/api/onboarding/v1/sources" for r in doc["routes"])
    assert any(r["uri"]=="/api/onboarding/v1/sources/*" for r in doc["routes"])
    assert any(r["uri"]=="/api/trusted-human/v1/approval-challenges/*" for r in doc["routes"])
    assert any(r["uri"]=="/api/managed-sources/v1/files" and r["methods"]==["POST"] for r in doc["routes"])
    assert any(r["uri"]=="/api/onboarding/v1/managed-files/*" and r["methods"]==["POST"] for r in doc["routes"])
    assert any(r["uri"]=="/api/onboarding/v1/managed-files/*" and r["methods"]==["GET"] for r in doc["routes"])


def test_ingestion_compatibility_route_is_separate_m2m_boundary():
    routes={r["id"]:r for r in runtime()["routes"]}
    route=routes["r4a-onboarding-ingestion-compatibility"]
    assert route["uri"]=="/api/internal/v1/onboarding/compatibility/ingestion-runtime"
    assert route["methods"]==["POST"]
    assert route["x-ouf-policy"]["identity"]=="M2M"
    assert route["x-ouf-policy"]["requiredScope"]=="ouf.ingestion.configuration.attest"
    assert route["x-ouf-policy"]["allowedServiceIdentities"]==["ouf-ingestion"]
    assert route["x-ouf-policy"]["allowedActorTypes"]==["SERVICE"]


def test_managed_file_route_rejects_unverified_remote_upstream():
    candidate=runtime()
    upload=next(r for r in candidate["routes"] if r["id"]=="trusted-human-managed-file-upload")
    upload["x-ouf-backend-binding"]["service"]="onboarding.other-network.example"
    with pytest.raises(MaterializationError,match="verified transport profile"):
        materialize(candidate,"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")

def test_upload_installation_requires_explicit_request_streaming_before_snapshot():
    routes=materialize(runtime(),"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")["routes"]
    class NoAdminCalls:
        def route(self,*args):
            raise AssertionError("must fail before touching APISIX")
    with pytest.raises(ValueError,match="request streaming"):
        apply(routes,NoAdminCalls())
    ready=materialize(runtime(),"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET",streaming_runtime=True)["routes"]
    upload=next(r for r in ready if r["id"]=="trusted-human-managed-file-upload")
    assert upload["plugins"]["proxy-control"]=={"request_buffering":False}
    assert all("proxy-control" not in r["plugins"] for r in ready if r is not upload)

    class UnsupportedPlugin:
        def curl(self,*args,**kwargs):
            return 404,{}
        def route(self,*args):
            raise AssertionError("must fail before route snapshot")
    with pytest.raises(RuntimeError,match="proxy-control plugin schema"):
        apply(ready,UnsupportedPlugin())
