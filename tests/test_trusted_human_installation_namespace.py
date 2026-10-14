import json
from pathlib import Path

import pytest

from tools.materialize_apisix_runtime import MaterializationError
from tools.materialize_trusted_human_installation_runtime import (
    MAX_BODY,
    METHODS,
    NAMESPACE,
    materialize,
)

ROOT=Path(__file__).resolve().parents[1]


def projection():
    return json.loads((ROOT/"tests/fixtures/installation-projection-lab.json").read_text())


def test_materializes_human_only_installation_namespace_without_umbrella_scope():
    p=projection()
    installation={
        "installationId":p["installationId"],
        "revision":p["revision"],
        "checksum":p["checksum"],
        "issuerUrl":p["gateway"]["issuerUrl"],
        "gatewayAudience":p["gateway"]["requiredAudience"],
    }
    doc=materialize(installation,"$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    assert len(doc["routes"])==2
    assert {tuple(r["methods"]) for r in doc["routes"]}=={(m,) for m in METHODS}
    for route in doc["routes"]:
        assert route["uri"]==NAMESPACE
        assert route["upstream"]["nodes"]=={"ouf-onboarding:8080":1}
        assert route["plugins"]["client-control"]["max_body_size"]==MAX_BODY
        oidc=route["plugins"]["openid-connect"]
        assert "required_scopes" not in oidc
        assert oidc["claim_validator"]["audience"]["match_with_client_id"] is True
        assert oidc["set_access_token_header"] is False
        pre=route["plugins"]["serverless-pre-function"]["functions"][0]
        post=route["plugins"]["serverless-post-function"]["functions"][0]
        assert "Authorization" not in pre
        assert "ouf_actor_type" in post and "HUMAN" in post


def test_materializer_rejects_plain_secret_reference():
    p=projection()
    installation={
        "installationId":p["installationId"],
        "revision":p["revision"],
        "checksum":p["checksum"],
        "issuerUrl":p["gateway"]["issuerUrl"],
        "gatewayAudience":p["gateway"]["requiredAudience"],
    }
    with pytest.raises(MaterializationError,match="secret reference"):
        materialize(installation,"plain-secret")


def test_deployer_manages_exactly_two_routes():
    import importlib.util
    path=ROOT/"ops/apisix/deploy_trusted_human_installation.py"
    spec=importlib.util.spec_from_file_location("deploy_trusted_human_installation",path)
    subject=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    assert subject.METHODS==("GET","POST")
    assert subject.CURRENT_IDS=={
        "trusted-human-installation-get",
        "trusted-human-installation-post",
    }
    raw=path.read_text()
    assert "previous.json" in raw
    assert "restore(previous,admin)" in raw
    assert "anonymous protected namespace" in raw
