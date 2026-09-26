import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "ops/policy_token/refresh_policy_token.py"


def load_subject():
    spec = importlib.util.spec_from_file_location("refresh_policy_token", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generic_refresher_has_no_workload_specific_client_id():
    text = MODULE.read_text()
    assert "ouf-mcp-server" not in text
    assert "ouf-ingestion" not in text
    assert "ouf-udp" not in text
    assert "OUF_POLICY_TOKEN_CLIENT_ID" in text
    assert "os.replace" in text
    assert "0o440" in text


def test_systemd_templates_are_parameterized_and_hardened():
    service = (ROOT / "ops/policy_token/ouf-policy-token@.service").read_text()
    timer = (ROOT / "ops/policy_token/ouf-policy-token@.timer").read_text()
    assert "EnvironmentFile=/etc/ouf/policy-token/%i.conf" in service
    assert "RuntimeDirectory=ouf-%i-auth" in service
    assert "ProtectSystem=strict" in service
    assert "NoNewPrivileges=true" in service
    assert "OnUnitActiveSec=60s" in timer
    assert "ouf-policy-token@%i.service" in timer


def test_validate_response_rejects_non_bearer_and_short_lifetime():
    subject = load_subject()
    assert subject.validate_response({"access_token": "abc.def.ghi", "token_type": "Bearer", "expires_in": 60}) == "abc.def.ghi"
    with pytest.raises(ValueError):
        subject.validate_response({"access_token": "abc", "token_type": "MAC"})
    with pytest.raises(ValueError):
        subject.validate_response({"access_token": "abc", "token_type": "Bearer", "expires_in": 10})


def test_udp_installation_projection_resolves_policy_reader():
    import json
    from tools.compile_config import ROOT as CONFIG_ROOT, compile_config
    from tools.apply_installation_projection import apply_projection

    projection = json.loads((ROOT / "tests/fixtures/installation-projection-lab.json").read_text())
    runtime = apply_projection(compile_config(CONFIG_ROOT / "ouf-config"), projection)
    route = next(r for r in runtime["routes"] if r["id"] == "mcp-authorization-policy-bundle-read")
    assert route["x-ouf-policy"]["allowedServiceIdentities"] == ["ouf-mcp-server", "ouf-ingestion", "ouf-udp", "ouf-semantic"]
    assert runtime["x-ouf-installation"]["udpServiceIdentity"] == "ouf-udp"
