import json
from pathlib import Path

import pytest

from tools.apply_installation_projection import ProjectionError, apply_projection, caddy_environment
from tools.compile_config import ROOT, compile_config


FIXTURE = ROOT / "tests" / "fixtures" / "installation-projection-lab.json"


def projection():
    return json.loads(FIXTURE.read_text())


def test_installation_projection_resolves_gateway_audience_and_mcp_identity():
    compiled = compile_config(ROOT / "ouf-config")
    resolved = apply_projection(compiled, projection())

    public_mcp = next(r for r in resolved["routes"] if r["id"] == "public-mcp-endpoint")
    assert public_mcp["x-ouf-policy"]["requiredAudience"] == "ouf-api-gateway"

    execution = next(r for r in resolved["routes"] if r["id"] == "mcp-generic-execution")
    assert execution["x-ouf-mediation"]["serviceIdentityRef"] == "installation://iam.workloadClients.mcpServer"
    assert execution["x-ouf-mediation"]["serviceIdentity"] == "ouf-mcp-server"

    policy_bundle = next(r for r in resolved["routes"] if r["id"] == "mcp-authorization-policy-bundle-read")
    assert policy_bundle["x-ouf-policy"]["allowedServiceIdentities"] == ["ouf-mcp-server", "ouf-ingestion", "ouf-udp"]

    assert resolved["x-ouf-installation"] == {
        "installationId": "ouf-lab-netcup-01",
        "revision": 1,
        "checksum": "a" * 64,
        "issuerUrl": "https://auth.ouf-lab.it/realms/ouf",
        "gatewayAudience": "ouf-api-gateway",
        "publicApiBaseUrl": "https://api.ouf-lab.it",
        "mcpServiceIdentity": "ouf-mcp-server",
        "ingestionServiceIdentity": "ouf-ingestion",
        "udpServiceIdentity": "ouf-udp",
    }


def test_caddy_environment_is_derived_only_from_projection():
    assert caddy_environment(projection()) == {
        "OUF_BACKEND_NETWORK": "ouf-backend",
        "OUF_EDGE_NETWORK": "ouf-edge",
        "OUF_INTERNAL_ISSUER_HOST": "auth.ouf-lab.it",
        "OUF_INTERNAL_API_HOST": "api.ouf-lab.it",
        "OUF_OIDC_DISCOVERY_URL": "https://auth.ouf-lab.it/realms/ouf/.well-known/openid-configuration",
    }


def test_missing_installation_projection_data_fails_closed():
    broken = projection()
    del broken["gateway"]["requiredAudience"]
    with pytest.raises(ProjectionError, match="gateway.requiredAudience"):
        apply_projection(compile_config(ROOT / "ouf-config"), broken)


def test_product_caddy_deploy_script_contains_no_lab_hostname_defaults():
    raw = (ROOT / "ops" / "caddy" / "deploy.sh").read_text()
    assert "auth.ouf-lab.it" not in raw
    assert "api.ouf-lab.it" not in raw
    assert "OUF_INSTALLATION_PROJECTION" in raw
    assert "--get caddy.backendNetwork" in raw
    assert "--get caddy.internalApiHost" in raw


def test_missing_ingestion_workload_identity_fails_closed():
    broken = projection()
    del broken["iam"]["workloadClients"]["ingestion"]
    with pytest.raises(ProjectionError, match="iam.workloadClients.ingestion"):
        apply_projection(compile_config(ROOT / "ouf-config"), broken)


def test_missing_udp_workload_identity_fails_closed():
    broken = projection()
    del broken["iam"]["workloadClients"]["udp"]
    with pytest.raises(ProjectionError, match="iam.workloadClients.udp"):
        apply_projection(compile_config(ROOT / "ouf-config"), broken)


def test_mcp_identity_must_match_iam_workload_binding():
    broken = projection()
    broken["mcp"]["environment"]["MCP_OIDC_CLIENT_ID"] = "other-mcp"
    with pytest.raises(ProjectionError, match="mcp workload identity disagrees"):
        apply_projection(compile_config(ROOT / "ouf-config"), broken)
