from pathlib import Path

from tools.compile_config import compile_config


ROOT = Path(__file__).resolve().parents[1]


def test_identity_preflight_separates_human_rebuild_from_service_attestation_read():
    routes = {route["id"]: route for route in compile_config(ROOT / "ouf-config")["routes"]}
    create = routes["ths-identity-preflight-create"]
    read = routes["ths-identity-preflight-read"]
    internal = routes["onboarding-identity-preflight-read"]
    assert create["methods"] == ["POST"]
    assert read["methods"] == ["GET"]
    assert all(route["x-ouf-policy"]["allowedActorTypes"] == ["HUMAN"]
               for route in (create, read))
    assert all(route["x-ouf-capability"]["toolEligible"] is False
               for route in (create, read, internal))
    assert internal["methods"] == ["GET"]
    assert internal["x-ouf-policy"]["identity"] == "M2M"
    assert internal["x-ouf-policy"]["allowedServiceIdentities"] == ["ouf-source-onboarding"]
    assert internal["x-ouf-policy"]["allowedActorTypes"] == ["SERVICE"]
    assert internal["plugins"]["proxy-rewrite"]["uri"] == "/api/udp/v1/governance/internal/identity/preflight"
