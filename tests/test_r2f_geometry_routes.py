from pathlib import Path
from tools.compile_config import compile_config

ROOT=Path(__file__).resolve().parents[1]

def test_geometry_review_and_decision_keep_bounded_owner_paths_and_human_contract():
    routes={r["id"]:r for r in compile_config(ROOT/"ouf-config")["routes"]}
    read,write=routes["r2f-geometry-review"],routes["r2f-geometry-decision"]
    assert read["methods"]==["GET"] and write["methods"]==["POST"]
    assert read["x-ouf-policy"]["requiredScope"]=="resolution.issue.read"
    assert write["x-ouf-policy"]["requiredScope"]=="authority.override"
    assert write["x-ouf-policy"]["allowedActorTypes"]==["HUMAN_USER"]
    assert write["x-ouf-capability"]["humanRequired"] is True
    assert write["x-ouf-capability"]["toolEligible"] is False
    for route in (read,write):
        assert route["uri"]=="/api/udp/v1/governance/geometry/issues/*"
        assert route["service_id"]=="ouf-udp-object-resolution"
        assert "proxy-rewrite" not in route["plugins"]
        assert route["x-ouf-policy"]["identity"]=="OIDC"


def test_property_decisions_and_onboarding_surface_preserve_ownership():
    routes={r["id"]:r for r in compile_config(ROOT/"ouf-config")["routes"]}
    for action in ("review","decision"):
        route=routes["r2f-property-"+action]
        assert route["service_id"]=="ouf-udp-object-resolution"
        assert route["uri"]=="/api/udp/v1/governance/properties/conflicts/*"
    write=routes["r2f-property-decision"]
    assert write["x-ouf-policy"]["allowedActorTypes"]==["HUMAN_USER"]
    assert write["x-ouf-capability"]["toolEligible"] is False
    for name in ("page","assets"):
        route=routes["r2f-review-"+name]
        assert route["service_id"]=="ouf-source-onboarding"
        assert route["x-ouf-policy"]["allowedActorTypes"]==["HUMAN_USER"]
        assert route["methods"]==["GET"]


def test_access_schema_proposal_route_cannot_become_an_approval_route():
    routes={r["id"]:r for r in compile_config(ROOT/"ouf-config")["routes"]}
    route=routes["r2f-access-proposals"]
    assert route["uri"]=="/api/onboarding/v1/access-semantic-proposals"
    assert route["service_id"]=="ouf-source-onboarding"
    assert route["methods"]==["POST"]
    assert route["x-ouf-policy"]["requiredScope"]=="ouf.source-onboarding.semantic-gap.create"
    assert route["x-ouf-capability"]["toolEligible"] is True
