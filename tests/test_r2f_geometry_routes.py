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
