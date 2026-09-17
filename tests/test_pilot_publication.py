from pathlib import Path

from tools.compile_config import ROOT, compile_config
from tools.pilot_publication import filtered_config, preflight


class Gate:
    def binding_exists(self, capability_ref, required_scope):
        return capability_ref.startswith("urban.object.related_search@") and required_scope=="urban.object.related_search"


class Plane:
    def __init__(self):
        self.staged=None
        self.rolled_back=None
    def healthy(self): return True
    def stage(self, artifact):
        self.staged=artifact
        return "sha256:"+"a"*64
    def verify(self, revision, artifact):
        return {
            "health":True,
            "routeBinding":True,
            "authorizationNegativePath":True,
            "upstreamReachability":True,
            "convergence":False,
            "artifactIntegrity":True,
        }
    def rollback(self, revision): self.rolled_back=revision


def test_filtered_config_keeps_exactly_one_governed_route(tmp_path):
    root=filtered_config(ROOT/"ouf-config","mcp-related-search",tmp_path/"ouf-config")
    artifact=compile_config(root)
    assert [r["id"] for r in artifact["apisixRoutes"]]==["mcp-related-search"]
    assert [r["id"] for r in artifact["routes"]]==["mcp-related-search"]


def test_preflight_verifies_single_route_and_always_rolls_back(tmp_path):
    plane=Plane()
    result=preflight(ROOT/"ouf-config","mcp-related-search","test",plane,Gate())
    assert result["verified"] is True
    assert result["checks"]["convergence"] is False
    assert len(plane.staged["apisixRoutes"])==1
    assert plane.staged["apisixRoutes"][0]["id"]=="mcp-related-search"
    assert plane.rolled_back==result["revision"]
