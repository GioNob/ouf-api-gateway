from pathlib import Path
import json
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_operational_awareness_capabilities_and_routes_are_governed():
    expected = {
        "ouf.ingestion.status": ("ingestion.operations.read", "/api/internal/v1/ingestion/operations/status"),
        "ouf.ingestion.history": ("ingestion.operations.read", "/api/internal/v1/ingestion/operations/history"),
        "ouf.operations.incidents": ("operations.incident.read", "/api/internal/v1/ingestion/operations/incidents"),
        "ouf.operations.explain": ("operations.incident.explain", "/api/internal/v1/ingestion/operations/incidents/explain"),
        "ouf.operations.summary": ("operations.status.read", "/api/internal/v1/ingestion/operations/summary"),
    }
    source = load("ouf-config/source-runtime/ingestion-runtime-operations.yaml")
    assert source["spec"]["endpointRef"] == "service://ouf-ingestion-runtime"
    for capability_id, (scope, backend_path) in expected.items():
        capability = load(f"ouf-config/capabilities/{capability_id}.yaml")
        assert capability["spec"]["scope"] == scope
        assert capability["spec"]["classification"] == ["TENANT_OPERATIONAL"]
        assert capability["spec"]["mcp"]["toolEligible"] is True
        route_name = {
            "ouf.ingestion.status": "mcp-ingestion-status",
            "ouf.ingestion.history": "mcp-ingestion-history",
            "ouf.operations.incidents": "mcp-operations-incidents",
            "ouf.operations.explain": "mcp-operations-explain",
            "ouf.operations.summary": "mcp-operations-summary",
        }[capability_id]
        route = load(f"ouf-config/routes/northbound/{route_name}.yaml")
        assert route["spec"]["capabilityRef"] == f"{capability_id}@1.0.0"
        assert route["spec"]["sourceRef"] == "ingestion-runtime-operations@1.0.0"
        assert route["spec"]["backendBinding"]["service"] == "ouf-ingestion-runtime"
        assert route["spec"]["backendBinding"]["path"] == backend_path
        assert route["spec"]["policy"]["allowedServiceIdentities"] == ["ouf-mcp-server"]
        assert route["spec"]["policy"]["maxRequestBytes"] <= 65536


def test_compiled_routes_preserve_operational_scopes():
    from tools.compile_config import compile_config
    compiled = compile_config(ROOT / "ouf-config")
    operational = {r["id"]: r for r in compiled["routes"] if r["id"].startswith("mcp-ingestion-") or r["id"].startswith("mcp-operations-")}
    assert len(operational) == 5
    scopes = {r["x-ouf-policy"]["requiredScope"] for r in operational.values()}
    assert scopes == {"ingestion.operations.read", "operations.incident.read", "operations.incident.explain", "operations.status.read"}
    assert all(r["service_id"] == "ouf-ingestion-runtime" for r in operational.values())
