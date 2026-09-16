from tools.gateway_operational_api import GatewayOperationalOwnerAPI
from tools.operational_incidents import SQLiteOperationalIncidentStore


def trusted_headers():
    return {
        "X-OUF-Gateway-Verified": "true",
        "X-OUF-Principal-ID": "operator",
        "X-OUF-Authorization-Decision-Ref": "authz://decision/1",
    }


def test_owner_api_requires_verified_gateway_and_authorization(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite")
    api = GatewayOperationalOwnerAPI(store)
    status, body = api.handle(api.SUMMARY_PATH, {})
    assert status == 401
    assert body["code"] == "TRUSTED_GATEWAY_CONTEXT_REQUIRED"
    status, body = api.handle(api.SUMMARY_PATH, {"X-OUF-Gateway-Verified": "true"})
    assert status == 403
    assert body["code"] == "VERIFIED_AUTHORIZATION_CONTEXT_REQUIRED"
    store.close()


def test_owner_api_returns_safe_persisted_incident_projection(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite")
    incident = store.open_incident(
        dedup_key="gateway:publication:blocked",
        event_type="GATEWAY_PUBLICATION_BLOCKED",
        severity="ERROR",
        error_code="PUBLICATION_STAGE_FAILED",
        impact_summary="Gateway configuration publication is blocked.",
        correlation_id="publication-1",
        endpoint_ref="gateway://control-plane/publication",
    )
    api = GatewayOperationalOwnerAPI(store)
    status, body = api.handle(api.INCIDENTS_PATH, trusted_headers(), '{"limit":10}')
    assert status == 200
    assert body["partial"] is False
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["incident_id"] == incident.incident_id
    assert item["module"] == "GATEWAY"
    assert item["endpoint_ref"].startswith("gateway://")
    assert "hostname" not in str(item).lower()
    assert "token" not in str(item).lower()
    store.close()


def test_owner_api_is_bounded(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite")
    api = GatewayOperationalOwnerAPI(store)
    status, body = api.handle(api.INCIDENTS_PATH, trusted_headers(), '{"limit":101}')
    assert status == 400
    assert body["code"] == "OPERATIONAL_LIMIT_INVALID"
    store.close()
