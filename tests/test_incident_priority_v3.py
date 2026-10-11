from datetime import datetime, timedelta, timezone
import pytest
from tools.gateway_operational_api import GatewayOperationalOwnerAPI
from tools.operational_incidents import SQLiteOperationalIncidentStore

HEADERS = {"X-OUF-Gateway-Verified":"true", "X-OUF-Principal-ID":"operator", "X-OUF-Authorization-Decision-Ref":"decision"}
def add(store, key, severity="ERROR", action=True):
    return store.open_incident(dedup_key=key, event_type="DEPENDENCY_UNAVAILABLE", severity=severity,
        error_code="TIMEOUT", impact_summary="Dependent work paused.", action_required=action)

def test_priority_before_limit_and_full_summary_counts(tmp_path):
    now = [datetime(2026,10,11,2,0,tzinfo=timezone.utc)]
    store = SQLiteOperationalIncidentStore(tmp_path/"ops.sqlite", clock=lambda:now[0])
    critical = add(store,"critical","CRITICAL")
    other = add(store,"other","ERROR")
    for i in range(20):
        now[0] += timedelta(seconds=1)
        item = add(store,f"resolved-{i}","CRITICAL")
        store.resolve_incident(item.dedup_key,"Recovered.")
    now[0] += timedelta(seconds=1)
    add(store,"recent-info","INFO")
    assert store.list_incidents(limit=1)[0].incident_id == critical.incident_id
    summary = store.summary(limit=1)
    assert summary["status"] == "DEGRADED"
    assert summary["openIncidents"] == 3
    assert summary["truncated"] is True
    api = GatewayOperationalOwnerAPI(store)
    status, body = api.handle(api.INCIDENTS_PATH,HEADERS,'{"limit":1}')
    assert status == 200 and body["truncated"] is True
    assert body["items"][0]["incident_id"] == critical.incident_id
    store.close()

def test_catchup_includes_recovery_update_and_normalizes_offset(tmp_path):
    now = [datetime(2026,10,11,1,0,tzinfo=timezone.utc)]
    store = SQLiteOperationalIncidentStore(tmp_path/"ops.sqlite",clock=lambda:now[0])
    old = add(store,"old")
    now[0] += timedelta(hours=2)
    store.resolve_incident("old","Recovered after operator disconnected.")
    api = GatewayOperationalOwnerAPI(store)
    status, body = api.handle(api.INCIDENTS_PATH,HEADERS,'{"since":"2026-10-11T04:00:00+02:00"}')
    assert status == 200
    assert [i["incident_id"] for i in body["items"]] == [old.incident_id]
    assert body["items"][0]["lifecycle_state"] == "RESOLVED"
    assert body["truncated"] is False
    status, body = api.handle(api.SUMMARY_PATH,HEADERS,'{"since":"2026-10-11T04:00:00+02:00"}')
    assert status == 200 and body["status"] == "HEALTHY"
    assert len(body["items"]) == 1
    store.close()

@pytest.mark.parametrize("since",["2026-10-11T04:00:00","invalid",123])
def test_invalid_since_is_rejected(tmp_path,since):
    import json
    store = SQLiteOperationalIncidentStore(tmp_path/"ops.sqlite")
    api = GatewayOperationalOwnerAPI(store)
    status, body = api.handle(api.INCIDENTS_PATH,HEADERS,json.dumps({"since":since}))
    assert status == 400 and body["code"] == "OPERATIONAL_SINCE_INVALID"
    store.close()

def test_action_and_identity_ties_are_stable(tmp_path):
    fixed = datetime(2026,10,11,2,0,tzinfo=timezone.utc)
    store = SQLiteOperationalIncidentStore(tmp_path/"ops.sqlite",clock=lambda:fixed)
    unattended = add(store,"not-action","ERROR",False)
    first = add(store,"a","ERROR",True)
    second = add(store,"b","ERROR",True)
    ids = [i.incident_id for i in store.list_incidents()]
    assert ids[:2] == sorted([first.incident_id,second.incident_id])
    assert ids[-1] == unattended.incident_id
    store.close()
