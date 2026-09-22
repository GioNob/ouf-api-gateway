import json
from datetime import datetime, timezone, timedelta
from tools.operational_incidents import SQLiteOperationalIncidentStore
from tools.gateway_operational_api import GatewayOperationalOwnerAPI


def open_incident(store, key, visibility="TENANT_OPERATIONAL"):
    return store.open_incident(dedup_key=key,event_type="SOURCE_UNAVAILABLE",severity="ERROR",error_code="SOURCE_UNAVAILABLE",impact_summary="Source unavailable",visibility_class=visibility)


def test_snapshot_pages_survive_recovery_restart_and_do_not_duplicate(tmp_path):
    clock=[datetime(2026,9,22,8,tzinfo=timezone.utc)]
    path=tmp_path/"incidents.sqlite"
    store=SQLiteOperationalIncidentStore(path,clock=lambda:clock[0])
    expected={open_incident(store,str(n)).incident_id for n in range(4)}
    first=store.incident_page({"limit":2},"tenant:user")
    clock[0]+=timedelta(seconds=2)
    store.resolve_incident("0","Recovered")
    open_incident(store,"new")
    store.close()
    store=SQLiteOperationalIncidentStore(path,clock=lambda:clock[0])
    second=store.incident_page({"limit":2,"cursor":first["nextCursor"]},"tenant:user")
    assert second["hasMore"] is False
    items=first["items"]+second["items"]
    assert len(items)==4 and {i["incident_id"] for i in items}==expected
    assert all(i["lifecycle_state"]=="OPEN" for i in items)
    store.close()


def test_owner_reauthorizes_and_redacts_restricted_data(tmp_path):
    store=SQLiteOperationalIncidentStore(tmp_path/"incidents.sqlite")
    open_incident(store,"protected","RESTRICTED_OPERATIONAL")
    headers={"X-OUF-Gateway-Verified":"true","X-OUF-Principal-ID":"reader","X-OUF-Authorization-Decision-Ref":"decision","X-OUF-Tenant-ID":"tenant"}
    api=GatewayOperationalOwnerAPI(store)
    assert api.handle(api.INCIDENTS_PATH,headers)[0]==503
    api=GatewayOperationalOwnerAPI(store,tenant_id="tenant",summary_authorizer=lambda *args:True)
    code,body=api.handle(api.INCIDENTS_PATH,headers)
    assert code==200 and body["partial"] is True and body["items"]==[]
    assert api.handle(api.INCIDENTS_PATH,{**headers,"X-OUF-Tenant-ID":"other"})[0]==403
    api.summary_authorizer=lambda *args:False
    assert api.handle(api.INCIDENTS_PATH,headers)[0]==403
    store.close()


def test_cursor_bound_to_filters_and_principal(tmp_path):
    import pytest
    store=SQLiteOperationalIncidentStore(tmp_path/"incidents.sqlite")
    open_incident(store,"a");open_incident(store,"b")
    page=store.incident_page({"limit":1},"tenant:user")
    with pytest.raises(ValueError):store.incident_page({"limit":1,"cursor":page["nextCursor"]},"other:user")
    with pytest.raises(ValueError):store.incident_page({"limit":1,"state":"RESOLVED","cursor":page["nextCursor"]},"tenant:user")
    with pytest.raises(ValueError):store.incident_page({"limit":1,"until":"not-a-date"},"tenant:user")
    store.close()
