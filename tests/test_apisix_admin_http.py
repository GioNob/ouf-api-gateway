import pytest
from tools.apisix_admin_http import APISIXAdminHTTP,APISIXAdminError


def test_admin_allows_loopback_http_only():
    admin=APISIXAdminHTTP("http://127.0.0.1:9180","secret")
    assert admin.base_url=="http://127.0.0.1:9180"
    assert admin.ssl_context is None
    with pytest.raises(ValueError,match="loopback"):APISIXAdminHTTP("http://apisix:9180","secret")

def test_admin_rejects_url_credentials():
    with pytest.raises(ValueError):APISIXAdminHTTP("https://user:pass@apisix.example","secret")

def test_admin_requires_api_key():
    with pytest.raises(ValueError,match="key"):APISIXAdminHTTP("https://apisix.example","")

def test_revision_id_is_path_encoded_and_routes_are_staged_disabled():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    seen=[]
    route={"id":"logical","uri":"/x","methods":["POST"],"plugins":{},"upstream":{"type":"roundrobin","nodes":{"svc:8080":1}}}
    def fake(method,path,body=None,expected=(200,201)):
        seen.append((method,path,body))
        if method=="GET" and "/routes/" in path:
            return {"value":{**route,"status":0}}
        return {}
    admin._request=fake
    admin.put_revision("sha256:a/b",{"apisixRoutes":[route]})
    assert seen[0][0:2]==("PUT","/apisix/admin/routes/ouf-a/b-001")
    assert seen[0][2]["status"]==0
    metadata=next(item for item in seen if "/plugin_metadata/" in item[1])
    assert "%2F" in metadata[1]
    assert metadata[2]["value"]["routeIds"]==["ouf-a/b-001"]

def test_read_revision_verifies_staged_routes_against_artifact():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    route={"id":"logical","uri":"/x","methods":["POST"],"plugins":{},"upstream":{"type":"roundrobin","nodes":{"svc:8080":1}}}
    artifact={"apisixRoutes":[route]}
    def fake(method,path,body=None,expected=(200,201)):
        if "/plugin_metadata/" in path:return {"value":{"value":{"artifact":artifact,"routeIds":["ouf-abc-001"]}}}
        return {"value":{**route,"status":0}}
    admin._request=fake
    assert admin.read_revision("sha256:abc")==artifact

def test_activate_enables_new_revision_disables_previous_then_advances_pointer():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    calls=[]
    admin.active_revision=lambda:"old" if not any("ouf-active-publication" in p for _,p,_ in calls) else "new"
    admin._revision_node=lambda revision:{"routeIds":[revision+"-route"]}
    statuses={}
    def fake_request(method,path,body=None,expected=(200,201)):
        calls.append((method,path,body))
        if method=="PATCH":statuses[path]=body["status"];return {}
        if method=="GET" and "/routes/" in path:return {"value":{"status":statuses[path]}}
        return {}
    admin._request=fake_request
    admin.activate_revision("new")
    assert ("PATCH","/apisix/admin/routes/new-route",{"status":1}) in calls
    assert ("PATCH","/apisix/admin/routes/old-route",{"status":0}) in calls
    assert any(path=="/apisix/admin/plugin_metadata/ouf-active-publication" for _,path,_ in calls)

def test_delete_revision_refuses_active_revision():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    admin.active_revision=lambda:"rev"
    with pytest.raises(APISIXAdminError,match="active"):admin.delete_revision("rev")

def test_probe_never_fakes_runtime_authorization_or_upstream_evidence():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    admin.read_revision=lambda revision:{"routes":[]};admin.health=lambda:True;admin.active_revision=lambda:"rev"
    checks=admin.probe_revision("rev")
    assert checks["health"] and checks["routeBinding"] and checks["convergence"]
    assert checks["authorizationNegativePath"] is False
    assert checks["upstreamReachability"] is False
