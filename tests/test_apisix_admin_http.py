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

def _revision(ch="a"): return "sha256:"+ch*64

def _route(): return {"id":"logical","uri":"/x","methods":["POST"],"plugins":{},"upstream":{"type":"roundrobin","nodes":{"svc:8080":1}}}

def test_routes_are_staged_disabled_without_body_id_and_with_revision_labels():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    seen=[];route=_route();revision=_revision()
    def fake(method,path,body=None,expected=(200,201)):
        seen.append((method,path,body))
        if method=="GET" and "/routes/" in path:
            return {"value":{**{k:v for k,v in route.items() if k!="id"},"labels":admin._revision_labels(revision,1),"status":0}}
        return {}
    admin._request=fake
    admin.put_revision(revision,{"apisixRoutes":[route]})
    assert seen[0][0:2]==("PUT","/apisix/admin/routes/ouf-aaaaaaaaaaaa-001")
    assert seen[0][2]["status"]==0 and "id" not in seen[0][2]
    assert seen[0][2]["labels"]["ouf_revision"]=="a"*64
    assert all("plugin_metadata" not in path for _,path,_ in seen)

def test_revision_matches_reads_real_routes():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    route=_route();artifact={"apisixRoutes":[route]};revision=_revision("b")
    def fake(method,path,body=None,expected=(200,201)):
        return {"value":{**{k:v for k,v in route.items() if k!="id"},"labels":admin._revision_labels(revision,1),"status":0}}
    admin._request=fake
    assert admin.revision_matches(revision,artifact) is True

def test_active_revision_is_derived_from_enabled_managed_routes():
    admin=APISIXAdminHTTP("https://apisix.example","secret");revision=_revision("c")
    admin._request=lambda *a,**k:{"list":[{"key":"/apisix/routes/r1","value":{"status":1,"labels":admin._revision_labels(revision,1)}}]}
    assert admin.active_revision()==revision

def test_multiple_active_revisions_fail_closed():
    admin=APISIXAdminHTTP("https://apisix.example","secret");r1=_revision("c");r2=_revision("d")
    admin._request=lambda *a,**k:{"list":[
        {"key":"/apisix/routes/r1","value":{"status":1,"labels":admin._revision_labels(r1,1)}},
        {"key":"/apisix/routes/r2","value":{"status":1,"labels":admin._revision_labels(r2,1)}}]}
    with pytest.raises(APISIXAdminError,match="multiple active"):admin.active_revision()

def test_delete_revision_refuses_active_revision():
    admin=APISIXAdminHTTP("https://apisix.example","secret");revision=_revision()
    admin.active_revision=lambda:revision
    with pytest.raises(APISIXAdminError,match="active"):admin.delete_revision(revision)

def test_probe_never_fakes_runtime_authorization_or_upstream_evidence():
    admin=APISIXAdminHTTP("https://apisix.example","secret");revision=_revision()
    admin._route_ids_for_revision=lambda revision:["r1"];admin.health=lambda:True;admin.active_revision=lambda:revision
    checks=admin.probe_revision(revision)
    assert checks["health"] and checks["routeBinding"] and checks["convergence"]
    assert checks["authorizationNegativePath"] is False
    assert checks["upstreamReachability"] is False
