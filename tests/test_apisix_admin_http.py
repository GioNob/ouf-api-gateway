import pytest
from tools.apisix_admin_http import APISIXAdminHTTP


def test_admin_requires_https():
    with pytest.raises(ValueError,match="https"):APISIXAdminHTTP("http://apisix:9180","secret")

def test_admin_rejects_url_credentials():
    with pytest.raises(ValueError):APISIXAdminHTTP("https://user:pass@apisix.example","secret")

def test_admin_requires_api_key():
    with pytest.raises(ValueError,match="key"):APISIXAdminHTTP("https://apisix.example","")

def test_revision_id_is_path_encoded():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    seen=[]
    admin._request=lambda method,path,body=None,expected=(200,201):(seen.append((method,path,body)) or {})
    admin.put_revision("sha256:a/b",{"routes":[]})
    assert "%2F" in seen[0][1]

def test_probe_never_fakes_runtime_authorization_or_upstream_evidence():
    admin=APISIXAdminHTTP("https://apisix.example","secret")
    admin.read_revision=lambda revision:{"routes":[]};admin.health=lambda:True;admin.active_revision=lambda:"rev"
    checks=admin.probe_revision("rev")
    assert checks["health"] and checks["routeBinding"] and checks["convergence"]
    assert checks["authorizationNegativePath"] is False
    assert checks["upstreamReachability"] is False
