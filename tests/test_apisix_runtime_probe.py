from tools.apisix_runtime_probe import APISIXHTTPRuntimeProbe


class FakeAdmin:
    def __init__(self): self.calls=[]
    @staticmethod
    def _revision_digest(revision): return revision.split(":",1)[1]
    @staticmethod
    def _route_value(response): return response["value"]
    def _request(self,method,path,body=None,expected=(200,201)):
        self.calls.append((method,path,body))
        if method=="GET":
            return {"value":{"id":"staged","uri":"/probe","methods":["POST"],"plugins":{"openid-connect":{}},"upstream":{"type":"roundrobin","nodes":{"svc:8080":1}},"status":0,"labels":{"ouf_managed":"true"}}}
        return {}


def test_runtime_probe_accepts_observed_401_403_and_backend_404():
    probe=APISIXHTTPRuntimeProbe("http://127.0.0.1:9080","negative","positive")
    statuses=iter([401,403,404])
    probe._status=lambda *args,**kwargs:next(statuses)
    admin=FakeAdmin()
    result=probe.probe(admin,"sha256:"+"a"*64,["r1"])
    assert result=={"authorizationNegativePath":True,"upstreamReachability":True}
    put=next(call for call in admin.calls if call[0]=="PUT")
    assert put[1]=="/apisix/admin/routes/ouf-probe-aaaaaaaaaaaa"
    assert put[2]["status"]==1 and put[2]["labels"]=={"ouf_probe":"runtime-verification"}
    assert all(key not in put[2] for key in ("id","create_time","update_time"))
    assert any(call[0]=="DELETE" and call[1].endswith("ouf-probe-aaaaaaaaaaaa") for call in admin.calls)


def test_runtime_probe_rejects_missing_negative_scope_enforcement():
    probe=APISIXHTTPRuntimeProbe("http://127.0.0.1:9080","negative","positive")
    statuses=iter([401,200,404])
    probe._status=lambda *args,**kwargs:next(statuses)
    result=probe.probe(FakeAdmin(),"sha256:"+"b"*64,["r1"])
    assert result["authorizationNegativePath"] is False
    assert result["upstreamReachability"] is True


def test_runtime_probe_rejects_gateway_upstream_failure():
    probe=APISIXHTTPRuntimeProbe("http://127.0.0.1:9080","negative","positive")
    statuses=iter([401,403,503])
    probe._status=lambda *args,**kwargs:next(statuses)
    result=probe.probe(FakeAdmin(),"sha256:"+"c"*64,["r1"])
    assert result["authorizationNegativePath"] is True
    assert result["upstreamReachability"] is False


def test_runtime_probe_is_fail_closed_for_multi_route_revision():
    probe=APISIXHTTPRuntimeProbe("http://127.0.0.1:9080","negative","positive")
    result=probe.probe(FakeAdmin(),"sha256:"+"d"*64,["r1","r2"])
    assert result=={"authorizationNegativePath":False,"upstreamReachability":False}


def test_runtime_probe_requires_secure_non_loopback_transport():
    try:
        APISIXHTTPRuntimeProbe("http://apisix:9080","negative","positive")
    except ValueError as exc:
        assert "https" in str(exc)
    else:
        raise AssertionError("non-loopback HTTP must be rejected")
