import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass
class APISIXHTTPRuntimeProbe:
    data_plane_url: str
    negative_token: str
    positive_token: str
    timeout_seconds: float = 5.0

    def __post_init__(self):
        parsed=urllib.parse.urlparse(self.data_plane_url)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("APISIX data-plane probe requires an origin without URL credentials")
        loopback=parsed.hostname in {"127.0.0.1","localhost","::1"}
        if parsed.scheme not in ({"http","https"} if loopback else {"https"}):
            raise ValueError("APISIX data-plane probe requires https except for loopback http")
        if not self.negative_token or not self.positive_token:
            raise ValueError("APISIX data-plane probe requires negative and positive tokens")
        self.data_plane_url=self.data_plane_url.rstrip("/")

    def _status(self,method,path,token=None):
        headers={"Accept":"application/json","Content-Type":"application/json"}
        if token: headers["Authorization"]="Bearer "+token
        body=b"{}" if method in {"POST","PUT","PATCH"} else None
        req=urllib.request.Request(self.data_plane_url+path,data=body,method=method,headers=headers)
        try:
            with urllib.request.urlopen(req,timeout=self.timeout_seconds) as response:
                response.read()
                return response.status
        except urllib.error.HTTPError as exc:
            exc.read()
            return exc.code
        except (urllib.error.URLError,TimeoutError):
            return 0

    def probe(self,admin,revision,route_ids):
        if len(route_ids) != 1:
            return {"authorizationNegativePath":False,"upstreamReachability":False}
        source_id=route_ids[0]
        source=admin._route_value(admin._request("GET",f"/apisix/admin/routes/{source_id}",expected=(200,)))
        if not isinstance(source,dict):
            return {"authorizationNegativePath":False,"upstreamReachability":False}
        methods=source.get("methods") or []
        path=source.get("uri")
        if not isinstance(path,str) or len(methods) != 1:
            return {"authorizationNegativePath":False,"upstreamReachability":False}
        method=methods[0]
        probe_id="ouf-probe-"+admin._revision_digest(revision)[:12]
        body={k:v for k,v in source.items() if k not in {"id","create_time","update_time","status","labels"}}
        body["status"]=1
        body["labels"]={"ouf_probe":"runtime-verification"}
        try:
            admin._request("PUT",f"/apisix/admin/routes/{probe_id}",body,expected=(200,201))
            no_token=self._status(method,path)
            negative=self._status(method,path,self.negative_token)
            positive=self._status(method,path,self.positive_token)
        except Exception:
            return {"authorizationNegativePath":False,"upstreamReachability":False}
        finally:
            try:admin._request("DELETE",f"/apisix/admin/routes/{probe_id}",expected=(200,204))
            except Exception:pass
        authorization_negative=(no_token==401 and negative==403)
        upstream_reachable=(200 <= positive < 500 and positive not in {401,403})
        return {"authorizationNegativePath":authorization_negative,"upstreamReachability":upstream_reachable}
