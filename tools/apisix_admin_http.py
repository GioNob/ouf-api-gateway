import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


class APISIXAdminError(RuntimeError): pass


@dataclass
class APISIXAdminHTTP:
    base_url: str
    api_key: str
    timeout_seconds: float = 3.0
    convergence_timeout_seconds: float = 30.0
    ca_file: str | None = None

    def __post_init__(self):
        parsed=urllib.parse.urlparse(self.base_url)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("APISIX Admin API requires an origin without URL credentials")
        if parsed.scheme == "http":
            if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("APISIX Admin API permits plaintext HTTP only on loopback")
            self.ssl_context=None
        elif parsed.scheme == "https":
            self.ssl_context=ssl.create_default_context(cafile=self.ca_file)
        else:
            raise ValueError("APISIX Admin API requires https, or loopback http")
        if not self.api_key: raise ValueError("APISIX Admin API key is required")
        self.base_url=self.base_url.rstrip("/")

    def _request(self,method,path,body=None,expected=(200,201)):
        data=None if body is None else json.dumps(body,separators=(",",":"),sort_keys=True).encode()
        req=urllib.request.Request(self.base_url+path,data=data,method=method,headers={"X-API-KEY":self.api_key,"Accept":"application/json","Content-Type":"application/json"})
        try:
            kwargs={"timeout":self.timeout_seconds}
            if self.ssl_context is not None: kwargs["context"]=self.ssl_context
            with urllib.request.urlopen(req,**kwargs) as response:
                payload=response.read()
                if response.status not in expected: raise APISIXAdminError(f"unexpected APISIX status {response.status}")
                return json.loads(payload) if payload else {}
        except (urllib.error.URLError,TimeoutError,json.JSONDecodeError) as exc: raise APISIXAdminError("APISIX Admin API request failed") from exc

    def health(self):
        try:self._request("GET","/apisix/admin/routes",expected=(200,));return True
        except APISIXAdminError:return False

    @staticmethod
    def _route_ids(revision, artifact):
        digest=revision.split(":",1)[-1][:12]
        return [f"ouf-{digest}-{index:03d}" for index,_ in enumerate(artifact.get("apisixRoutes",[]),start=1)]

    @staticmethod
    def _route_value(response):
        value=response.get("value",response)
        return value.get("value",value) if isinstance(value,dict) else value

    def put_revision(self,revision,artifact):
        route_ids=self._route_ids(revision,artifact)
        staged=[]
        try:
            for route_id,route in zip(route_ids,artifact.get("apisixRoutes",[])):
                body={**route,"status":0}
                self._request("PUT",f"/apisix/admin/routes/{route_id}",body,expected=(200,201))
                value=self._route_value(self._request("GET",f"/apisix/admin/routes/{route_id}",expected=(200,)))
                if not isinstance(value,dict) or value.get("status") != 0:
                    raise APISIXAdminError("staged APISIX route failed read-after-write verification")
                staged.append(route_id)
            rid=urllib.parse.quote(revision,safe="")
            self._request("PUT",f"/apisix/admin/plugin_metadata/ouf-publication-{rid}",{"value":{"revision":revision,"artifact":artifact,"routeIds":route_ids}},expected=(200,201))
        except Exception:
            for route_id in reversed(staged):
                try:self._request("DELETE",f"/apisix/admin/routes/{route_id}",expected=(200,204))
                except Exception:pass
            raise

    def _revision_node(self,revision):
        rid=urllib.parse.quote(revision,safe="")
        value=self._request("GET",f"/apisix/admin/plugin_metadata/ouf-publication-{rid}",expected=(200,))
        node=value.get("value",value).get("value",value.get("value",value))
        if not isinstance(node,dict) or "artifact" not in node or "routeIds" not in node:
            raise APISIXAdminError("staged APISIX revision is unreadable")
        return node

    def read_revision(self,revision):
        node=self._revision_node(revision)
        artifact=node["artifact"]
        route_ids=node["routeIds"]
        expected=artifact.get("apisixRoutes",[])
        if len(route_ids) != len(expected): raise APISIXAdminError("staged APISIX revision route count mismatch")
        for route_id,route in zip(route_ids,expected):
            value=self._route_value(self._request("GET",f"/apisix/admin/routes/{route_id}",expected=(200,)))
            if not isinstance(value,dict): raise APISIXAdminError("staged APISIX route is unreadable")
            for key in ("uri","methods","plugins","upstream"):
                if value.get(key) != route.get(key):
                    raise APISIXAdminError("staged APISIX route differs from compiled artifact")
        return artifact

    def probe_revision(self,revision):
        try:self.read_revision(revision);health=self.health()
        except APISIXAdminError:return {k:False for k in ("health","routeBinding","authorizationNegativePath","upstreamReachability","convergence")}
        return {"health":health,"routeBinding":True,"authorizationNegativePath":False,"upstreamReachability":False,"convergence":self.active_revision()==revision}

    def _set_revision_status(self,revision,status):
        node=self._revision_node(revision)
        for route_id in node["routeIds"]:
            self._request("PATCH",f"/apisix/admin/routes/{route_id}",{"status":status},expected=(200,))
            value=self._route_value(self._request("GET",f"/apisix/admin/routes/{route_id}",expected=(200,)))
            if not isinstance(value,dict) or value.get("status") != status:
                raise APISIXAdminError("APISIX route status failed to converge")

    def activate_revision(self,revision):
        previous=self.active_revision()
        self._set_revision_status(revision,1)
        if previous and previous != revision:
            self._set_revision_status(previous,0)
        self._request("PUT","/apisix/admin/plugin_metadata/ouf-active-publication",{"value":{"revision":revision}},expected=(200,201))
        deadline=time.monotonic()+self.convergence_timeout_seconds
        while time.monotonic()<deadline:
            if self.active_revision()==revision:return
            time.sleep(0.1)
        raise APISIXAdminError("APISIX activation convergence timeout")

    def active_revision(self):
        try:value=self._request("GET","/apisix/admin/plugin_metadata/ouf-active-publication",expected=(200,))
        except APISIXAdminError:return None
        node=value.get("value",value).get("value",value.get("value",value))
        return node.get("revision") if isinstance(node,dict) else None

    def delete_revision(self,revision):
        if self.active_revision()==revision: raise APISIXAdminError("refusing to delete active APISIX revision")
        node=self._revision_node(revision)
        for route_id in reversed(node["routeIds"]):
            self._request("DELETE",f"/apisix/admin/routes/{route_id}",expected=(200,204))
        rid=urllib.parse.quote(revision,safe="")
        self._request("DELETE",f"/apisix/admin/plugin_metadata/ouf-publication-{rid}",expected=(200,204))
