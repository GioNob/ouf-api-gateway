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
    runtime_probe: object | None = None

    def __post_init__(self):
        parsed=urllib.parse.urlparse(self.base_url)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("APISIX Admin API requires an origin without URL credentials")
        loopback=parsed.hostname in {"127.0.0.1","localhost","::1"}
        if parsed.scheme not in ({"http","https"} if loopback else {"https"}):
            raise ValueError("APISIX Admin API requires https except for loopback http")
        if not self.api_key: raise ValueError("APISIX Admin API key is required")
        self.base_url=self.base_url.rstrip("/")
        self.ssl_context=ssl.create_default_context(cafile=self.ca_file) if parsed.scheme=="https" else None

    def _request(self,method,path,body=None,expected=(200,201)):
        data=None if body is None else json.dumps(body,separators=(",",":"),sort_keys=True).encode()
        req=urllib.request.Request(self.base_url+path,data=data,method=method,headers={"X-API-KEY":self.api_key,"Accept":"application/json","Content-Type":"application/json"})
        kwargs={"timeout":self.timeout_seconds}
        if self.ssl_context is not None: kwargs["context"]=self.ssl_context
        try:
            with urllib.request.urlopen(req,**kwargs) as response:
                payload=response.read()
                if response.status not in expected: raise APISIXAdminError(f"unexpected APISIX status {response.status}")
                return json.loads(payload) if payload else {}
        except (urllib.error.URLError,TimeoutError,json.JSONDecodeError) as exc: raise APISIXAdminError("APISIX Admin API request failed") from exc

    def health(self):
        try:self._request("GET","/apisix/admin/routes",expected=(200,));return True
        except APISIXAdminError:return False

    @staticmethod
    def _revision_digest(revision):
        prefix,digest=revision.split(":",1) if ":" in revision else ("",revision)
        if prefix != "sha256" or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise APISIXAdminError("invalid OUF revision")
        return digest

    @classmethod
    def _route_ids(cls,revision,artifact):
        digest=cls._revision_digest(revision)[:12]
        return [f"ouf-{digest}-{index:03d}" for index,_ in enumerate(artifact.get("apisixRoutes",[]),start=1)]

    @staticmethod
    def _route_value(response):
        value=response.get("value",response) if isinstance(response,dict) else response
        return value.get("value",value) if isinstance(value,dict) else value

    @classmethod
    def _revision_labels(cls,revision,index):
        return {"ouf_managed":"true","ouf_revision":cls._revision_digest(revision),"ouf_index":f"{index:03d}"}

    def _managed_routes(self):
        payload=self._request("GET","/apisix/admin/routes",expected=(200,))
        items=payload.get("list",[]) if isinstance(payload,dict) else []
        managed=[]
        for item in items:
            value=self._route_value(item)
            if not isinstance(value,dict): continue
            labels=value.get("labels") or {}
            if labels.get("ouf_managed") != "true": continue
            route_id=value.get("id")
            if not route_id and isinstance(item,dict):
                key=item.get("key")
                if isinstance(key,str): route_id=key.rsplit("/",1)[-1]
            if route_id: managed.append((route_id,value))
        return managed

    def _route_ids_for_revision(self,revision):
        digest=self._revision_digest(revision)
        rows=[(route_id,value) for route_id,value in self._managed_routes() if (value.get("labels") or {}).get("ouf_revision")==digest]
        rows.sort(key=lambda pair:(pair[1].get("labels") or {}).get("ouf_index",""))
        return [route_id for route_id,_ in rows]

    def put_revision(self,revision,artifact):
        route_ids=self._route_ids(revision,artifact)
        staged=[]
        try:
            for index,(route_id,route) in enumerate(zip(route_ids,artifact.get("apisixRoutes",[])),start=1):
                body={key:value for key,value in route.items() if key != "id"}
                body["labels"]={**(body.get("labels") or {}),**self._revision_labels(revision,index)}
                body["status"]=0
                self._request("PUT",f"/apisix/admin/routes/{route_id}",body,expected=(200,201))
                value=self._route_value(self._request("GET",f"/apisix/admin/routes/{route_id}",expected=(200,)))
                if not isinstance(value,dict) or value.get("status") != 0:
                    raise APISIXAdminError("staged APISIX route failed read-after-write verification")
                staged.append(route_id)
        except Exception:
            for route_id in reversed(staged):
                try:self._request("DELETE",f"/apisix/admin/routes/{route_id}",expected=(200,204))
                except Exception:pass
            raise

    def revision_matches(self,revision,artifact):
        route_ids=self._route_ids(revision,artifact)
        expected=artifact.get("apisixRoutes",[])
        if len(route_ids) != len(expected): return False
        for index,(route_id,route) in enumerate(zip(route_ids,expected),start=1):
            try:value=self._route_value(self._request("GET",f"/apisix/admin/routes/{route_id}",expected=(200,)))
            except APISIXAdminError:return False
            if not isinstance(value,dict): return False
            for key in ("uri","methods","plugins","upstream"):
                if value.get(key) != route.get(key): return False
            labels=value.get("labels") or {}
            for key,val in self._revision_labels(revision,index).items():
                if labels.get(key) != val:return False
        return True

    def probe_revision(self,revision):
        try:
            route_ids=self._route_ids_for_revision(revision)
            health=self.health()
            convergence=self.active_revision()==revision
        except APISIXAdminError:
            return {k:False for k in ("health","routeBinding","authorizationNegativePath","upstreamReachability","convergence")}
        runtime={"authorizationNegativePath":False,"upstreamReachability":False}
        if route_ids and self.runtime_probe is not None:
            try:
                observed=self.runtime_probe.probe(self,revision,route_ids)
                if isinstance(observed,dict):
                    runtime["authorizationNegativePath"]=observed.get("authorizationNegativePath") is True
                    runtime["upstreamReachability"]=observed.get("upstreamReachability") is True
            except Exception:
                pass
        return {"health":health,"routeBinding":bool(route_ids),**runtime,"convergence":convergence}

    def _set_revision_status(self,revision,status):
        route_ids=self._route_ids_for_revision(revision)
        if not route_ids: raise APISIXAdminError("APISIX revision has no managed routes")
        for route_id in route_ids:
            self._request("PATCH",f"/apisix/admin/routes/{route_id}",{"status":status},expected=(200,))
            value=self._route_value(self._request("GET",f"/apisix/admin/routes/{route_id}",expected=(200,)))
            if not isinstance(value,dict) or value.get("status") != status:
                raise APISIXAdminError("APISIX route status failed to converge")

    def activate_revision(self,revision):
        previous=self.active_revision()
        self._set_revision_status(revision,1)
        try:
            if previous and previous != revision:self._set_revision_status(previous,0)
        except Exception:
            try:self._set_revision_status(revision,0)
            except Exception:pass
            raise
        deadline=time.monotonic()+self.convergence_timeout_seconds
        while time.monotonic()<deadline:
            if self.active_revision()==revision:return
            time.sleep(0.1)
        raise APISIXAdminError("APISIX activation convergence timeout")

    def active_revision(self):
        revisions=set()
        for _,value in self._managed_routes():
            if value.get("status") != 1: continue
            digest=(value.get("labels") or {}).get("ouf_revision")
            if digest: revisions.add(digest)
        if not revisions:return None
        if len(revisions) != 1: raise APISIXAdminError("multiple active OUF revisions")
        return "sha256:"+next(iter(revisions))

    def delete_revision(self,revision):
        if self.active_revision()==revision: raise APISIXAdminError("refusing to delete active APISIX revision")
        route_ids=self._route_ids_for_revision(revision)
        for route_id in reversed(route_ids):
            self._request("DELETE",f"/apisix/admin/routes/{route_id}",expected=(200,204))
