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
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("APISIX Admin API requires an https origin without URL credentials")
        if not self.api_key: raise ValueError("APISIX Admin API key is required")
        self.base_url=self.base_url.rstrip("/")
        self.ssl_context=ssl.create_default_context(cafile=self.ca_file)

    def _request(self,method,path,body=None,expected=(200,201)):
        data=None if body is None else json.dumps(body,separators=(",",":"),sort_keys=True).encode()
        req=urllib.request.Request(self.base_url+path,data=data,method=method,headers={"X-API-KEY":self.api_key,"Accept":"application/json","Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(req,timeout=self.timeout_seconds,context=self.ssl_context) as response:
                payload=response.read()
                if response.status not in expected: raise APISIXAdminError(f"unexpected APISIX status {response.status}")
                return json.loads(payload) if payload else {}
        except (urllib.error.URLError,TimeoutError,json.JSONDecodeError) as exc: raise APISIXAdminError("APISIX Admin API request failed") from exc

    def health(self):
        try:self._request("GET","/apisix/admin/routes",expected=(200,));return True
        except APISIXAdminError:return False

    def put_revision(self,revision,artifact):
        rid=urllib.parse.quote(revision,safe="")
        self._request("PUT",f"/apisix/admin/plugin_metadata/ouf-publication-{rid}",{"value":{"revision":revision,"artifact":artifact}},expected=(200,201))

    def read_revision(self,revision):
        rid=urllib.parse.quote(revision,safe="")
        value=self._request("GET",f"/apisix/admin/plugin_metadata/ouf-publication-{rid}",expected=(200,))
        node=value.get("value",value).get("value",value.get("value",value))
        if isinstance(node,dict) and "artifact" in node:return node["artifact"]
        raise APISIXAdminError("staged APISIX revision is unreadable")

    def probe_revision(self,revision):
        # Structural probes are executed against the adopted Admin API state;
        # Authorization/upstream runtime probes remain explicit environment gates.
        try:self.read_revision(revision);health=self.health()
        except APISIXAdminError:return {k:False for k in ("health","routeBinding","authorizationNegativePath","upstreamReachability","convergence")}
        return {"health":health,"routeBinding":True,"authorizationNegativePath":False,"upstreamReachability":False,"convergence":self.active_revision()==revision}

    def activate_revision(self,revision):
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
        rid=urllib.parse.quote(revision,safe="")
        self._request("DELETE",f"/apisix/admin/plugin_metadata/ouf-publication-{rid}",expected=(200,204))
