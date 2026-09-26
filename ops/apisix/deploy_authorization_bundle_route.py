#!/usr/bin/env python3
"""Install/restore the governed Authorization ACTIVE bundle route in APISIX."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROUTE_ID="mcp-authorization-policy-bundle-read"
ROUTE_URI="/internal/capabilities/v1/authorization/policy-bundle/active"


def route_value(doc):
    value=doc.get("value",doc)
    if isinstance(value,dict) and isinstance(value.get("value"),dict):
        value=value["value"]
    return {k:v for k,v in value.items() if k not in ("create_time","update_time")}


class Admin:
    def __init__(self,args):
        self.args=args
        args.backup_dir.mkdir(parents=True,exist_ok=True)
        self.work=Path(tempfile.mkdtemp(prefix="authorization-bundle-route-",dir=args.backup_dir))
        key=args.admin_key.read_text().strip()
        if not key or "\n" in key or "\r" in key:
            raise ValueError("invalid APISIX admin key")
        (self.work/"admin.header").write_text("X-API-KEY: "+key+"\n")
        os.chmod(self.work/"admin.header",0o600)
        print("BACKUP="+str(self.work/"previous.json"),flush=True)

    def curl(self,path,method="GET",data=None,admin=False,headers=None):
        cmd=["docker","run","--rm","--user","0:0",
             "--network","container:"+self.args.container,
             "-v",str(self.work)+":/work",self.args.curl_image,
             "--max-time","15","-sS","-o","/work/response.json","-w","%{http_code}","-X",method]
        if admin:
            cmd += ["-H","@/work/admin.header"]
        for h in headers or []:
            cmd += ["-H",h]
        if data is not None:
            (self.work/"request.json").write_text(json.dumps(data))
            cmd += ["-H","Content-Type: application/json","--data-binary","@/work/request.json"]
        cmd += ["http://127.0.0.1:"+("9180" if admin else "9080")+path]
        result=subprocess.run(cmd,check=True,capture_output=True,text=True)
        raw=(self.work/"response.json").read_text()
        try: body=json.loads(raw)
        except json.JSONDecodeError: body={}
        return int(result.stdout),body

    def route(self,method,data=None):
        return self.curl("/apisix/admin/routes/"+ROUTE_ID,method,data,admin=True)

    def close(self):
        for name in ("admin.header","request.json","response.json"):
            (self.work/name).unlink(missing_ok=True)


def snapshot(admin):
    code,body=admin.route("GET")
    if code not in (200,404):
        raise RuntimeError(f"snapshot HTTP {code}")
    previous=route_value(body) if code==200 else None
    (admin.work/"previous.json").write_text(json.dumps({ROUTE_ID:previous},indent=2)+"\n")
    return previous


def restore(previous,admin):
    code,_=admin.route("PUT" if previous else "DELETE",previous)
    if code not in (200,201,204,404):
        raise RuntimeError(f"rollback HTTP {code}")


def apply(route,admin):
    previous=snapshot(admin)
    try:
        code,_=admin.route("PUT",route)
        if code not in (200,201):
            raise RuntimeError(f"write HTTP {code}")
        code,body=admin.route("GET")
        actual=route_value(body) if code==200 else {}
        if any(actual.get(k)!=v for k,v in route.items()):
            raise RuntimeError("route readback differs")
        code,_=admin.curl(ROUTE_URI)
        if code not in (401,403):
            raise RuntimeError(f"anonymous protected route HTTP {code}")
    except BaseException:
        restore(previous,admin)
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--materialization",type=Path)
    group.add_argument("--restore",type=Path)
    p.add_argument("--admin-key",type=Path,required=True)
    p.add_argument("--container",default="ouf-apisix")
    p.add_argument("--curl-image",default="curlimages/curl:8.16.0")
    p.add_argument("--backup-dir",type=Path,default=Path("/opt/ouf/backup"))
    a=p.parse_args()
    os.umask(0o077)
    admin=Admin(a)
    try:
        if a.restore:
            doc=json.loads(a.restore.read_text())
            if set(doc)!={ROUTE_ID}:
                raise ValueError("snapshot does not contain Authorization bundle route")
            restore(doc[ROUTE_ID],admin)
            print("AUTHORIZATION_BUNDLE_ROUTE_RESTORED")
            return

        doc=json.loads(a.materialization.read_text())
        routes=doc.get("routes")
        if not isinstance(routes,list) or len(routes)!=1:
            raise ValueError("expected one Authorization bundle route")
        route=routes[0]
        if route.get("id")!=ROUTE_ID or route.get("uri")!=ROUTE_URI or route.get("methods")!=["GET"]:
            raise ValueError("unexpected Authorization bundle route")
        guard="\n".join((((route.get("plugins") or {}).get("serverless-post-function") or {}).get("functions") or []))
        for service in ("ouf-mcp-server","ouf-ingestion","ouf-udp","ouf-semantic"):
            if service not in guard:
                raise ValueError("required service identity missing: "+service)
        apply(route,admin)
        print("AUTHORIZATION_BUNDLE_ROUTE_ACTIVE")
    finally:
        admin.close()


if __name__=="__main__":
    main()
