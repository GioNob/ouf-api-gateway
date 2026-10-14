#!/usr/bin/env python3
"""Install/restore governed Trusted Human Onboarding lifecycle routes in APISIX."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROUTE_IDS={
    "trusted-human-onboarding-sources-get",
    "trusted-human-onboarding-sources-post",
    "trusted-human-onboarding-lifecycle-get",
    "trusted-human-onboarding-lifecycle-post",
    "trusted-human-onboarding-lifecycle-put",
    "trusted-human-onboarding-approvals-get",
    "trusted-human-onboarding-approvals-post",
    "trusted-human-managed-file-upload",
    "trusted-human-managed-file-actions-post",
    "trusted-human-managed-file-preview-get",
}

def route_value(doc):
    value=doc.get("value",doc)
    if isinstance(value,dict) and isinstance(value.get("value"),dict):
        value=value["value"]
    return {k:v for k,v in value.items() if k not in ("create_time","update_time")}

class Admin:
    def __init__(self,args):
        self.args=args
        args.backup_dir.mkdir(parents=True,exist_ok=True)
        self.work=Path(tempfile.mkdtemp(prefix="trusted-human-onboarding-",dir=args.backup_dir))
        key=args.admin_key.read_text().strip()
        if not key or "\n" in key or "\r" in key:
            raise ValueError("invalid APISIX admin key")
        (self.work/"admin.header").write_text("X-API-KEY: "+key+"\n")
        os.chmod(self.work/"admin.header",0o600)
        print("BACKUP="+str(self.work/"previous.json"),flush=True)

    def curl(self,path,method="GET",data=None,admin=False):
        cmd=["docker","run","--rm","--user","0:0",
             "--network","container:"+self.args.container,
             "-v",str(self.work)+":/work",self.args.curl_image,
             "--max-time","15","-sS","-o","/work/response.json","-w","%{http_code}","-X",method]
        if admin:
            cmd+=["-H","@/work/admin.header"]
        if data is not None:
            (self.work/"request.json").write_text(json.dumps(data))
            cmd+=["-H","Content-Type: application/json","--data-binary","@/work/request.json"]
        cmd+=["http://127.0.0.1:"+("9180" if admin else "9080")+path]
        result=subprocess.run(cmd,check=True,capture_output=True,text=True)
        raw=(self.work/"response.json").read_text()
        try: body=json.loads(raw)
        except json.JSONDecodeError: body={}
        return int(result.stdout),body

    def route(self,method,route_id,data=None):
        return self.curl("/apisix/admin/routes/"+route_id,method,data,admin=True)

    def close(self):
        for name in ("admin.header","request.json","response.json"):
            (self.work/name).unlink(missing_ok=True)

def snapshot(admin):
    previous={}
    for route_id in sorted(ROUTE_IDS):
        code,body=admin.route("GET",route_id)
        if code not in (200,404):
            raise RuntimeError(f"snapshot HTTP {code} for {route_id}")
        previous[route_id]=route_value(body) if code==200 else None
    (admin.work/"previous.json").write_text(json.dumps(previous,indent=2)+"\n")
    return previous

def restore(previous,admin):
    failures=[]
    for route_id in sorted(ROUTE_IDS):
        old=previous.get(route_id)
        try:
            code,_=admin.route("PUT" if old else "DELETE",route_id,old)
            if code not in (200,201,204,404):
                failures.append(route_id)
        except Exception:
            failures.append(route_id)
    if failures:
        raise RuntimeError("rollback incomplete: "+",".join(failures))

def apply(routes,admin):
    upload=next((r for r in routes if r.get("id")=="trusted-human-managed-file-upload"),None)
    if upload is None or upload.get("plugins",{}).get("proxy-control")!={"request_buffering":False}:
        raise ValueError("managed-file upload requires APISIX-Runtime request streaming; verify the runtime before materializing")
    code,_=admin.curl("/apisix/admin/plugins/proxy-control?subsystem=http",admin=True)
    if code!=200:
        raise RuntimeError("APISIX proxy-control plugin schema is unavailable; upload route not installed")
    previous=snapshot(admin)
    try:
        for route in routes:
            code,_=admin.route("PUT",route["id"],route)
            if code not in (200,201):
                raise RuntimeError(f"write HTTP {code}")
            code,body=admin.route("GET",route["id"])
            actual=route_value(body) if code==200 else {}
            if any(actual.get(k)!=v for k,v in route.items()):
                raise RuntimeError("route readback differs")
        probes=[
            ("GET","/api/onboarding/v1/sources"),
            ("POST","/api/onboarding/v1/sources"),
            ("GET","/api/trusted-human/v1/approval-challenges/00000000-0000-0000-0000-000000000000"),
            ("POST","/api/managed-sources/v1/files"),
            ("POST","/api/onboarding/v1/managed-files/00000000-0000-0000-0000-000000000000/profile"),
            ("GET","/api/onboarding/v1/managed-files/00000000-0000-0000-0000-000000000000"),
        ]
        for method,path in probes:
            code,_=admin.curl(path,method)
            if code not in (401,403):
                raise RuntimeError(f"anonymous protected lifecycle HTTP {code} for {method} {path}")
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
            previous=json.loads(a.restore.read_text())
            if set(previous)!=ROUTE_IDS:
                raise ValueError("snapshot does not contain full onboarding lifecycle route set")
            restore(previous,admin)
            print("TRUSTED_HUMAN_ONBOARDING_ROUTES_RESTORED")
            return
        doc=json.loads(a.materialization.read_text())
        routes=doc.get("routes")
        if not isinstance(routes,list) or {r.get("id") for r in routes}!=ROUTE_IDS:
            raise ValueError("unexpected onboarding lifecycle route set")
        apply(routes,admin)
        print("TRUSTED_HUMAN_ONBOARDING_NAMESPACE_INSTALLED")
    finally:
        admin.close()

if __name__=="__main__":
    main()
