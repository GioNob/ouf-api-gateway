#!/usr/bin/env python3
"""Install or restore a governed set of internal M2M APISIX routes."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

def route_value(doc):
    value=doc.get("value",doc)
    if isinstance(value,dict) and isinstance(value.get("value"),dict):
        value=value["value"]
    return {k:v for k,v in value.items() if k not in ("create_time","update_time")}

def probe_path(uri):
    if uri.endswith("/*"):
        return uri[:-1]+"probe"
    return uri

def validate_routes(routes):
    if not isinstance(routes,list) or not routes:
        raise ValueError("materialization must contain routes")
    ids=set()
    for route in routes:
        if not isinstance(route,dict):
            raise ValueError("route must be an object")
        route_id=route.get("id")
        if not isinstance(route_id,str) or not re.fullmatch(r"[A-Za-z0-9._-]+",route_id):
            raise ValueError("invalid route id")
        if route_id in ids:
            raise ValueError("duplicate route id")
        ids.add(route_id)
        if (route.get("labels") or {}).get("ouf-managed")!="true" or (route.get("labels") or {}).get("ouf-exposure")!="internal":
            raise ValueError("route is not a governed internal materialization")
        if not isinstance(route.get("uri"),str) or not route["uri"].startswith("/"):
            raise ValueError("invalid route uri")
        if not isinstance(route.get("methods"),list) or len(route["methods"])!=1:
            raise ValueError("route must contain exactly one method")
        plugins=route.get("plugins") or {}
        for required in ("openid-connect","serverless-pre-function","serverless-post-function","request-id","limit-count"):
            if required not in plugins:
                raise ValueError("missing required plugin: "+required)
    return ids

class Admin:
    def __init__(self,args,prefix):
        self.args=args
        args.backup_dir.mkdir(parents=True,exist_ok=True)
        self.work=Path(tempfile.mkdtemp(prefix=prefix,dir=args.backup_dir))
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
            cmd += ["-H","@/work/admin.header"]
        if data is not None:
            (self.work/"request.json").write_text(json.dumps(data))
            cmd += ["-H","Content-Type: application/json","--data-binary","@/work/request.json"]
        cmd += ["http://127.0.0.1:"+("9180" if admin else "9080")+path]
        result=subprocess.run(cmd,check=True,capture_output=True,text=True)
        raw=(self.work/"response.json").read_text()
        try:
            body=json.loads(raw)
        except json.JSONDecodeError:
            body={}
        return int(result.stdout),body

    def route(self,method,route_id,data=None):
        return self.curl("/apisix/admin/routes/"+route_id,method,data,admin=True)

    def close(self):
        for name in ("admin.header","request.json","response.json"):
            (self.work/name).unlink(missing_ok=True)

def snapshot(route_ids,admin):
    previous={}
    for route_id in sorted(route_ids):
        code,body=admin.route("GET",route_id)
        if code not in (200,404):
            raise RuntimeError(f"snapshot HTTP {code} for {route_id}")
        previous[route_id]=route_value(body) if code==200 else None
    (admin.work/"previous.json").write_text(json.dumps(previous,indent=2,sort_keys=True)+"\n")
    return previous

def restore(previous,admin):
    failures=[]
    for route_id in sorted(previous):
        old=previous[route_id]
        try:
            code,_=admin.route("PUT" if old else "DELETE",route_id,old)
            if code not in (200,201,204,404):
                failures.append(route_id)
        except Exception:
            failures.append(route_id)
    if failures:
        raise RuntimeError("rollback incomplete: "+",".join(failures))

def apply(routes,admin):
    ids=validate_routes(routes)
    previous=snapshot(ids,admin)
    try:
        for route in routes:
            route_id=route["id"]
            code,_=admin.route("PUT",route_id,route)
            if code not in (200,201):
                raise RuntimeError(f"write HTTP {code} for {route_id}")
            code,body=admin.route("GET",route_id)
            actual=route_value(body) if code==200 else {}
            if any(actual.get(k)!=v for k,v in route.items()):
                raise RuntimeError("route readback differs for "+route_id)
        for route in routes:
            code,_=admin.curl(probe_path(route["uri"]),route["methods"][0])
            if code not in (401,403):
                raise RuntimeError(f"anonymous protected route HTTP {code} for {route['id']}")
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
    admin=Admin(a,"internal-m2m-routes-")
    try:
        if a.restore:
            previous=json.loads(a.restore.read_text())
            if not isinstance(previous,dict) or not previous:
                raise ValueError("invalid route snapshot")
            for route_id in previous:
                if not re.fullmatch(r"[A-Za-z0-9._-]+",route_id):
                    raise ValueError("invalid route id in snapshot")
            restore(previous,admin)
            print("INTERNAL_M2M_ROUTES_RESTORED")
            return
        doc=json.loads(a.materialization.read_text())
        routes=doc.get("routes")
        validate_routes(routes)
        apply(routes,admin)
        print("INTERNAL_M2M_ROUTES_ACTIVE")
    finally:
        admin.close()

if __name__=="__main__":
    main()
