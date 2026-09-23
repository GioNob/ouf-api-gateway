#!/usr/bin/env python3
"""Install or restore only the reviewed UDP search APISIX route with a saved snapshot."""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from ops.apisix.deploy_status_execute import Admin, apply_routes, inherits_env, route_value

ROUTE_ID='execute-urban-object-search'
ROUTE_URI='/internal/capabilities/v1/execute/urban.object.search'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialization',type=Path)
    parser.add_argument('--restore',type=Path)
    parser.add_argument('--admin-key',type=Path,required=True)
    parser.add_argument('--backup-dir',type=Path,default=Path('/opt/ouf/backup'),
                        help='existing persistent, private directory for the route snapshot')
    parser.add_argument('--container',default='ouf-apisix')
    parser.add_argument('--curl-image',default='curlimages/curl:8.16.0')
    args=parser.parse_args()
    os.umask(0o077)
    if bool(args.materialization)==bool(args.restore):parser.error('choose materialization or restore')
    if args.restore:
        previous=json.loads(args.restore.read_text())
        if set(previous)!={ROUTE_ID}:raise SystemExit('invalid UDP search snapshot')
        admin=Admin(args)
        try:
            old=previous[ROUTE_ID]
            code,_=admin('PUT' if old is not None else 'DELETE',ROUTE_ID,old)
            if code not in (200,201,204,404):raise RuntimeError('restore failed')
            code,actual=admin('GET',ROUTE_ID)
            if (old is None and code!=404) or (old is not None and (code!=200 or route_value(actual)!=old)):
                raise RuntimeError('restore readback differs')
        finally:(admin.work/'admin.header').unlink(missing_ok=True)
        return
    doc=json.loads(args.materialization.read_text())
    routes=[r for r in doc['routes'] if r.get('id')==ROUTE_ID]
    if len(routes)!=1 or routes[0].get('uri')!=ROUTE_URI or routes[0].get('methods')!=['POST'] or routes[0]['upstream'].get('nodes')!={'ouf-udp-object-resolution:8080':1} or routes[0]['upstream'].get('retries')!=0:
        raise SystemExit('reviewed UDP search route missing or changed')
    names=[doc.get('delegationKeyEnv',''),doc.get('udpOwnerKeyEnv','')]
    if len(set(names))!=2 or any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',name) for name in names):raise SystemExit('separate named keys required')
    inspected=json.loads(subprocess.run(['docker','inspect',args.container],check=True,capture_output=True,text=True).stdout)[0]
    env=dict(x.split('=',1) for x in inspected['Config']['Env'] if '=' in x)
    nginx=subprocess.run(['docker','exec',args.container,'cat','/usr/local/apisix/conf/nginx.conf'],check=True,capture_output=True,text=True).stdout
    if any(not re.fullmatch(r'[0-9a-fA-F]{64}',env.get(name,'')) or not inherits_env(nginx,name) for name in names):
        raise SystemExit('delegation/UDP owner key missing from APISIX or Nginx inheritance')
    ref=routes[0]['plugins']['openid-connect'].get('client_secret','')
    if not ref.startswith('$ENV://') or not env.get(ref[7:]):raise SystemExit('OIDC environment secret missing')
    admin=Admin(args)
    try:
        apply_routes(routes,admin)
        print('APISIX_UDP_SEARCH_ROUTE_INSTALLED; authenticated smoke test still required')
    finally:(admin.work/'admin.header').unlink(missing_ok=True)


if __name__=='__main__':main()
