#!/usr/bin/env python3
"""Apply three reviewed APISIX routes, retaining a private rollback snapshot.

No credentials in argv/output. Admin traffic stays in APISIX's network namespace.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def route_value(doc):
    value = doc.get('value', doc)
    if isinstance(value, dict) and isinstance(value.get('value'), dict):
        value = value['value']
    return {k:v for k,v in value.items() if k not in ('create_time','update_time')}


def apply_routes(routes, request):
    """Snapshot before any write; on partial failure restore all attempted IDs."""
    previous = {}
    for route in routes:
        code, value = request('GET', route['id'])
        if code not in (200, 404):
            raise RuntimeError(f'snapshot HTTP {code}')
        previous[route['id']] = route_value(value) if code == 200 else None
    request.save_snapshot(previous)
    attempted = []
    try:
        for route in routes:
            attempted.append(route['id'])
            code, _ = request('PUT', route['id'], route)
            if code not in (200, 201):
                raise RuntimeError(f'write HTTP {code}')
            code, actual = request('GET', route['id'])
            # APISIX can fill defaults; all configured fields must survive unchanged.
            actual = route_value(actual) if code == 200 else {}
            if any(actual.get(k) != v for k,v in route.items()):
                raise RuntimeError('route readback differs')
        request.check_public()
    except BaseException:
        failures = []
        for route_id in reversed(attempted):
            old = previous[route_id]
            try:
                code, _ = request('PUT' if old else 'DELETE', route_id, old)
                if code not in (200,201,204,404): failures.append(route_id)
            except Exception:
                failures.append(route_id)
        if failures:
            raise RuntimeError('rollback incomplete; use saved snapshot for: '+','.join(failures))
        raise


class Admin:
    def __init__(self, args):
        self.args = args
        self.work = Path(tempfile.mkdtemp(prefix='ouf-status-routes-', dir='/run'))
        key = args.admin_key.read_text().strip()
        if not key or '\n' in key or '\r' in key:
            raise ValueError('invalid admin key file')
        (self.work/'admin.header').write_text('X-API-KEY: '+key+'\n')
        os.chmod(self.work/'admin.header',0o600)
        print('BACKUP='+str(self.work/'previous.json'),flush=True)

    def curl(self, path, method='GET', data=None, admin=False):
        cmd=['docker','run','--rm','--user','0:0','--network','container:'+self.args.container,
             '-v',str(self.work)+':/work',self.args.curl_image,'--max-time','15','-sS',
             '-o','/work/response.json','-w','%{http_code}','-X',method]
        if admin: cmd += ['-H','@/work/admin.header']
        if data is not None:
            (self.work/'request.json').write_text(json.dumps(data))
            cmd += ['-H','Content-Type: application/json','--data-binary','@/work/request.json']
        cmd += ['http://127.0.0.1:'+('9180' if admin else '9080')+path]
        result=subprocess.run(cmd,check=True,capture_output=True,text=True)
        raw=(self.work/'response.json').read_text()
        try: value=json.loads(raw)
        except json.JSONDecodeError: value={}
        return int(result.stdout),value

    def __call__(self, method, route_id, data=None):
        return self.curl('/apisix/admin/routes/'+route_id,method,data,admin=True)

    def save_snapshot(self, value):
        (self.work/'previous.json').write_text(json.dumps(value,indent=2)+'\n')

    def check_public(self):
        code,_=self.curl('/mcp','POST',{})
        if code!=401: raise RuntimeError(f'unauthenticated MCP HTTP {code}')
        code,_=self.curl('/.well-known/oauth-protected-resource')
        if code!=200: raise RuntimeError(f'metadata HTTP {code}')
        # A schema-valid execute probe is needed to reach OIDC before Lua.
        probe=dict(GatewayBindingRef='capability://ouf.system.status',CapabilityID='ouf.system.status',Owner='mcp',OperationClass='READ',Arguments={},Identity=dict(ServicePrincipalID='probe',PrincipalID='probe',TenantID='probe',ActorType='HUMAN',AuthenticationContextRef='1'),AuthorizationDecisionRef='probe',CorrelationID='probe',IdempotencyKey='probe',AttemptID='11111111-1111-4111-8111-111111111111',RequestHash='44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',MaxResultBytes=262144)
        code,_=self.curl('/internal/capabilities/v1/execute','POST',probe)
        if code!=401: raise RuntimeError(f'unauthenticated execute HTTP {code}')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialization',type=Path)
    parser.add_argument('--restore',type=Path,help='restore an existing previous.json snapshot')
    parser.add_argument('--admin-key',type=Path,required=True)
    parser.add_argument('--container',default='ouf-apisix')
    parser.add_argument('--curl-image',default='curlimages/curl:8.16.0')
    args=parser.parse_args()
    os.umask(0o077)
    if bool(args.materialization)==bool(args.restore):
        parser.error('choose exactly one of --materialization or --restore')
    if args.restore:
        previous=json.loads(args.restore.read_text())
        if not isinstance(previous,dict) or len(previous)!=3 or any(not re.fullmatch(r'[A-Za-z0-9_-]+',str(k)) for k in previous):
            raise SystemExit('invalid snapshot')
        admin=Admin(args)
        try:
            for route_id,old in previous.items():
                code,_=admin('PUT' if old else 'DELETE',route_id,old)
                if code not in (200,201,204,404):raise RuntimeError('restore failed')
                code,actual=admin('GET',route_id)
                if (old is None and code!=404) or (old is not None and (code!=200 or route_value(actual)!=old)):
                    raise RuntimeError('restore readback differs')
            print('APISIX_PREVIOUS_ROUTES_RESTORED')
        finally:
            (admin.work/'admin.header').unlink(missing_ok=True)
        return
    doc=json.loads(args.materialization.read_text())
    routes=doc['routes']
    expected={'/mcp':['POST'],'/.well-known/oauth-protected-resource':['GET'],'/internal/capabilities/v1/execute':['POST']}
    if len(routes)!=3 or {r['uri']:r['methods'] for r in routes}!=expected:
        raise SystemExit('expected the three reviewed status profile routes')
    if any(not re.fullmatch(r'[A-Za-z0-9_-]+',str(r['id'])) for r in routes):
        raise SystemExit('invalid route id')
    env_name=doc.get('delegationKeyEnv','')
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',env_name):
        raise SystemExit('invalid delegation environment name')
    # Capture inspect internally; never display environment/credentials.
    inspected=json.loads(subprocess.run(['docker','inspect',args.container],check=True,capture_output=True,text=True).stdout)[0]
    env=dict(x.split('=',1) for x in inspected['Config']['Env'] if '=' in x)
    if not re.fullmatch(r'[0-9a-fA-F]{64}',env.get(env_name,'')):
        raise SystemExit('delegation key absent or invalid in APISIX container')
    for route in routes:
        oidc=route['plugins'].get('openid-connect')
        if oidc:
            ref=oidc.get('client_secret','')
            if not ref.startswith('$ENV://') or not env.get(ref[7:]):
                raise SystemExit('OIDC environment secret missing')
    # Nginx workers need an explicit env directive; container env alone is insufficient.
    nginx=subprocess.run(['docker','exec',args.container,'cat','/usr/local/apisix/conf/nginx.conf'],check=True,capture_output=True,text=True).stdout
    if not re.search(r'^\s*env\s+'+re.escape(env_name)+r'\s*;',nginx,re.M):
        raise SystemExit('delegation key not inherited by Nginx workers; configure nginx_config.envs and restart first')
    admin=Admin(args)
    try:
        apply_routes(routes,admin)
        print('APISIX_STATUS_ROUTES_INSTALLED; authenticated smoke test still required')
    finally:
        (admin.work/'admin.header').unlink(missing_ok=True)


if __name__=='__main__': main()
