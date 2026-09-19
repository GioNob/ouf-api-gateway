"""Real APISIX/OIDC/Lua gate. Opt-in locally; mandatory in GitHub Actions.

Synthetic issuer and owner use HTTP only inside the isolated CI job. Production
materialization keeps HTTPS discovery with certificate verification enabled.
"""
import base64
import copy
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from tools.materialize_apisix_execute_runtime import materialize
from tests.test_execute_delegation import runtime, envelope

pytestmark=pytest.mark.skipif(os.environ.get('OUF_APISIX_LIVE_TEST')!='1',reason='requires Docker APISIX integration gate')

def test_real_apisix_oidc_delegation_and_execute():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='fixture',use='sig',alg='RS256')
    rt=runtime();installation=rt['x-ouf-installation'];issuer=installation['issuerUrl'];aud=installation['gatewayAudience'];workload=installation['mcpServiceIdentity']
    calls=[]
    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/discovery':
                self.reply({'issuer':issuer,'jwks_uri':f'http://127.0.0.1:{server.server_port}/jwks','token_endpoint':issuer+'/token','authorization_endpoint':issuer+'/auth','id_token_signing_alg_values_supported':['RS256']})
            elif self.path=='/jwks': self.reply({'keys':[jwk]})
            else:self.send_error(404)
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length','0')))
            if self.path=='/mcp':
                # Test-only MCP stub returns opaque proof to the test driver.
                assert not self.headers.get('Authorization')
                self.reply({'proof':self.headers.get('X-OUF-Delegation'),'roles':self.headers.get('X-OUF-External-Role-Refs')})
            elif self.path=='/api/internal/v1/mcp/operations/status':
                calls.append((dict(self.headers),body));self.reply({'module':'MCP','status':'HEALTHY','actionRequired':False,'partial':False,'visibilityClass':'PUBLIC_OPERATIONAL','redacted':True})
            else:self.send_error(404)
        def reply(self,value):
            data=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Fixture)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    def token(actor='HUMAN',**updates):
        now=int(time.time());c=dict(iss=issuer,aud=aud,iat=now,exp=now+300,sub='human-a',tenant_id='tenant-a',acr='1',azp='chatgpt',scope='mcp.connect operations.status.read',ouf_actor_type=actor)
        if actor=='SERVICE':c.update(azp=workload,sub='service',scope='authorization.bundle.read')
        c.update(updates);return jwt.encode(c,key,algorithm='RS256',headers={'kid':'fixture'})
    def post(path,body,bearer=None,proof=None):
        headers={'Content-Type':'application/json','X-Correlation-ID':'corr','Idempotency-Key':'idem','X-Tool-Attempt-ID':envelope()['AttemptID'],'X-OUF-External-Role-Refs':'ouf:forged-admin'}
        if bearer:headers['Authorization']='Bearer '+bearer
        if proof:headers['X-OUF-Delegation']=proof
        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=json.dumps(body).encode(),headers=headers)
        try:res=urllib.request.urlopen(req,timeout=5)
        except urllib.error.HTTPError as e:res=e
        with res:return res.status,res.read()
    with tempfile.TemporaryDirectory() as folder:
        os.chmod(folder,0o755)
        doc=materialize(rt,'$ENV://OIDC_SECRET','DELEGATION_KEY')
        for r in doc['routes']:
            oidc=r['plugins'].get('openid-connect')
            if oidc:oidc['discovery']=f'http://127.0.0.1:{server.server_port}/discovery'
            if 'upstream' in r:r['upstream']['nodes']={f'127.0.0.1:{server.server_port}':1}
        config={'apisix':{'node_listen':port,'enable_admin':False},'deployment':{'role':'data_plane','role_data_plane':{'config_provider':'yaml'}},'nginx_config':{'envs':['OIDC_SECRET','DELEGATION_KEY']}}
        Path(folder,'config.yaml').write_text(yaml.safe_dump(config))
        Path(folder,'apisix.yaml').write_text(yaml.safe_dump({'routes':doc['routes']})+'\n#END\n')
        name='ouf-execute-ci-'+str(os.getpid())
        subprocess.run(['docker','run','-d','--name',name,'--network','host','-e','OIDC_SECRET=fixture-only','-e','DELEGATION_KEY='+'ab'*32,'-v',folder+'/config.yaml:/usr/local/apisix/conf/config.yaml:ro','-v',folder+'/apisix.yaml:/usr/local/apisix/conf/apisix.yaml:ro','apache/apisix:3.18.0-debian'],check=True,stdout=subprocess.DEVNULL)
        try:
            for _ in range(60):
                try:
                    code,_=post('/mcp',{},None)
                    if code==401:break
                except (OSError,urllib.error.URLError):pass
                time.sleep(1)
            else:raise AssertionError('APISIX did not load protected routes')
            code,raw=post('/mcp',{},token(externalRoleRefs=['ouf:viewer']),proof='forged')
            assert code==200, (code,raw)
            proof=json.loads(raw)['proof'];assert proof and proof!='forged'
            assert json.loads(raw)['roles']=='ouf:viewer'
            path='/internal/capabilities/v1/execute'
            code,raw=post(path,envelope(),token('SERVICE'),proof)
            assert code==200,(code,raw)
            assert len(calls)==1 and calls[0][1]==b'{}'
            h={k.lower():v for k,v in calls[0][0].items()}
            assert h['x-ouf-principal-id']=='human-a' and h['x-ouf-service-principal']==workload
            assert h['x-ouf-external-role-refs']=='ouf:viewer'
            assert 'authorization' not in h and 'x-ouf-delegation' not in h
            bad=envelope();bad['Identity']['TenantID']='other'
            cases=[(envelope(),None,proof),(envelope(),token('SERVICE')+'broken',proof),(envelope(),token('SERVICE',aud='wrong'),proof),(envelope(),token('SERVICE',azp='other'),proof),(envelope(),token('SERVICE'),proof[:-2]+'zz'),(bad,token('SERVICE'),proof)]
            for body,bearer,p in cases:
                code,raw=post(path,body,bearer,p);assert code in (400,401,403),(code,raw)
            assert len(calls)==1
        except Exception:
            subprocess.run(['docker','logs','--tail','60',name],check=False)
            raise
        finally:
            subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,check=False)
            server.shutdown()
