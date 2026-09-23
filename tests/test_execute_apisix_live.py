"""Real APISIX/OIDC/Lua gate. Opt-in locally; mandatory in GitHub Actions.

Synthetic issuer and owner use HTTP only inside the isolated CI job. Production
materialization keeps HTTPS discovery with certificate verification enabled.
"""
import contextlib
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

from tools.materialize_object_search import materialize
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
            elif self.path in ['/api/internal/v1/mcp/operations/summary','/api/internal/v1/ingestion/operations/summary','/api/internal/v1/gateway/operations/summary']:
                self.reply({'body':json.loads(body),'proof':self.headers.get('X-OUF-Delegation'),'client':self.headers.get('X-OUF-Service-Principal'),'authorization':self.headers.get('Authorization')})
            elif self.path.startswith('/api/internal/v1/authorization/permissions/'):

                self.reply({'receipt':self.headers.get('X-OUF-Authorization-Receipt'),'body':body.decode(),'authorization':self.headers.get('Authorization')})
            elif self.path=='/api/udp/v1/objects/search':
                self.reply({'receipt':self.headers.get('X-OUF-UDP-Search-Receipt'),'body':body.decode(),'authorization':self.headers.get('Authorization'),'delegation':self.headers.get('X-OUF-Delegation')})
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
    with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as owners:
        owner_port=None
        if os.environ.get('OUF_GATEWAY_OWNER_JAR'):
            from tests.summary_java_owner import java_owner
            owner_port,owner_db=owners.enter_context(java_owner(os.environ['OUF_GATEWAY_OWNER_JAR'],folder,installation))
        os.chmod(folder,0o755)
        doc=materialize(rt,'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','UDP_KEY')
        for r in doc['routes']:
            oidc=r['plugins'].get('openid-connect')
            if oidc:oidc['discovery']=f'http://127.0.0.1:{server.server_port}/discovery'
            if 'upstream' in r:r['upstream']['nodes']={f'127.0.0.1:{server.server_port}':1}
            if owner_port and r.get('uri','').endswith('/execute/ouf.gateway.operations.summary'):
                r['upstream']['nodes']={f'127.0.0.1:{owner_port}':1}
        config={'apisix':{'node_listen':port,'enable_admin':False},'deployment':{'role':'data_plane','role_data_plane':{'config_provider':'yaml'}},'nginx_config':{'envs':['OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','UDP_KEY','INGESTION_SUMMARY_RECEIPT_KEY','GATEWAY_SUMMARY_RECEIPT_KEY']}}
        Path(folder,'config.yaml').write_text(yaml.safe_dump(config))
        Path(folder,'apisix.yaml').write_text(yaml.safe_dump({'routes':doc['routes']})+'\n#END\n')
        name='ouf-execute-ci-'+str(os.getpid())
        subprocess.run(['docker','run','-d','--name',name,'--network','host','-e','OIDC_SECRET=fixture-only','-e','DELEGATION_KEY='+'ab'*32,'-e','OWNER_KEY='+'cd'*32,'-e','UDP_KEY='+'34'*32,'-e','INGESTION_SUMMARY_RECEIPT_KEY='+'ef'*32,'-e','GATEWAY_SUMMARY_RECEIPT_KEY='+'12'*32,'-v',folder+'/config.yaml:/usr/local/apisix/conf/config.yaml:ro','-v',folder+'/apisix.yaml:/usr/local/apisix/conf/apisix.yaml:ro','apache/apisix:3.18.0-debian'],check=True,stdout=subprocess.DEVNULL)
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
            from tests.test_summary_execute import summary_envelope
            for cap,owner in [('ouf.operations.summary','mcp'),('ouf.ingestion.operations.summary','ingestion'),('ouf.gateway.operations.summary','gateway')]:
                summary_path='/internal/capabilities/v1/execute/'+cap
                code,raw=post(summary_path,summary_envelope(cap,owner),token('SERVICE'),proof)
                assert code==200,(code,raw)
                observed=json.loads(raw)
                if owner=='gateway' and owner_port:
                    assert observed['module']=='GATEWAY' and observed['status']=='DEGRADED'
                    assert observed['partial'] is False and len(observed['items'])==1
                    assert 'correlation_id' not in observed['items'][0]
                    code,raw=post('/mcp',{},token(externalRoleRefs=[]))
                    assert code==200
                    revoked=json.loads(raw)['proof']
                    code,_=post(summary_path,summary_envelope(cap,owner),token('SERVICE'),revoked)
                    assert code==403  # Same IAM subject after role removal.
                    direct=urllib.request.Request(f'http://127.0.0.1:{owner_port}/api/internal/v1/gateway/operations/summary',data=b'{"limit":5}',headers={'Content-Type':'application/json','X-OUF-Gateway-Verified':'true','X-OUF-Principal-ID':'human-a'})
                    with pytest.raises(urllib.error.HTTPError) as denied:urllib.request.urlopen(direct)
                    assert denied.value.code==403
                    from tools.operational_incidents import SQLiteOperationalIncidentStore
                    with contextlib.closing(SQLiteOperationalIncidentStore(owner_db)) as store:
                        store.open_incident(dedup_key='protected',event_type='SECURITY',severity='ERROR',error_code='HIDDEN',impact_summary='hidden-sensitive-evidence')
                    code,raw=post(summary_path,summary_envelope(cap,owner),token('SERVICE'),proof)
                    hidden=json.loads(raw)
                    assert code==200 and hidden['partial'] is True and hidden['status']=='UNKNOWN'
                    assert 'openIncidents' not in hidden and b'hidden-sensitive-evidence' not in raw
                else:
                    assert observed['client']=='chatgpt' and observed['authorization'] is None
                    assert observed['body']=={'limit':5}
                    assert observed['proof']==(proof if owner=='mcp' else None)
                wrong=summary_envelope(cap,owner);wrong['Owner']='udp'
                code,_=post(summary_path,wrong,token('SERVICE'),proof);assert code in (400,403)

            assert 'authorization' not in h and 'x-ouf-delegation' not in h
            bad=envelope();bad['Identity']['TenantID']='other'
            cases=[(envelope(),None,proof),(envelope(),token('SERVICE')+'broken',proof),(envelope(),token('SERVICE',aud='wrong'),proof),(envelope(),token('SERVICE',azp='other'),proof),(envelope(),token('SERVICE'),proof[:-2]+'zz'),(bad,token('SERVICE'),proof)]
            for body,bearer,p in cases:
                code,raw=post(path,body,bearer,p);assert code in (400,401,403),(code,raw)
            assert len(calls)==1
            from tests.test_permission_proposals import request as permission_request
            cap='authorization.permissions.propose'
            code,raw=post('/mcp',{},token(scope='mcp.connect '+cap,externalRoleRefs=['ente:staff']))
            assert code==200,(code,raw)
            delegated=json.loads(raw)['proof']
            code,raw=post('/internal/capabilities/v1/execute/authorization/propose',permission_request(),token('SERVICE'),delegated)
            assert code==200,(code,raw)
            import hashlib,hmac
            data=json.loads(raw);encoded,signature=data['receipt'].split('.');pad=lambda s:s+'='*((4-len(s)%4)%4)
            assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),hmac.new(('cd'*32).encode(),('ouf-authorization-owner-v1.'+encoded).encode(),hashlib.sha256).digest())
            receipt=json.loads(base64.urlsafe_b64decode(pad(encoded)))
            assert receipt['bodyHash']==hashlib.sha256(data['body'].encode()).hexdigest()
            assert receipt['roles']=='ente:staff' and data['authorization'] is None
            bad=permission_request();bad['Arguments']['confirm']=True
            code,raw=post('/internal/capabilities/v1/execute/authorization/propose',bad,token('SERVICE'),delegated)
            assert code==400,(code,raw)
            code,_=post('/internal/capabilities/v1/execute/authorization/confirm',permission_request(),token('SERVICE'),delegated)
            assert code==404
            # Reproduce the deployed view=GRANTS rejection with actual APISIX,
            # and exercise the same contract for role catalogue proposals.
            from tests.test_permission_role_contract import cases, dispatch, READ
            proofs = {}
            for capability, arguments, allowed in cases():
                if capability not in proofs:
                    code, raw = post('/mcp', {}, token(scope='mcp.connect '+capability))
                    assert code == 200, (code, raw)
                    proofs[capability] = json.loads(raw)['proof']
                mode = 'read' if capability == READ else 'propose'
                body = dispatch(capability, arguments)
                code, raw = post('/internal/capabilities/v1/execute/authorization/'+mode,
                                 body, token('SERVICE'), proofs[capability])
                assert code == (200 if allowed else 400), (arguments, code, raw)
                if allowed:
                    forwarded = json.loads(raw)
                    assert json.loads(forwarded['body'])['Arguments'] == arguments
                    assert forwarded['authorization'] is None
            # The real APISIX OIDC/Lua chain must not deliver the MCP envelope,
            # workload bearer or caller-supplied proof to UDP's fixed endpoint.
            from tests.test_object_search_execute import request as search_request
            search_path='/internal/capabilities/v1/execute/urban.object.search'
            code,raw=post('/mcp',{},token(scope='mcp.connect urban.object.search',externalRoleRefs=['ente:viewer']))
            assert code==200,(code,raw)
            search_proof=json.loads(raw)['proof']
            code,raw=post(search_path,search_request(),token('SERVICE'),search_proof)
            assert code==200,(code,raw)
            forwarded=json.loads(raw)
            assert json.loads(forwarded['body'])=={'type':'ouf:Asset','pageSize':10}
            assert forwarded['authorization'] is None and forwarded['delegation'] is None
            encoded,signature=forwarded['receipt'].split('.')
            assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),hmac.new(('34'*32).encode(),('ouf-udp-search-owner-v1.'+encoded).encode(),hashlib.sha256).digest())
            receipt=json.loads(base64.urlsafe_b64decode(pad(encoded)))
            assert receipt['bodyHash']==hashlib.sha256(forwarded['body'].encode()).hexdigest()
            assert receipt['tenant']=='tenant-a' and receipt['roles']=='ente:viewer' and receipt['client']=='chatgpt'
            for bad_args in ({'type':'*'},{'type':'ouf:Asset','pageSize':101},{'type':'ouf:Asset','sql':'select *'}):
                code,raw=post(search_path,search_request(bad_args),token('SERVICE'),search_proof)
                assert code in (400,403),(code,raw)
            code,raw=post('/mcp',{},token(scope='mcp.connect'))
            assert code==200,(code,raw)
            code,raw=post(search_path,search_request(),token('SERVICE'),json.loads(raw)['proof'])
            assert code==403,(code,raw)
            bad_tenant=search_request();bad_tenant['Identity']['TenantID']='other'
            code,raw=post(search_path,bad_tenant,token('SERVICE'),search_proof)
            assert code in (400,403),(code,raw)
        except Exception:
            subprocess.run(['docker','logs','--tail','60',name],check=False)
            raise
        finally:
            subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,check=False)
            server.shutdown()
