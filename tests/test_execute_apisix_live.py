"""Real APISIX/OIDC/Lua gate. Opt-in locally; mandatory in GitHub Actions.

Synthetic issuer and owner use HTTP only inside the isolated CI job. Production
materialization keeps HTTPS discovery with certificate verification enabled.
"""
import base64
import copy
import contextlib
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
            elif self.path in ('/api/internal/v1/ingestion/operations/status', '/api/internal/v1/ingestion/operations/history', '/api/internal/v1/mcp/operations/summary', '/api/internal/v1/mcp/operations/incidents',
                               '/api/internal/v1/ingestion/operations/summary', '/api/internal/v1/ingestion/operations/incidents',
                               '/api/internal/v1/gateway/operations/summary', '/api/internal/v1/gateway/operations/incidents'):
                self.reply({'headers': {k.lower():v for k,v in self.headers.items()}, 'body': json.loads(body)})
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
        udp_port=None
        if os.environ.get('OUF_UDP_JAR'):
            import hashlib
            from datetime import datetime, timedelta, timezone
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));udp_port=sock.getsockname()[1]
            now=datetime.now(timezone.utc)
            admitted={'grantId':'search-admission','capabilityId':'urban.object.search','tenantId':'tenant-a','subjectId':'human-a',
                'servicePrincipalId':None,'organizationId':None,'validFrom':(now-timedelta(minutes=1)).isoformat(),
                'validUntil':(now+timedelta(hours=1)).isoformat(),'constraints':{'resourceType':'capability'}}
            object_grants=[dict(admitted,grantId=f'search-object-{n}',constraints={'resourceType':'object','resourceId':f'00000000-0000-4000-8000-{n:012d}'}) for n in (11,22)]
            bundle={'bundleId':'udp-search-ci','version':1,'publishedAt':now.isoformat(),
                'capabilities':[{'capabilityId':'urban.object.search','operation':'SEARCH','requiredScope':'urban.object.search','allowedActors':['HUMAN']}],
                'grants':[admitted,*object_grants]}
            raw_bundle=json.dumps(bundle,separators=(',',':')).encode()
            Path(folder,'udp-bundle.json').write_bytes(raw_bundle)
            Path(folder,'udp-owner.key').write_text('34'*32)
            udp_env=dict(os.environ,PORT=str(udp_port),OUF_UDP_LAKE_REQUIRED='false',
                OUF_UDP_SEARCH_TENANT_ID='tenant-a',OUF_UDP_SEARCH_ISSUER=issuer,
                OUF_UDP_SEARCH_AUDIENCE=aud,OUF_UDP_SEARCH_WORKLOAD=workload,
                OUF_UDP_SEARCH_OWNER_KEY_FILE=str(Path(folder,'udp-owner.key')),
                OUF_AUTHORIZATION_BUNDLE_FILE=str(Path(folder,'udp-bundle.json')),
                OUF_AUTHORIZATION_BUNDLE_ID='udp-search-ci',OUF_AUTHORIZATION_BUNDLE_VERSION='1',
                OUF_AUTHORIZATION_BUNDLE_SHA256=hashlib.sha256(raw_bundle).hexdigest())
            udp_log=open(Path(folder,'udp-server.log'),'wb')
            owners.callback(udp_log.close)
            udp=subprocess.Popen(['java','-jar',os.environ['OUF_UDP_JAR']],env=udp_env,stdout=udp_log,stderr=subprocess.STDOUT)
            def stop_udp():
                if udp.poll() is None:
                    udp.terminate()
                    try:udp.wait(timeout=8)
                    except subprocess.TimeoutExpired:udp.kill();udp.wait(timeout=8)
            owners.callback(stop_udp)
            for _ in range(90):
                if udp.poll() is not None:raise AssertionError('UDP terminated on startup: '+Path(folder,'udp-server.log').read_text()[-4000:])
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{udp_port}/actuator/health',timeout=2) as response:
                        if response.status==200:break
                except (OSError,urllib.error.URLError):pass
                time.sleep(1)
            else:raise AssertionError('UDP not ready: '+Path(folder,'udp-server.log').read_text()[-4000:])
            # Fixed SQL fixture is loaded only in the disposable CI PostgreSQL.
            rows=[]
            for n,tenant in [(11,'tenant-a'),(22,'tenant-a'),(33,'tenant-a'),(44,'tenant-b')]:
                rows.append(f"('00000000-0000-4000-8000-{n:012d}','ouf:Asset','ci-{n}','{tenant}')")
            sql='insert into ouf_udp.urban_object(urban_object_id,canonical_type,canonical_key,tenant_id) values '+','.join(rows)
            subprocess.run(['docker','run','--rm','--network','host','-e','PGPASSWORD='+udp_env['OUF_UDP_DB_PASSWORD'],
                'postgres:17-alpine','psql','-h','127.0.0.1','-U',udp_env['OUF_UDP_DB_USER'],'-d','ouf_udp','-v','ON_ERROR_STOP=1','-c',sql],check=True,stdout=subprocess.DEVNULL)
        os.chmod(folder,0o755)
        doc=materialize(rt,'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','UDP_KEY')
        from tools.materialize_ingestion_read import materialize as ingestion_reads
        doc=ingestion_reads(doc,rt,'DELEGATION_KEY')
        for r in doc['routes']:
            oidc=r['plugins'].get('openid-connect')
            if oidc:oidc['discovery']=f'http://127.0.0.1:{server.server_port}/discovery'
            if 'upstream' in r:r['upstream']['nodes']={f'127.0.0.1:{server.server_port}':1}
            if udp_port and r.get('uri','').endswith('/execute/urban.object.search'):
                r['upstream']['nodes']={f'127.0.0.1:{udp_port}':1}
        config={'apisix':{'node_listen':port,'enable_admin':False},'deployment':{'role':'data_plane','role_data_plane':{'config_provider':'yaml'}},'nginx_config':{'envs':['OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','UDP_KEY']}}
        Path(folder,'config.yaml').write_text(yaml.safe_dump(config))
        Path(folder,'apisix.yaml').write_text(yaml.safe_dump({'routes':doc['routes']})+'\n#END\n')
        name='ouf-execute-ci-'+str(os.getpid())
        subprocess.run(['docker','run','-d','--name',name,'--network','host','-e','OIDC_SECRET=fixture-only','-e','DELEGATION_KEY='+'ab'*32,'-e','OWNER_KEY='+'cd'*32,'-e','UDP_KEY='+'34'*32,'-v',folder+'/config.yaml:/usr/local/apisix/conf/config.yaml:ro','-v',folder+'/apisix.yaml:/usr/local/apisix/conf/apisix.yaml:ro','apache/apisix:3.18.0-debian'],check=True,stdout=subprocess.DEVNULL)
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
            # Exact two missing Ingestion READ bindings through real APISIX/OIDC.
            code, raw = post('/mcp', {}, token(scope='mcp.connect ingestion.operations.read'))
            assert code == 200, (code, raw)
            ingestion_proof = json.loads(raw)['proof']
            for mode in ('status', 'history'):
                capability = 'ouf.ingestion.' + mode
                body = envelope()
                body.update(CapabilityID=capability, GatewayBindingRef='capability://'+capability,
                            Owner='ingestion', Arguments={'sourceId':'source-a','limit':7})
                read_path = '/internal/capabilities/v1/execute/' + capability
                code, raw = post(read_path, body, token('SERVICE'), ingestion_proof)
                assert code == 200, (code, raw)
                forwarded = json.loads(raw)
                assert forwarded['body'] == body['Arguments']
                assert forwarded['headers']['x-ouf-capability-id'] == capability
                assert forwarded['headers']['x-ouf-principal-id'] == 'human-a'
                assert forwarded['headers']['x-ouf-service-principal'] == workload
                assert 'ingestion.operations.read' in forwarded['headers']['x-ouf-granted-scopes'].split()
                assert not any(k in forwarded['headers'] for k in ('authorization','cookie','x-ouf-delegation'))
                bad = copy.deepcopy(body); bad['Identity']['TenantID'] = 'other'
                invalid = copy.deepcopy(body); invalid['Arguments']['url'] = 'https://attacker.invalid'
                for request, bearer, delegated in [
                    (body,None,ingestion_proof),(body,token('SERVICE')+'broken',ingestion_proof),
                    (body,token('SERVICE',azp='other'),ingestion_proof),
                    (body,token('SERVICE'),ingestion_proof[:-2]+'zz'),
                    (bad,token('SERVICE'),ingestion_proof),(body,token('SERVICE'),proof),
                    (invalid,token('SERVICE'),ingestion_proof)]:
                    code, raw = post(read_path, request, bearer, delegated)
                    assert code in (400,401,403), (code,raw)
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
            # Six fixed operational routes: retained context only to aggregate
            # MCP, then a second governed workload hop to a producer.
            from tools.materialize_operational_execute import CAPABILITIES
            code, raw = post('/mcp', {}, token(scope='mcp.connect operations.status.read operations.incident.read', externalRoleRefs=['ouf:viewer']))
            assert code == 200, (code, raw)
            operational_proof = json.loads(raw)['proof']
            for capability, (owner, _, _, _, _, _) in CAPABILITIES.items():
                body = envelope()
                body.update(CapabilityID=capability, GatewayBindingRef='capability://'+capability,
                            Owner=owner, Arguments={'limit':3}, MaxResultBytes=524288,
                            AuthorizationDecisionRef='bundle:6:'+capability)
                body['RequestHash'] = hashlib.sha256(b'{"limit":3}').hexdigest()
                # Nested calls preserve HUMAN subject/tenant/roles while using
                # a separately verified current MCP workload bearer.
                body['Identity']['ServicePrincipalID'] = workload
                route = '/internal/capabilities/v1/execute/'+capability
                code, raw = post(route, body, token('SERVICE'), operational_proof)
                assert code == 200, (capability, code, raw)
                projection = json.loads(raw)
                h = projection['headers']
                assert projection['body'] == {'limit':3}
                assert h['x-ouf-principal-id'] == 'human-a' and h['x-ouf-service-principal'] == workload
                assert h['x-ouf-external-role-refs'] == 'ouf:viewer' and 'authorization' not in h
                if owner == 'mcp':
                    assert h['x-ouf-delegation'] == operational_proof
                    assert h['x-ouf-delegation-verified'] == 'mcp-operational-aggregate-v1'
                else:
                    assert 'x-ouf-delegation' not in h and 'x-ouf-delegation-verified' not in h
                changed = copy.deepcopy(body); changed['Identity']['PrincipalID'] = 'forged'
                code, raw = post(route, changed, token('SERVICE'), operational_proof)
                assert code == 403, (capability, code, raw)
                changed = copy.deepcopy(body); changed['Arguments']['arbitrary'] = 'secret'
                code, raw = post(route, changed, token('SERVICE'), operational_proof)
                assert code == 400, (capability, code, raw)
            # Global incident snapshot/continuation has a closed opt-in contract.
            capability = 'ouf.operations.incidents'
            route = '/internal/capabilities/v1/execute/'+capability
            cursor = '11111111-1111-4111-8111-111111111111'
            for arguments, allowed in [
                ({'snapshot':True,'limit':1,'sourceId':'source-a','state':'OPEN'},True),
                ({'cursor':cursor},True),
                ({'snapshot':False},False),
                ({'snapshot':None},False),
                ({'cursor':cursor,'limit':1},False),
                ({'cursor':cursor,'sourceId':'source-a'},False),
                ({'snapshot':True,'cursor':cursor},False),
                ({'cursor':'00000000-0000-0000-0000-000000000000'},False),
                ({'cursor':'11111111-AAAA-4111-8111-111111111111'},False),
            ]:
                body = envelope()
                body.update(CapabilityID=capability,GatewayBindingRef='capability://'+capability,
                            Owner='mcp',Arguments=arguments,MaxResultBytes=524288,
                            AuthorizationDecisionRef='bundle:6:'+capability)
                body['RequestHash'] = hashlib.sha256(json.dumps(arguments,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                body['Identity']['ServicePrincipalID'] = workload
                code, raw = post(route,body,token('SERVICE'),operational_proof)
                assert code == (200 if allowed else 400),(arguments,code,raw)
                if allowed:
                    result = json.loads(raw)
                    assert result['body'] == arguments
                    assert result['headers']['x-ouf-delegation'] == operational_proof
                    assert result['headers']['x-ouf-delegation-verified'] == 'mcp-operational-aggregate-v1'
                    assert 'authorization' not in result['headers']
            # Owner publication coverage is a hidden READ mode, never a global vector.
            for capability in ['ouf.gateway.operations.incidents','ouf.ingestion.operations.incidents','ouf.operations.incidents']:
                owner = CAPABILITIES[capability][0]
                route = '/internal/capabilities/v1/execute/'+capability
                for arguments, structurally_valid in [
                    ({'snapshot':True,'coverage':True,'limit':1},True),
                    ({'cursor':cursor,'coverage':True},True),
                    ({'resumeFrom':cursor,'limit':1},True),
                    ({'resumeFrom':cursor,'state':'OPEN'},False),
                    ({'snapshot':True,'coverage':True,'since':'2026-10-11T00:00:00Z'},False),
                    ({'coverage':True},False),
                    ({'resumeFrom':'00000000-0000-0000-0000-000000000000'},False),
                ]:
                    body = envelope()
                    body.update(CapabilityID=capability,GatewayBindingRef='capability://'+capability,
                                Owner=owner,Arguments=arguments,MaxResultBytes=524288,
                                AuthorizationDecisionRef='bundle:6:'+capability)
                    body['RequestHash'] = hashlib.sha256(json.dumps(arguments,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                    body['Identity']['ServicePrincipalID'] = workload
                    code, raw = post(route,body,token('SERVICE'),operational_proof)
                    allowed = structurally_valid
                    assert code == (200 if allowed else 400),(capability,arguments,code,raw)
                    if allowed:
                        result = json.loads(raw)
                        assert result['body'] == arguments
                        if owner == 'mcp':
                            assert result['headers']['x-ouf-delegation'] == operational_proof
                            assert result['headers']['x-ouf-delegation-verified'] == 'mcp-operational-aggregate-v1'
                        else:
                            assert 'x-ouf-delegation' not in result['headers']
                        assert 'authorization' not in result['headers']
            code, _ = post('/internal/capabilities/v1/execute/ouf.operations.arbitrary', envelope(), token('SERVICE'), operational_proof)
            assert code == 404
            # The real APISIX OIDC/Lua chain must not deliver the MCP envelope,
            # workload bearer or caller-supplied proof to UDP's fixed endpoint.
            from tests.test_object_search_execute import request as search_request
            search_path='/internal/capabilities/v1/execute/urban.object.search'
            code,raw=post('/mcp',{},token(scope='mcp.connect urban.object.search',externalRoleRefs=['ente:viewer']))
            assert code==200,(code,raw)
            search_proof=json.loads(raw)['proof']
            search_args={'type':'ouf:Asset','pageSize':1} if udp_port else None
            code,raw=post(search_path,search_request(search_args),token('SERVICE'),search_proof)
            assert code==200,(code,raw)
            if udp_port:
                result=json.loads(raw)
                assert len(result['items'])==1 and result['items'][0]['urbanObjectId']=='00000000-0000-4000-8000-000000000011'
                assert result['nextCursor'] and result['partial'] is False
                code,raw=post(search_path,search_request({'type':'ouf:Asset','pageSize':1,'cursor':result['nextCursor']}),token('SERVICE'),search_proof)
                assert code==200,(code,raw)
                result=json.loads(raw)
                assert len(result['items'])==1 and result['items'][0]['urbanObjectId']=='00000000-0000-4000-8000-000000000022'
                assert result['nextCursor'] and result['partial'] is False
                code,raw=post(search_path,search_request({'type':'ouf:Asset','pageSize':1,'cursor':result['nextCursor']}),token('SERVICE'),search_proof)
                assert code==200,(code,raw)
                result=json.loads(raw)
                assert result['items']==[] and result['nextCursor'] is None and result['partial'] is True
                assert '000000000033' not in raw.decode() and '000000000044' not in raw.decode()
                direct=urllib.request.Request(f'http://127.0.0.1:{udp_port}/api/udp/v1/objects/search',data=b'{"type":"ouf:Asset"}',headers={'Content-Type':'application/json'})
                with pytest.raises(urllib.error.HTTPError) as denied:urllib.request.urlopen(direct)
                assert denied.value.code==403
            else:
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
