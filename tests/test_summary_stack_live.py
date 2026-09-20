"""Real MCP + APISIX + both Java producers. Synthetic IAM/policy, real PostgreSQL/SQLite."""
import base64
import contextlib
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from tests.test_execute_delegation import runtime
from tests.summary_java_owner import java_owner
from tools.materialize_summary import materialize

pytestmark=pytest.mark.skipif(os.environ.get('OUF_SUMMARY_STACK_TEST')!='1',reason='requires complete summary stack')

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

@contextlib.contextmanager
def process(args,log,port,env=None):
    with log.open('wb') as output:
        proc=subprocess.Popen(args,stdout=output,stderr=subprocess.STDOUT,env=env)
        try:
            for _ in range(120):
                if proc.poll() is not None:raise AssertionError(log.read_text()[-8000:])
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.5):break
                except OSError:time.sleep(.5)
            else:raise AssertionError(log.read_text()[-8000:])
            yield proc
        finally:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()

def test_summary_through_real_stack(tmp_path):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='fixture',use='sig',alg='RS256')
    rt=runtime();installation=rt['x-ouf-installation'];issuer=installation['issuerUrl'];aud=installation['gatewayAudience'];workload=installation['mcpServiceIdentity']
    api_port,mcp_port,ing_port=free_port(),free_port(),free_port()
    def token(roles=None,service=False):
        now=int(time.time());claims=dict(iss=issuer,aud=aud,sub='human-a',tenant_id='tenant-a',acr='1',azp='chatgpt',iat=now,exp=now+600,scope='mcp.connect operations.status.read',ouf_actor_type='HUMAN',externalRoleRefs=roles or [])
        if service:claims.update(sub='workload',azp=workload,ouf_actor_type='SERVICE',scope='authorization.bundle.read')
        return jwt.encode(claims,key,algorithm='RS256',headers={'kid':'fixture'})
    now=datetime.now(timezone.utc);caps=['ouf.operations.summary','ouf.gateway.operations.summary','ouf.ingestion.operations.summary','operations.status.read']
    bundle={'bundleId':'bundle','version':6,'publishedAt':now.isoformat(),'capabilities':[],'grants':[]}
    for cap in caps:
        bundle['capabilities'].append(dict(capabilityId=cap,operation='READ',requiredScope='operations.status.read',allowedActors=['HUMAN']))
        bundle['grants'].append(dict(grantId=cap,capabilityId=cap,tenantId='tenant-a',validFrom=(now-timedelta(minutes=1)).isoformat(),validUntil=(now+timedelta(hours=1)).isoformat(),constraints=dict(externalRoleRef='ouf:viewer',resourceType='operational' if cap=='operations.status.read' else 'capability',allowedDetailLevels=['TENANT_OPERATIONAL'])))
    raw=json.dumps(bundle,separators=(',',':')).encode();digest=hashlib.sha256(raw).hexdigest()
    active=dict(bundleId='bundle',bundleVersion=6,activatedAt=now.isoformat(),contentHash=digest,bundle=bundle)
    class Issuer(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/discovery':value=dict(issuer=issuer,jwks_uri=f'http://127.0.0.1:{server.server_port}/jwks',token_endpoint=issuer+'/token',authorization_endpoint=issuer+'/auth',id_token_signing_alg_values_supported=['RS256'])
            elif self.path=='/jwks':value={'keys':[jwk]}
            elif self.path=='/active' and self.headers.get('Authorization')=='Bearer '+workload_token:value=active
            else:self.send_error(403);return
            body=json.dumps(value,separators=(',',':')).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    workload_token=token(service=True)
    server=ThreadingHTTPServer(('127.0.0.1',0),Issuer);threading.Thread(target=server.serve_forever,daemon=True).start()
    name='ouf-summary-stack-'+str(os.getpid())
    try:
        with contextlib.ExitStack() as stack:
            owner_port,_=stack.enter_context(java_owner(os.environ['OUF_GATEWAY_OWNER_JAR'],tmp_path,installation,bundle))
            ing_key=tmp_path/'ingestion.key';ing_key.write_text('ef'*32);ing_key.chmod(0o600)
            ing_args=['java','-jar',os.environ['OUF_INGESTION_JAR'],f'--server.port={ing_port}',f'--spring.datasource.url={os.environ["SUMMARY_JDBC_URL"]}',
                      '--spring.datasource.username=summary','--spring.datasource.password=summary-ci-only',
                      f'--ouf.summary.receipt-key-file={ing_key}','--ouf.summary.tenant-id=tenant-a',f'--ouf.summary.issuer={issuer}',f'--ouf.summary.audience={aud}',f'--ouf.summary.workload={workload}',
                      f'--ouf.authorization.bundle-file={tmp_path / "policy.json"}','--ouf.authorization.bundle-id=bundle','--ouf.authorization.bundle-version=6',f'--ouf.authorization.bundle-sha256={digest}']
            stack.enter_context(process(ing_args,tmp_path/'ingestion.log',ing_port))
            env=dict(os.environ,MCP_DATABASE_URL=os.environ['SUMMARY_PG_URL'],MCP_WORKLOAD_TOKEN=workload_token,MCP_FINGERPRINT_KEY='ci-only-fingerprint-key-material-32-bytes',MCP_AUTHORIZATION_BUNDLE_ENDPOINT=f'http://127.0.0.1:{server.server_port}/active',MCP_GATEWAY_ENDPOINT=f'http://127.0.0.1:{api_port}/internal/capabilities/v1/execute')
            subprocess.run([os.environ['OUF_MCP_BINARY'],'migrate'],env=env,check=True,capture_output=True,timeout=30)
            stack.enter_context(process([os.environ['OUF_MCP_BINARY'],'server','--http',f'127.0.0.1:{mcp_port}'],tmp_path/'mcp.log',mcp_port,env))
            doc=materialize(rt,'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY')
            for route in doc['routes']:
                if 'openid-connect' in route['plugins']:route['plugins']['openid-connect']['discovery']=f'http://127.0.0.1:{server.server_port}/discovery'
                if 'upstream' in route:
                    uri=route.get('uri','')
                    port=ing_port if uri.endswith('/execute/ouf.ingestion.operations.summary') else owner_port if uri.endswith('/execute/ouf.gateway.operations.summary') else mcp_port
                    route['upstream']['nodes']={f'127.0.0.1:{port}':1}
            config={'apisix':{'node_listen':api_port,'enable_admin':False},'deployment':{'role':'data_plane','role_data_plane':{'config_provider':'yaml'}},'nginx_config':{'envs':['OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','INGESTION_SUMMARY_RECEIPT_KEY','GATEWAY_SUMMARY_RECEIPT_KEY']}}
            os.chmod(tmp_path,0o755);(tmp_path/'config.yaml').write_text(yaml.safe_dump(config));(tmp_path/'apisix.yaml').write_text(yaml.safe_dump({'routes':doc['routes']})+'\n#END\n')
            subprocess.run(['docker','run','-d','--name',name,'--network','host','-e','OIDC_SECRET=fixture-only','-e','DELEGATION_KEY='+'ab'*32,'-e','OWNER_KEY='+'cd'*32,'-e','INGESTION_SUMMARY_RECEIPT_KEY='+'ef'*32,'-e','GATEWAY_SUMMARY_RECEIPT_KEY='+'12'*32,'-v',str(tmp_path/'config.yaml')+':/usr/local/apisix/conf/config.yaml:ro','-v',str(tmp_path/'apisix.yaml')+':/usr/local/apisix/conf/apisix.yaml:ro','apache/apisix:3.18.0-debian'],check=True,capture_output=True)
            def invoke(roles):
                meta={'io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{'name':'summary-stack','version':'1'},'io.modelcontextprotocol/protocolVersion':'2026-07-28'}
                body={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'ouf.operations.summary','arguments':{'limit':5},'_meta':meta}}
                headers={'Authorization':'Bearer '+token(roles),'Content-Type':'application/json','Accept':'application/json, text/event-stream','Mcp-Protocol-Version':'2026-07-28','Mcp-Method':'tools/call','Mcp-Name':'ouf.operations.summary','Idempotency-Key':str(uuid.uuid4()),'X-Correlation-ID':str(uuid.uuid4()),'X-OUF-External-Role-Refs':'ouf:viewer'}
                req=urllib.request.Request(f'http://127.0.0.1:{api_port}/mcp',data=json.dumps(body).encode(),headers=headers)
                try:
                    with urllib.request.urlopen(req,timeout=15) as response:return response.status,response.read()
                except urllib.error.HTTPError as e:return e.code,e.read()
            for _ in range(60):
                try:
                    code,body=invoke([])
                    if code!=404:break
                except OSError:pass
                time.sleep(.5)
            else:raise AssertionError('APISIX startup timeout')
            code,body=invoke(['ouf:viewer']);assert code==200,(code,body)
            result=json.loads(body)['result'];assert not result.get('isError'),body
            summary=json.loads(result['content'][0]['text'])
            assert summary['status']=='DEGRADED' and summary['partial'] is False,json.dumps(summary)
            assert {m['module'] for m in summary['modules']}=={'MCP','GATEWAY','INGESTION'},summary
            code,body=invoke([]);assert code==200,(code,body)
            result=json.loads(body)['result'];assert result.get('isError') is True,body
            assert json.loads(result['content'][0]['text'])['code']=='authorization denied',body
            assert 'modules' not in str(result),body
    except Exception:
        subprocess.run(['docker','logs','--tail','40',name],check=False)
        for log in tmp_path.glob('*.log'):print(log.name,log.read_text()[-6000:])
        raise
    finally:
        subprocess.run(['docker','rm','-f',name],check=False,capture_output=True);server.shutdown()
