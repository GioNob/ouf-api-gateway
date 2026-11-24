"""Real APISIX/OIDC/Lua gate. Opt-in locally; mandatory in GitHub Actions.

Synthetic issuer and owner use HTTP only inside the isolated CI job. Production
materialization keeps HTTPS discovery with certificate verification enabled.
"""
import base64
import copy
import contextlib
import hashlib
import hmac
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from tools.materialize_object_search import materialize
from tests.test_dispatch_schema_contract import (
    THS_LINK_DISPATCH_CASES, dispatch_body, dispatch_profiles, is_dispatch, wave2_dispatch_cases,
)
from tests.test_execute_delegation import runtime, envelope
from tests.release_bundle_fixture import READ_OPERATIONS_IDS, R2B_ROUTE_IDS, RELEASE_ROUTE_IDS, SEARCH_IDS, ci_profile, load_release_routes
from tools.gateway_release_bundle import generate
from tools.materialize_onboarding_review import RECOVERY_PAGE_ID, RUN_ROUTES
from tools.mcp_dispatch_contract import INVALID_TOOL_ARGUMENTS, PICKER_ROUTES, bound_capability, capability_contracts, picker_contract


R2B_GET = '/api/semantic/v1/references:resolve'
R2B_CASES = {
    '/api/internal/v1/lake/objects': ('POST', 'datalake.write'),
    '/api/internal/v1/handoffs': ('POST', 'udp.candidate.write'),
    R2B_GET: ('GET', 'ouf.semantic.read'),
    R2B_GET + '-batch': ('POST', 'ouf.semantic.read'),
}


def check_r2b_mixed_window(request, token, installation):
    """GW-51D-LIVE. Observe ordering and quotas on the installed APISIX routes."""
    ingestion = installation['ingestionServiceIdentity']
    udp = installation['udpServiceIdentity']
    reference = {'semanticId': 'urn:ci:term', 'revisionId': '11111111-1111-4111-8111-111111111111',
                 'publicationSetId': '22222222-2222-4222-8222-222222222222'}
    for path, (method, scope) in R2B_CASES.items():
        target = path + '?' + urllib.parse.urlencode(reference) if method == 'GET' else path
        body = None if method == 'GET' else {}
        if path.endswith('-batch'):
            body = {'references': [reference]}

        def call(service=ingestion, actor='SERVICE', granted=scope, payload=body):
            bearer = token(actor, azp=service, scope=granted)
            return request(method, target, payload, bearer, with_headers=True)

        assert request(method, target, body)[0] == 401
        wrong_aud = token('SERVICE', azp=ingestion, scope=scope, aud='other-resource')
        assert request(method, target, body, wrong_aud)[0] in (401, 403)
        assert call(granted='other.scope')[0] == 403
        # A signed token with the correct scope reaches limit-count before the
        # access-phase workload guard. A rejected service consumes one credit.
        first, _, initial_quota = call()
        assert first == 200
        assert call(service='unlisted-client')[0] == 403
        second, _, quota = call()
        assert second == 200
        assert int(quota['X-RateLimit-Remaining']) == int(initial_quota['X-RateLimit-Remaining']) - 2
        assert call(actor='HUMAN')[0] == 403
        if path.startswith(R2B_GET):
            assert call(udp)[0] == 200
        else:
            assert call(udp)[0] == 403
        if path.endswith('-batch'):
            exact = json.dumps(body).encode().ljust(262144)
            assert call(payload=exact)[0] == 200
            status, raw, _ = call(payload=exact + b' ')
            assert status == 413 and json.loads(raw)['code'] == 'SEM_REFERENCE_BATCH_TOO_LARGE'
        status, raw, quota = call()
        assert status == 200, (path, status)
        owner = json.loads(raw)
        assert owner['path'] == target and owner['bearerPresent']
        assert owner['headers'] == {
            'x-ouf-gateway-verified': 'true', 'x-ouf-service-principal': ingestion,
            'x-ouf-actor-type': 'SERVICE', 'x-ouf-principal-id': 'service',
            'x-ouf-tenant-id': 'tenant-a', 'x-ouf-authentication-context-ref': '1',
            'x-ouf-token-issuer': installation['issuerUrl'], 'x-ouf-token-audience': installation['gatewayAudience'],
            'x-ouf-granted-scopes': scope,
        }
        assert int(quota['X-RateLimit-Limit']) == 12
        for _ in range(int(quota['X-RateLimit-Remaining'])):
            assert call()[0] == 200
        # GET and batch each have their own bucket, shared by both workloads
        # behind the same proxy. A fresh signed JWT does not reset that bucket.
        status, _, quota = call(udp if path.startswith(R2B_GET) else ingestion)
        assert status == 429
        assert int(quota['X-RateLimit-Limit']) == 12
        assert int(quota['X-RateLimit-Remaining']) == 0
        # APISIX 3.18 reports the reset in fractional seconds, for example 59.97.
        assert 0 <= float(quota['X-RateLimit-Reset']) <= 60


def wait_for_protected_routes(post, probes, timeout=60):
    """Wait for each required route to enforce OIDC before testing dispatch."""
    deadline = time.monotonic() + timeout
    pending = dict(probes)
    observed = {}
    while pending:
        for path, body in list(pending.items()):
            try:
                status, _ = post(path, body)
            except (TimeoutError, urllib.error.URLError) as error:
                if isinstance(error, urllib.error.URLError) and not isinstance(
                    error.reason, (ConnectionRefusedError, TimeoutError)
                ):
                    raise
                observed[path] = 'listener unavailable'
                continue
            observed[path] = status
            if status == 401:
                del pending[path]
            elif status != 404:
                raise AssertionError(f'expected protected APISIX route {path}, got HTTP {status}')
        if pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                missing = {path: observed[path] for path in pending}
                raise AssertionError(f'APISIX routes not ready: {missing}')
            time.sleep(min(0.5, remaining))


def test_apisix_readiness_requires_the_execute_route(monkeypatch):
    monkeypatch.setattr(time, 'sleep', lambda _: None)
    execute = '/internal/capabilities/v1/execute/semantic/create'
    outcomes = {'/mcp': iter([401]), execute: iter([404, 401])}
    calls = []

    def post(path, body):
        calls.append(path)
        return next(outcomes[path]), b''

    wait_for_protected_routes(post, {'/mcp': {}, execute: {'Arguments': {}}})
    assert calls == ['/mcp', execute, execute]


def test_apisix_readiness_reports_the_missing_route():
    execute = '/internal/capabilities/v1/execute/semantic/create'
    with pytest.raises(AssertionError, match='semantic/create.*404'):
        wait_for_protected_routes(lambda *_: (404, b''), {execute: {}}, timeout=0)


@pytest.mark.skipif(os.environ.get('OUF_APISIX_LIVE_TEST') != '1', reason='requires Docker APISIX integration gate')
def test_real_apisix_oidc_delegation_and_execute():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='fixture',use='sig',alg='RS256')
    rt=runtime();installation=rt['x-ouf-installation'];issuer=installation['issuerUrl'];aud=installation['gatewayAudience'];workload=installation['mcpServiceIdentity']
    calls=[]
    terms_path = '/api/trusted-human/v1/semantic-published-terms'
    wave2_dispatch = wave2_dispatch_cases()
    search_receipts = {}
    recovery_page = '/trusted-human/ingestion-run-recovery/'
    recovery_run = '/api/trusted-human/v1/ingestion/runs/11111111-1111-4111-8111-111111111111'
    human_runs = {
        recovery_run: ('GET', 'ingestion.run.read'),
        recovery_run + '/resume': ('POST', 'ingestion.run.resume'),
        recovery_run + '/abort': ('POST', 'ingestion.run.abort'),
    }
    human_run_calls = []
    terms_calls = []
    dispatch_paths = {
        "semantic.propose": ("semantic/create", "/api/semantic/v1/proposal-commands/create"),
        "source.onboarding.create": ("managed.file/create", "/api/internal/v1/onboarding/managed-file-mcp/create"),
        "source.onboarding.revision.prepare": ("source.revision/prepare", "/api/internal/v1/onboarding/source-revision-mcp/prepare"),
    }
    dispatch_calls = []
    dispatch_bodies = {}
    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/discovery':
                self.reply({'issuer':issuer,'jwks_uri':f'http://127.0.0.1:{server.server_port}/jwks','token_endpoint':issuer+'/token','authorization_endpoint':issuer+'/auth','id_token_signing_alg_values_supported':['RS256']})
            elif self.path=='/jwks': self.reply({'keys':[jwk]})
            elif self.path.split('?')[0] in R2B_CASES: self.r2b()
            elif self.path.startswith(terms_path):
                terms_calls.append(self.path)
                self.reply({'target': self.path})
            elif self.path in human_runs:
                self.human_run()
            elif self.path == recovery_page:
                self.reply({'sessionRequired': True, 'authorization': self.headers.get('Authorization')}, 401)
            else:self.send_error(404)
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length','0')))
            if self.path in R2B_CASES:
                self.r2b()
            elif self.path.startswith(terms_path):
                terms_calls.append(self.path)
                self.reply({'unexpected_method': 'POST'})
            elif self.path in human_runs:
                self.human_run()
            elif self.path in ({owner for owner, _, _ in wave2_dispatch.values()} |
                               {owner for _, owner in dispatch_paths.values()}):
                dispatch_calls.append(self.path)
                dispatch_bodies[self.path] = body
                if self.path.startswith('/api/internal/v1/semantic/consultation/'):
                    search_receipts[self.path] = self.headers.get('X-OUF-Semantic-Read-Receipt')
                if self.path == dispatch_paths['semantic.propose'][1] and len(body) > 65536:
                    self.reply({
                        'bodyBytes': len(body), 'bodyHash': hashlib.sha256(body).hexdigest(),
                        'receipt': self.headers.get('X-OUF-Semantic-Proposal-Receipt'),
                    })
                else:
                    self.reply({'body': json.loads(body), 'authorization': self.headers.get('Authorization'),
                                'delegation': self.headers.get('X-OUF-Delegation')})
            elif self.path=='/mcp':
                # Test-only MCP stub returns opaque proof to the test driver.
                assert not self.headers.get('Authorization')
                self.reply({'proof':self.headers.get('X-OUF-Delegation'),'roles':self.headers.get('X-OUF-External-Role-Refs')})
            elif self.path=='/api/internal/v1/mcp/operations/status':
                calls.append((dict(self.headers),body));self.reply({'module':'MCP','status':'HEALTHY','actionRequired':False,'partial':False,'visibilityClass':'PUBLIC_OPERATIONAL','redacted':True})
            elif self.path in ('/api/internal/v1/mcp/operations/summary', '/api/internal/v1/mcp/operations/incidents',
                               '/api/internal/v1/ingestion/operations/summary', '/api/internal/v1/ingestion/operations/incidents',
                               '/api/internal/v1/gateway/operations/summary', '/api/internal/v1/gateway/operations/incidents'):
                self.reply({'headers': {k.lower():v for k,v in self.headers.items()}, 'body': json.loads(body)})
            elif self.path in ('/api/internal/v1/ingestion/operations/status', '/api/internal/v1/ingestion/operations/acquisition',
                               '/api/udp/v1/operations/acquisition'):
                self.reply({'headers': {k.lower(): v for k, v in self.headers.items()}, 'wire': body.decode()})
            elif self.path.startswith('/api/internal/v1/authorization/permissions/'):
                self.reply({'receipt':self.headers.get('X-OUF-Authorization-Receipt'),'body':body.decode(),'authorization':self.headers.get('Authorization')})
            elif self.path=='/api/udp/v1/objects/search':
                self.reply({'receipt':self.headers.get('X-OUF-UDP-Search-Receipt'),'body':body.decode(),'authorization':self.headers.get('Authorization'),'delegation':self.headers.get('X-OUF-Delegation')})
            else:self.reply({'message': 'unexpected synthetic owner path'}, status=404)
        def r2b(self):
            self.reply({'path': self.path, 'bearerPresent': bool(self.headers.get('Authorization')),
                        'headers': {k.lower(): v for k, v in self.headers.items() if k.lower().startswith('x-ouf-')}})
        def reply(self,value,status=200):
            data=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def human_run(self):
            human_run_calls.append((self.command, self.path))
            self.reply({'authorization': self.headers.get('Authorization'),
                        'oufHeaders': [name for name in self.headers if name.lower().startswith('x-ouf-')]})
        def log_message(self,*args):pass
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    def token(actor='HUMAN',**updates):
        now=int(time.time());c=dict(iss=issuer,aud=aud,iat=now,exp=now+300,sub='human-a',tenant_id='tenant-a',acr='1',azp='chatgpt',scope='mcp.connect operations.status.read',ouf_actor_type=actor)
        if actor=='SERVICE':c.update(azp=workload,sub='service',scope='authorization.bundle.read')
        c.update(updates);return jwt.encode(c,key,algorithm='RS256',headers={'kid':'fixture'})
    def request(method,path,body=None,bearer=None,proof=None,*,with_headers=False):
        headers={'Content-Type':'application/json','X-Correlation-ID':'corr','Idempotency-Key':'idem','X-Tool-Attempt-ID':envelope()['AttemptID'],'X-OUF-External-Role-Refs':'ouf:forged-admin', 'X-OUF-Unknown':'forged'}
        if path.endswith('/managed.file/handoff-issue') and body and 'IdempotencyKey' in body:
            headers['Idempotency-Key'] = body['IdempotencyKey']
        if path.split('?')[0] in R2B_CASES:
            headers.update({'X-OUF-Gateway-Verified': 'true', 'X-OUF-Tenant-ID': 'forged-tenant',
                            'X-OUF-Service-Principal': installation['ingestionServiceIdentity']})
        if bearer:headers['Authorization']='Bearer '+bearer
        if proof:headers['X-OUF-Delegation']=proof
        data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers=headers,method=method)
        try:res=urllib.request.urlopen(req,timeout=5)
        except urllib.error.HTTPError as e:res=e
        with res:
            result = res.status, res.read()
            return (*result, res.headers) if with_headers else result

    def post(path,body,bearer=None,proof=None):
        return request('POST', path, body, bearer, proof)
    with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as owners:
        server = owners.enter_context(ThreadingHTTPServer(('127.0.0.1', 0), Fixture))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        owners.callback(server.shutdown)
        owner_port = None
        if os.environ.get('OUF_GATEWAY_OWNER_JAR'):
            from tests.summary_java_owner import java_owner
            owner_port, owner_db = owners.enter_context(java_owner(os.environ['OUF_GATEWAY_OWNER_JAR'], folder, installation))
        udp_port=None
        if os.environ.get('OUF_UDP_JAR'):
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
        if owner_port:
            from tools.materialize_operational_execute import materialize as operational_routes
            signed = operational_routes(rt, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY',
                                        producer_receipt_key_envs={'gateway': 'GATEWAY_SUMMARY_RECEIPT_KEY'})
            summary_uri = '/internal/capabilities/v1/execute/ouf.gateway.operations.summary'
            summary = next(r for r in signed['routes'] if r.get('uri') == summary_uri)
            doc['routes'] = [summary if r.get('uri') == summary_uri else r for r in doc['routes']]
        for r in doc['routes']:
            oidc=r['plugins'].get('openid-connect')
            if oidc:oidc['discovery']=f'http://127.0.0.1:{server.server_port}/discovery'
            if 'upstream' in r:r['upstream']['nodes']={f'127.0.0.1:{server.server_port}':1}
            if owner_port and r.get('uri') == summary_uri:
                r['upstream']['nodes'] = {f'127.0.0.1:{owner_port}': 1}
            if udp_port and r.get('uri','').endswith('/execute/urban.object.search'):
                r['upstream']['nodes']={f'127.0.0.1:{udp_port}':1}
        probes = {'/mcp': {}}
        bundle_dir = os.environ.get('OUF_GATEWAY_RELEASE_BUNDLE')
        workflow = '.github/workflows/ci.yml'
        if bundle_dir:
            bundle_path = Path(bundle_dir)
            commit, run_id = os.environ['OUF_GATEWAY_RELEASE_COMMIT'], os.environ['GITHUB_RUN_ID']
        else:
            bundle_path = Path(folder, 'release')
            commit, run_id = '1' * 40, '50'
            generate(bundle_path, commit, workflow, run_id)
        profile = ci_profile(installation, server.server_port)
        release = load_release_routes(bundle_path, commit, workflow, run_id, profile)
        reads = [r for r in release if r['id'] in READ_OPERATIONS_IDS]
        if udp_port:
            next(r for r in reads if r['id'] == 'execute-urban-object-search')['upstream']['nodes'][0]['port'] = udp_port
        if owner_port:
            # Only summary is backed by the Java owner in this test.
            next(r for r in reads if r['uri'] == summary_uri)['upstream']['nodes'][0]['port'] = owner_port
        read_uris = {r['uri'] for r in reads}
        doc['routes'] = [r for r in doc['routes'] if r.get('uri') not in read_uris]
        optional_ids = [r['id'] for r in release if r['id'] in THS_LINK_DISPATCH_CASES]
        assert [route['id'] for route in release] == sorted(RELEASE_ROUTE_IDS + optional_ids)
        wave2_dispatch = wave2_dispatch_cases(release)
        if bundle_dir:
            doc['routes'].extend(release)
        else:
            doc['routes'].extend(route for route in release if route['id'] in READ_OPERATIONS_IDS or route.get('uri') in wave2_dispatch
                                 or route['id'] == RECOVERY_PAGE_ID or route['id'] in RUN_ROUTES
                                 or route['id'] in R2B_ROUTE_IDS)
        changed_routes = {route['uri']: route for route in release if route.get('uri') in wave2_dispatch}
        assert changed_routes.keys() == wave2_dispatch.keys()
        for uri, (_, accepted, _) in wave2_dispatch.items():
            schema = changed_routes[uri]['plugins']['request-validation']['body_schema']
            probes[uri] = dispatch_body(schema, accepted[0])
        if bundle_dir:
            # Qualify the rest of the JSON dispatch materializers alongside the release artifact.
            loaded = {r.get('uri') for r in doc['routes']}
            _, profiles = dispatch_profiles()
            for route in profiles:
                if route['uri'] not in loaded and 'request-validation' in route['plugins']:
                    route['plugins']['openid-connect']['discovery'] = f'http://127.0.0.1:{server.server_port}/discovery'
                    route['upstream']['nodes'] = {f'127.0.0.1:{server.server_port}': 1}
                    doc['routes'].append(route)
            from tests.test_value_type_schemas import dispatch
            for tool_name, (suffix, _) in dispatch_paths.items():
                probes['/internal/capabilities/v1/execute/' + suffix] = dispatch(tool_name)
        config = {
            'apisix': {'node_listen': port, 'enable_admin': False},
            'deployment': {'role': 'data_plane', 'role_data_plane': {'config_provider': 'yaml'}},
            'nginx_config': {'envs': ['OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY', 'UDP_KEY',
                                      'DISCOVERY_KEY', 'READ_KEY', 'GATEWAY_SUMMARY_RECEIPT_KEY', 'INGESTION_SUMMARY_RECEIPT_KEY']},
        }
        if bundle_dir:
            # Route readiness and the bundle assertions must observe the same worker.
            config['nginx_config']['worker_processes'] = 1
            # Keep route-load errors visible in the failure log during readiness.
            config['nginx_config']['http'] = {'enable_access_log': False}
        Path(folder,'config.yaml').write_text(yaml.safe_dump(config))
        Path(folder,'apisix.yaml').write_text(yaml.safe_dump({'routes':doc['routes']})+'\n#END\n')
        container_id = subprocess.check_output([
            'docker', 'run', '-d', '--network', 'host', '-e', 'OIDC_SECRET=fixture-only',
            '-e', 'DELEGATION_KEY=' + 'ab' * 32, '-e', 'OWNER_KEY=' + 'cd' * 32,
            '-e', 'READ_KEY=' + '56' * 32,
            '-e', 'DISCOVERY_KEY=' + '45' * 32, '-e', 'UDP_KEY=' + '34' * 32, '-e', 'GATEWAY_SUMMARY_RECEIPT_KEY=' + '12' * 32,
            '-e', 'INGESTION_SUMMARY_RECEIPT_KEY=' + 'ef' * 32,
            '-v', folder + '/config.yaml:/usr/local/apisix/conf/config.yaml:ro',
            '-v', folder + '/apisix.yaml:/usr/local/apisix/conf/apisix.yaml:ro',
            'apache/apisix:3.18.0-debian',
        ], text=True).strip()
        try:
            wait_for_protected_routes(post, probes)
            check_r2b_mixed_window(request, token, installation)
            for uri, (owner, accepted, rejected) in wave2_dispatch.items():
                schema = changed_routes[uri]['plugins']['request-validation']['body_schema']
                route_id = changed_routes[uri]['id']
                contract = (picker_contract(route_id) if route_id in PICKER_ROUTES
                            else capability_contracts()[bound_capability(schema)])
                scope = ('ouf.semantic.discovery' if route_id == 'mcp-semantic-discovery-candidates'
                         else contract['requiredAuthorizationCapability'])
                status, result = post('/mcp', {}, token(scope='mcp.connect ' + scope))
                assert status == 200
                delegation = json.loads(result)['proof']
                before = len(dispatch_calls)
                is_ths_link = changed_routes[uri]['id'] in THS_LINK_DISPATCH_CASES
                for arguments in accepted:
                    body = dispatch_body(schema, arguments)
                    status, result = post(uri, body, token('SERVICE'), delegation)
                    assert status == 200, (uri, status, result)
                    forwarded = arguments if is_ths_link else body
                    assert json.loads(result) == {'body': forwarded, 'authorization': None, 'delegation': None}
                    if route_id == 'mcp-semantic-discovery-candidates' or route_id in SEARCH_IDS:
                        assert dispatch_bodies[owner] == json.dumps(body).encode()
                    if route_id in SEARCH_IDS:
                        encoded, signed = search_receipts[owner].encode().split(b'.')
                        expected = hmac.digest(b'56' * 32, b'ouf-semantic-read-owner-v1.' + encoded, 'sha256')
                        assert hmac.compare_digest(expected, base64.urlsafe_b64decode(signed + b'=='))
                        receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
                        assert receipt['path'] == owner and receipt['capability'] == body['CapabilityID']
                        assert receipt['bodyHash'] == hashlib.sha256(dispatch_bodies[owner]).hexdigest()
                    if is_ths_link:
                        canonical = json.dumps(arguments, sort_keys=True, separators=(',', ':'),
                                               ensure_ascii=False).encode('utf-8')
                        assert dispatch_bodies[owner] == canonical
                for arguments in rejected:
                    status, result = post(uri, dispatch_body(schema, arguments), token('SERVICE'), delegation)
                    expected_error = 'SEM_BATCH_ARGUMENTS_INVALID' if route_id == 'mcp-semantic-search-batch' else INVALID_TOOL_ARGUMENTS
                    assert status == 400 and expected_error.encode() in result, (uri, status, result)
                    assert b'private-source-value' not in result
                assert dispatch_calls[before:] == [owner] * len(accepted)

            for uri, (method, scope) in human_runs.items():
                body = None if method == 'GET' else {'expectedVersion': 7}
                assert request(method, uri, body)[0] == 401
                assert request(method, uri, body, token('SERVICE', scope=scope))[0] == 403
                bearer = token(scope=scope)
                status, result = request(method, uri, body, bearer)
                assert status == 200, (uri, status, result)
                assert json.loads(result) == {'authorization': 'Bearer ' + bearer, 'oufHeaders': []}
            assert human_run_calls == [(method, uri) for uri, (method, _) in human_runs.items()]
            assert request('POST', recovery_run + '/pause', {'expectedVersion': 7})[0] == 404
            status, result = request('GET', recovery_page, bearer=token())
            assert status == 401
            assert json.loads(result) == {'sessionRequired': True, 'authorization': None}

            if bundle_dir:
                for route in doc['routes']:
                    if not is_dispatch(route):
                        continue
                    schema = route['plugins']['request-validation']['body_schema']
                    invalid = dispatch_body(schema, ['private-source-value'])
                    status, result = post(route['uri'], invalid, token('SERVICE'), delegation)
                    expected_error = route['plugins']['request-validation']['rejected_msg']
                    assert status == 400 and expected_error.encode() in result, (route['id'], status)
                    assert b'private-source-value' not in result

                target = terms_path + '?revisionIds=rev-a,rev-b'
                reviewer = token(scope='ouf.semantic.review')
                for method, uri, bearer, expected in [
                    ('GET', target, None, 401),
                    ('GET', target, token(), 403),
                    ('GET', target, token('SERVICE', scope='ouf.semantic.review'), 403),
                    ('GET', terms_path + '/extra', reviewer, 404),
                    ('POST', terms_path, reviewer, 404),
                    ('GET', target, reviewer, 200),
                ]:
                    req = urllib.request.Request(f'http://127.0.0.1:{port}' + uri, method=method)
                    if bearer:
                        req.add_header('Authorization', 'Bearer ' + bearer)
                    try:
                        response = urllib.request.urlopen(req, timeout=5)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        assert response.status == expected, (method, uri, response.status)
                        if expected == 200:
                            assert json.load(response)['target'] == target
                assert terms_calls == [target]
                from tests.test_value_type_schemas import (
                    compact_json, value_map_at_definition_limit, value_map_dispatch,
                )
                dispatch_cases = [(dispatch(tool), suffix, owner) for tool, (suffix, owner) in dispatch_paths.items()]
                dispatch_cases.append((value_map_dispatch(), *dispatch_paths['semantic.propose']))
                for body, suffix, owner_path in dispatch_cases:
                    if body['Arguments'].get('artifactType') == 'VALUE_MAP':
                        body['Arguments']['definition']['entries'][0]['code'] = '\U0001f30d' * 128
                    # Bind the synthetic MCP request to this live gate's identity and headers.
                    for field in ("Identity", "AttemptID", "IdempotencyKey", "CorrelationID"):
                        body[field] = envelope()[field]
                    if "commandKey" in body["Arguments"]:
                        body["Arguments"]["commandKey"] = body["IdempotencyKey"]
                    status, result = post("/mcp", {}, token(scope="mcp.connect " + body["CapabilityID"]))
                    assert status == 200
                    delegation = json.loads(result)["proof"]
                    path = "/internal/capabilities/v1/execute/" + suffix
                    before = len(dispatch_calls)
                    invalid = copy.deepcopy(body)
                    args = invalid['Arguments']
                    invalid_bodies = [invalid]
                    if args.get('artifactType') == 'DATATYPE':
                        args['definition']['components'][0].update(
                            type='string', constraints={'minInclusive': 'private-source-value'})
                    elif args.get('artifactType') == 'VALUE_MAP':
                        duplicate = copy.deepcopy(invalid)
                        duplicate_entries = duplicate['Arguments']['definition']['entries']
                        duplicate_entries[0]['code'] = duplicate_entries[1]['code'] = 'private-source-value'
                        invalid_bodies.append(duplicate)
                        for invalid_code in ('private-source-value\x80', '\u202fprivate-source-value'):
                            invalid_code_body = copy.deepcopy(body)
                            invalid_code_body['Arguments']['definition']['entries'][0]['code'] = invalid_code
                            invalid_bodies.append(invalid_code_body)
                        args['definition']['entries'][0]['code'] = 'private-source-value\x7f'
                    else:
                        args['compositions'][0]['kind'] = 'private-source-value'
                    for invalid_body in invalid_bodies:
                        status, result = post(path, invalid_body, token('SERVICE'), delegation)
                        assert status == 400, (path, status, {
                            'owner_404': b'unexpected synthetic owner path' in result,
                        })
                        assert b'INVALID_TOOL_ARGUMENTS' in result
                        assert b'private-source-value' not in result and len(dispatch_calls) == before
                    accepted = copy.deepcopy(body)
                    if accepted['Arguments'].get('artifactType') == 'DATATYPE':
                        components = accepted['Arguments']['definition']['components']
                        title = next(component for component in components if component['name'] == 'title')
                        title['constraints']['maxLength'] = 10_000_000_000_000_001
                        sent = compact_json(accepted)
                    elif suffix == 'source.revision/prepare':
                        # The schema allows an empty array and caps expectedVersion at 2**53 - 1.
                        accepted['Arguments'].update(compositions=[], expectedVersion=9_007_199_254_740_991)
                        sent = compact_json(accepted)
                    else:
                        sent = accepted
                    status, result = post(path, sent, token("SERVICE"), delegation)
                    assert status == 200, (path, status)
                    assert dispatch_calls[before:] == [owner_path]
                    if isinstance(sent, bytes):
                        assert dispatch_bodies[owner_path] == sent
                    assert json.loads(result)["body"] == accepted
                    if body['Arguments'].get('artifactType') == 'DATATYPE':
                        raw = compact_json(body).ljust(65536)
                        assert post(path, raw, token('SERVICE'), delegation)[0] == 200
                        assert post(path, raw + b' ', token('SERVICE'), delegation)[0] == 413
                        assert dispatch_calls[before:] == [owner_path, owner_path]
                    if body['Arguments'].get('artifactType') == 'VALUE_MAP':
                        large = value_map_at_definition_limit()
                        for field in ('Identity', 'AttemptID', 'IdempotencyKey', 'CorrelationID'):
                            large[field] = body[field]
                        large['Arguments']['commandKey'] = large['IdempotencyKey']
                        raw = compact_json(large).ljust(1048576)
                        status, result = post(path, raw, token('SERVICE'), delegation)
                        assert status == 200, (path, status)
                        owner = json.loads(result)
                        body_hash = hashlib.sha256(raw).hexdigest()
                        assert owner['bodyBytes'] == len(raw) and owner['bodyHash'] == body_hash
                        assert owner['receipt']
                        encoded, signature = (part.encode() for part in owner['receipt'].split('.'))
                        assert hmac.compare_digest(
                            base64.urlsafe_b64decode(signature + b'=='),
                            hmac.digest(('cd' * 32).encode(), b'ouf-semantic-proposal-owner-v1.' + encoded, 'sha256'),
                        )
                        receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
                        assert receipt['path'] == owner_path and receipt['bodyHash'] == body_hash
                        assert receipt['capability'] == body['CapabilityID']
                        # Oversized bodies can be rejected by nginx or request-validation.
                        assert post(path, raw + b' ', token('SERVICE'), delegation)[0] in (400, 413)
                        assert dispatch_calls[before:] == [owner_path, owner_path]
            code,raw=post('/mcp',{},token(externalRoleRefs=['ouf:viewer']),proof='forged')
            assert code==200, (code,raw)
            proof=json.loads(raw)['proof'];assert proof and proof!='forged'
            assert json.loads(raw)['roles']=='ouf:viewer'
            from tests.test_release_family_read_operations_mcp import check_read_owner_http
            check_read_owner_http(reads, post, token, dispatch_body)
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
            from tests.test_permission_proposals import request as permission_request
            cap='authorization.permissions.propose'
            code,raw=post('/mcp',{},token(scope='mcp.connect '+cap,externalRoleRefs=['ente:staff']))
            assert code==200,(code,raw)
            delegated=json.loads(raw)['proof']
            code,raw=post('/internal/capabilities/v1/execute/authorization/propose',permission_request(),token('SERVICE'),delegated)
            assert code==200,(code,raw)
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
                if owner_port and route == summary_uri:
                    assert projection['module'] == 'GATEWAY' and projection['status'] == 'DEGRADED'
                    assert projection['partial'] is False and len(projection['items']) == 1
                    assert 'correlation_id' not in projection['items'][0]
                    code, raw = post('/mcp', {}, token(externalRoleRefs=[]))
                    assert code == 200
                    code, _ = post(route, body, token('SERVICE'), json.loads(raw)['proof'])
                    assert code == 403
                    direct = urllib.request.Request(f'http://127.0.0.1:{owner_port}/api/internal/v1/gateway/operations/summary',
                        data=b'{}', headers={'Content-Type': 'application/json', 'X-OUF-Gateway-Verified': 'true',
                                             'X-OUF-Principal-ID': 'human-a'})
                    with pytest.raises(urllib.error.HTTPError) as denied:
                        urllib.request.urlopen(direct)
                    assert denied.value.code == 403
                    from tools.operational_incidents import SQLiteOperationalIncidentStore
                    with contextlib.closing(SQLiteOperationalIncidentStore(owner_db)) as store:
                        store.open_incident(dedup_key='protected', event_type='SECURITY', severity='ERROR',
                                            error_code='HIDDEN', impact_summary='hidden-sensitive-evidence')
                    code, raw = post(route, body, token('SERVICE'), operational_proof)
                    hidden = json.loads(raw)
                    assert code == 200 and hidden['partial'] is True and hidden['status'] == 'UNKNOWN'
                    assert 'openIncidents' not in hidden and b'hidden-sensitive-evidence' not in raw
                else:
                    h = projection['headers']
                    assert projection['body'] == {'limit':3}
                    assert h['x-ouf-principal-id'] == 'human-a' and h['x-ouf-service-principal'] == workload
                    assert h['x-ouf-external-role-refs'] == 'ouf:viewer' and 'authorization' not in h
                    if owner == 'mcp':
                        assert h['x-ouf-delegation'] == operational_proof
                        assert h['x-ouf-delegation-verified'] == 'mcp-operational-aggregate-v1'
                    else:
                        assert 'x-ouf-delegation' not in h and 'x-ouf-delegation-verified' not in h
                wrong = dict(body, Owner='udp')
                code, _ = post(route, wrong, token('SERVICE'), operational_proof)
                assert code in (400, 403)
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
            subprocess.run(['docker','logs','--tail','60',container_id],check=False)
            raise
        finally:
            subprocess.run(['docker','rm','-f',container_id],stdout=subprocess.DEVNULL,check=False)
