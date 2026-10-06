import copy
from email.message import Message
import unittest
from unittest.mock import Mock, patch

from tests.test_execute_delegation import Engine, Denied
from tests.test_semantic_provider_adapter import binding, form, KEY, NOW
from tools import semantic_provider_admission as admission
from tools import semantic_provider_adapter as adapter
from tools.materialize_semantic_provider import materialize


def config():
    b = binding()
    return {'installation': b.admission.installation, 'issuer': b.admission.issuer,
        'audience': b.admission.audience, 'workload': b.admission.workload,
        'scope': b.admission.scope, 'tenants': list(b.admission.tenants),
        'searchPath': b.search_path, 'fetchPath': b.fetch_path,
        'searchRouteId': 'provider-search', 'fetchRouteId': 'provider-fetch',
        'receiptKeyEnvironment': 'OUF_SEMANTIC_PROVIDER_OWNER_KEY', 'oidcSecretRef': '$ENV://OIDC_SECRET',
        'upstream': {'type': 'roundrobin', 'scheme': 'https', 'nodes': {'adapter.example:9443': 1},
            'pass_host': 'rewrite', 'upstream_host': 'adapter.example',
            'timeout': {'connect': 3, 'send': 3, 'read': 20}},
        'tlsProfile': {'role': 'DEDICATED_SOUTHBOUND', 'mode': 'NGINX_PROXY_SSL_VERIFY',
            'trustedCertificateFile': '/provider-fixture/cert.pem', 'verifyDepth': 3},
        'rateLimit': {'count': 30, 'time_window': 60, 'key_type': 'var', 'key': 'remote_addr', 'policy': 'local', 'rejected_code': 429},
        'maxRequestBytes': 65536}


def workload():
    return {'iss': 'https://auth.example/realms/test', 'aud': 'gateway-test',
        'azp': 'semantic-test', 'sub': 'service-subject', 'tenant_id': 'tenant-test',
        'ouf_actor_type': 'SERVICE', 'scope': 'gateway.southbound.invoke', 'iat': NOW-10, 'exp': NOW+300}


def run(claims=None, body=None, target='/provider/search', method='POST', key=KEY):
    engine = Engine(workload() if claims is None else claims, {'X-OUF-Semantic-Provider-Receipt': 'forged',
        'X-OUF-Tenant-ID': 'forged', 'Cookie': 'secret'}, now=NOW, key=key)
    engine.body = form() if body is None else body
    engine.lua.globals()[b'ngx'][b'var'][b'request_uri'] = target.encode()
    engine.lua.globals()[b'ngx'][b'req'][b'get_method'] = lambda: method.encode()
    engine.lua.globals()[b'ngx'][b'req'][b'get_body_file'] = lambda: None
    route = materialize({'routes': []}, config())['routes'][0 if method == 'POST' else 1]
    engine.lua.execute(route['plugins']['serverless-post-function']['functions'][0].encode())(None, None)
    return engine


class ProviderMaterializationTest(unittest.TestCase):
    def test_existing_routes_preserved_oidc_coarse_scope_tls_limits(self):
        existing = {'routes': [{'id': 'prior-route', 'uri': '/existing', 'upstream': {'nodes': {'prior:123': 1}}}], 'other': {'retained': True}}
        before = copy.deepcopy(existing); result = materialize(existing, config())
        self.assertEqual(existing, before); self.assertEqual(result['routes'][0], before['routes'][0])
        for route in result['routes'][1:]:
            oidc = route['plugins']['openid-connect']
            self.assertTrue(oidc['use_jwks']); self.assertTrue(oidc['ssl_verify'])
            self.assertEqual(oidc['required_scopes'], ['gateway.southbound.invoke'])
            self.assertTrue(oidc['claim_validator']['audience']['match_with_client_id'])
            self.assertEqual(route['upstream']['scheme'], 'https'); self.assertEqual(route['upstream']['retries'], 0)
            self.assertNotIn('proxy-rewrite', route['plugins'])
        self.assertIn('proxy_ssl_verify on;', result['providerTLSRequirement']['nginxHTTPConfigurationSnippet'])
        self.assertFalse(result['providerTLSRequirement']['installed'])
        with self.assertRaises(ValueError): materialize(result, config())

    def test_actual_lua_receipt_crosses_adapter_and_strips_forged_credentials(self):
        engine = run(); receipt = engine.headers[b'x-ouf-semantic-provider-receipt'].decode()
        for key in [b'authorization', b'cookie', b'x-ouf-tenant-id']:
            self.assertNotIn(key, engine.headers)
        incoming = Message(); incoming.add_header(admission.HEADER, receipt)
        incoming.add_header('Content-Type', 'application/x-www-form-urlencoded')
        provider = Mock(return_value=Mock())
        with patch.object(admission.time, 'time', return_value=NOW):
            adapter.dispatch(binding(), 'POST', '/provider/search', incoming, engine.body, provider_search=provider)
        provider.assert_called_once_with(binding().provider, form())

    def test_actual_lua_get_signs_exact_query_and_empty_body(self):
        target = '/provider/fetch?uri=https%3A%2F%2Fvocab.example%2Fclass%2FPlace'
        engine = run(body=b'', target=target, method='GET')
        claims = admission.verify(binding().admission, KEY, engine.headers[b'x-ouf-semantic-provider-receipt'].decode(),
            'GET', target, b'', now=NOW)
        self.assertEqual(claims['requestHash'], admission.request_hash('GET', target, b''))

    def test_actual_lua_rejects_issuer_audience_actor_workload_tenant_scope_time(self):
        changes = {'iss': 'https://foreign.example', 'aud': 'foreign', 'ouf_actor_type': 'HUMAN',
            'azp': 'other', 'tenant_id': 'other', 'scope': 'ouf.semantic.search', 'exp': NOW,
            'iat': NOW+1, 'nbf': NOW+1, 'sub': ''}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(Denied): run(dict(workload(), **{key: value}))
        with self.assertRaises(Denied): run(key='bad-key')

    def test_actual_lua_route_and_body_bounds(self):
        for target in ['/provider/search?endpoint=evil', '/elsewhere']:
            with self.assertRaises(Denied): run(target=target)
        with self.assertRaises(Denied): run(body=b'x'*65537)
        with self.assertRaises(Denied): run(method='GET', target='/provider/fetch?uri=x', body=b'x')

    def test_binding_requires_explicit_safe_paths_tls_and_separate_key(self):
        cases = [('searchPath', '/provider/*'), ('fetchPath', '/provider/search'), ('searchRouteId', 'provider-fetch'),
            ('receiptKeyEnvironment', 'OUF_SEMANTIC_READ_OWNER_KEY'), ('oidcSecretRef', 'inline-secret'),
            ('tenants', []), ('maxRequestBytes', 65537)]
        for key, value in cases:
            cfg = config(); cfg[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): materialize({'routes': []}, cfg)
        for profile in [{'role': 'NORTHBOUND'}, dict(config()['tlsProfile'], mode='DISABLED'),
                        dict(config()['tlsProfile'], trustedCertificateFile='/ca.pem; proxy_ssl_verify off;')]:
            cfg = config(); cfg['tlsProfile'] = profile
            with self.assertRaises(ValueError): materialize({'routes': []}, cfg)


if __name__ == '__main__': unittest.main()
