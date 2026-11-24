"""GW-55L-01…04, PET-gateway-008/043. Offline fixtures shared with the APISIX gate."""
import base64
import copy
import hashlib
import json
import os
import re
import unittest
from contextlib import nullcontext
from email.message import Message
from email.utils import formatdate
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tools.materialize_semantic_provider import _materialize, materialize
from tools.plan_semantic_search import changed_paths, provider_plan, provider_restore_plan
from tools.semantic_provider_quota import provider_quota
from tools import semantic_provider_relay as relay
from tools import semantic_provider_adapter as adapter


VECTOR = json.loads((Path(__file__).resolve().parents[1] / 'contracts/semantic-provider-429-vector-v1.json').read_bytes())
PROOF = 'X-OUF-RateLimit-Attestation'


def provider_binding():
    return dict(installation=VECTOR['installation'], issuer='https://issuer.invalid', audience='resource.invalid',
                workload='client.invalid', scope='provider.read', tenants=['tenant.invalid'],
                searchPath='/provider/search', fetchPath='/provider/fetch', searchRouteId='provider-search',
                fetchRouteId='provider-fetch', receiptKeyEnvironment='FIXTURE_RECEIPT', oidcSecretRef='$ENV://OIDC_SECRET',
                upstream=dict(type='roundrobin', scheme='https', nodes={'adapter.invalid:8443': 1},
                              pass_host='rewrite', upstream_host='adapter.invalid', timeout=dict(connect=1, send=2, read=3)),
                tlsProfile=dict(role='DEDICATED_SOUTHBOUND', mode='NGINX_PROXY_SSL_VERIFY',
                                trustedCertificateFile='/fixture/ca.pem', verifyDepth=2),
                maxRequestBytes=1024, quotaInventory=dict(instances=2, egressKeys=1),
                rateLimit=dict(count=10, time_window=60, key_type='var', key='remote_addr', policy='local', rejected_code=429))


def verified_origin(fields, *, method, target, nonce, now, status=429, installation=VECTOR['installation']):
    """Independent test consumer. Inputs are the actual exchange and the raw response field list."""
    if len(fields) != 1 or status != 429:
        return 'UNKNOWN'
    match = re.fullmatch(r'v1\.(APISIX|UPSTREAM)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.([A-Za-z0-9_-]{86})', fields[0])
    if not match:
        return 'UNKNOWN'
    origin, issued, expiry, encoded = match.groups()
    if not int(issued) <= now < int(expiry) or int(expiry) - int(issued) > 30:
        return 'UNKNOWN'
    message = '\n'.join(('v1', 'semantic-provider-429-origin', method, target, nonce, origin, '429',
                         issued, expiry, installation)).encode('ascii')
    signature = base64.urlsafe_b64decode(encoded + '==')
    if base64.urlsafe_b64encode(signature).decode().rstrip('=') != encoded:
        return 'UNKNOWN'
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(VECTOR['publicKeyHex'])).verify(signature, message)
    except InvalidSignature:
        return 'UNKNOWN'
    return origin


def inventory(routes):
    return {'total': len(routes), 'list': [{'value': r} for r in routes]}


def digest(route):
    return hashlib.sha256(json.dumps(route, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Provider429Test(unittest.TestCase):
    def test_provider_relay_preserves_only_the_single_delay_field(self):
        """GW-55L-02. Exercise the real relay status branch with an in-memory HTTPS response."""
        binding = relay.ProviderBinding('https://provider.invalid/sparql', ('https://terms.invalid/',))
        conn = MagicMock()
        response = conn.getresponse.return_value.__enter__.return_value
        response.status = 429
        for values, expected in ((['007'], '007'), ([], None), (['5', '7'], None), (['5\r\nOther: no'], None)):
            response.headers = Message()
            for v in values:
                response.headers['Retry-After'] = v
            with patch.object(relay, 'request_deadline', return_value=nullcontext()), \
                    patch.object(relay, 'validate_destination', return_value=['peer.invalid']), \
                    patch.object(relay.ipaddress, 'ip_address', return_value=MagicMock(is_global=True)), \
                    patch.object(relay.ssl, 'create_default_context'), self.assertRaises(relay.ProviderRateLimited) as caught:
                relay.exchange(binding, b'', accepted=set(), connection_factory=lambda *args: conn)
            self.assertEqual(expected, caught.exception.retry_after)
            handler = MagicMock(path='/provider/fetch?uri=fixture.invalid', command='GET', headers=Message())
            handler.rfile.read.return_value = b''
            adapter_binding = MagicMock()
            adapter_binding.provider.max_request_bytes = 1024
            with patch.object(adapter, 'dispatch', side_effect=caught.exception):
                adapter.handler_for(adapter_binding).handle_request(handler)
            handler.send_response.assert_called_once_with(429)
            delays = [args.args[1] for args in handler.send_header.call_args_list if args.args[0] == 'Retry-After']
            self.assertEqual(delays, [expected] if expected is not None else [])
        response.read.assert_not_called()
        self.assertEqual(conn.close.call_count, 4)

    def test_vector_and_exchange_binding(self):
        """GW-55L-04. Changing any signed exchange input suppresses origin."""
        proof = VECTOR['attestation']
        args = dict(method=VECTOR['method'], target=VECTOR['target'], nonce=VECTOR['exchangeId'], now=1800000001)
        self.assertEqual('UPSTREAM', verified_origin([proof], **args))
        for changes in (dict(method='POST'), dict(target=args['target'].replace('%2F', '%2f')),
                        dict(installation='other.invalid'), dict(nonce='5'+args['nonce'][1:]),
                        dict(now=1800000030), dict(now=1799999999), dict(status=200)):
            self.assertEqual('UNKNOWN', verified_origin([proof], **(args | changes)))
        for fields in ([], ['APISIX'], [proof, proof], [proof.replace('UPSTREAM', 'APISIX')],
                       [proof.replace('w_Vra', 'a_Vra')], [proof.replace('0030.', '0031.')]):
            self.assertEqual('UNKNOWN', verified_origin(fields, **args))

    def test_local_and_shared_counter_scope(self):
        """GW-55L-03. Exercise each multiplier and bind Redis to its installed scope."""
        binding = provider_binding()
        local = binding['rateLimit']
        for instances, keys in ((2, 1), (1, 2), (2, 2)):
            profile = dict(instances=instances, egressKeys=keys)
            count = 20 // (instances * keys)
            rates = {route: dict(local, count=count) for route in ('search', 'fetch')}
            plan = provider_quota(profile, rates)
            self.assertEqual([20, 20], [plan[k]['total'] for k in rates])
            for route in rates:
                with self.assertRaisesRegex(ValueError, route):
                    provider_quota(profile, rates | {route: dict(local, count=count + 1)})
        backend = dict(redis_host='counter.invalid', redis_port=6379)
        rates = {route: dict(local, policy='redis', group='fixture.invalid.' + route, **backend)
                 for route in ('search', 'fetch')}
        profile = dict(instances=3, egressKeys=2, redisBackend=backend)
        binding.update(quotaInventory=profile, rateLimit=rates)
        result = materialize({'routes': []}, binding)
        self.assertEqual(20, result['providerQuotaPlan']['fetch']['total'])
        self.assertEqual(rates['search'], result['routes'][0]['plugins']['limit-count'])
        for bad in (dict(egressKeys=3), dict(egressKeys=False), dict(ceiling=21), dict(ceiling=19),
                    dict(redisBackend=None), dict(redisBackend=dict(backend, redis_host='other.invalid'))):
            with self.assertRaises(ValueError):
                provider_quota(profile | bad, rates)
        with self.assertRaises(ValueError):
            provider_quota(profile, rates | {'search': dict(rates['search'], time_window=59)})
        with self.assertRaises(ValueError):
            materialize({'routes': []}, {k: v for k, v in binding.items() if k != 'quotaInventory'})

    def test_key_separation(self):
        binding = provider_binding()
        for name in (binding['receiptKeyEnvironment'], 'OUF_GATEWAY_DELEGATION_KEY',
                     'OUF_SEMANTIC_READ_OWNER_KEY', 'OIDC_SECRET'):
            with self.assertRaisesRegex(ValueError, 'dedicated'):
                materialize({'routes': []}, binding | dict(originKeyEnvironment=name))

    def test_exact_predecessor_and_guarded_restore(self):
        binding = provider_binding()
        previous = {k: v for k, v in binding.items() if k != 'quotaInventory'}
        other = dict(id='unchanged', uri='/elsewhere', methods=['POST'])
        old = _materialize({'routes': [other]}, previous, predecessor=True)['routes']
        self.assertEqual([digest(r) for r in old[1:]], [
            '7b6f1ec35fc4d373753d39025ef79537824df5b9e6a414237959fd0a3d2d2068',
            '5fbf7defc5cbb3ecbbccc9e33879108987cad2467785aec811e8cebc1cb3a2c6'])
        desired = materialize({'routes': [other]}, binding)['routes']
        self.assertEqual(old[0], desired[0])
        changes, summary = provider_plan(desired, inventory(old), binding, previous)
        self.assertEqual(summary['search']['total'], 20)
        self.assertEqual(['update', 'update'], [c.action for c in changes])
        for change in changes:
            self.assertEqual(list(changed_paths(change.before, change.after)), [
                '/plugins/serverless-post-function/functions/0', '/plugins/serverless-pre-function/functions/0',
                '/plugins/serverless-pre-function/phase'])
            self.assertNotEqual(digest(change.before), digest(change.after))
        restored = {r['id']: r for r in desired}
        rollback, quota = provider_restore_plan(changes, inventory(desired), binding)
        self.assertEqual(quota, summary)
        for change in rollback:
            restored[change.target_id] = change.after
        self.assertEqual([digest(r) for r in restored.values()], [digest(r) for r in old])
        drift = copy.deepcopy(desired)
        drift[-1]['plugins']['limit-count']['count'] += 1
        with self.assertRaisesRegex(ValueError, 'drift'):
            provider_restore_plan(changes, inventory(drift), binding)
        with self.assertRaisesRegex(ValueError, 'drift'):
            provider_plan(drift, inventory(old), binding, previous)
        with self.assertRaisesRegex(ValueError, 'drift'):
            provider_plan(desired, inventory(drift), binding, previous)
        unsafe = previous | {'rateLimit': dict(previous['rateLimit'], count=20)}
        installed = _materialize({'routes': []}, unsafe, predecessor=True)['routes']
        migration, _ = provider_plan(desired, inventory(installed), binding, unsafe)
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            provider_restore_plan(migration, inventory(desired), binding)


@unittest.skipUnless(os.name == 'posix', 'requires Linux LuaJIT/OpenSSL as in the APISIX image')
class OriginFilterTest(unittest.TestCase):
    def setUp(self):
        from lupa.luajit21 import LuaRuntime
        self.lua = lua = LuaRuntime(encoding='latin-1')
        # Distribution images often ship only the versioned soname (no -dev symlink).
        lua.execute("local ffi = require('ffi') for _, name in ipairs({'crypto', 'libcrypto.so.3'}) do "
                    "if pcall(ffi.load, name, true) then crypto = true break end end "
                    "assert(crypto, 'libcrypto not found')")
        self.headers = lua.table()
        self.request = lua.table_from({'X-OUF-Exchange-Id': VECTOR['exchangeId']})
        self.var = lua.table_from({'request_uri': VECTOR['target']})
        self.ctx = lua.table()
        def captures(value, pattern, flags):
            match = re.search(pattern.replace(r'\z', r'\Z'), value, re.ASCII)
            return lua.table_from(match.groups()) if match else None
        self.now = 1800000000
        lua.globals().ngx = lua.table_from({
            'req': {'get_method': lambda: 'GET', 'get_headers': lambda *args: self.request,
                    'clear_header': lambda name: self.request.__setitem__(name, None)},
            'status': 429, 'header': self.headers, 'var': self.var, 'time': lambda: self.now,
            're': {'find': captures, 'match': captures},
            'http_time': lambda value: formatdate(value, usegmt=True),
            'encode_base64': lambda data: base64.b64encode(data.encode('latin-1')).decode(),
        }, recursive=True)
        binding = provider_binding()
        route = materialize({'routes': []}, binding)['routes'][1]
        self.filter = lua.execute(route['plugins']['serverless-pre-function']['functions'][0])

    def run_filter(self, seed=VECTOR['seedHex']):
        # Only a published test seed enters Lua. No process environment is read.
        self.lua.globals().os.getenv = lambda name: seed
        self.filter(None, self.ctx)
        return self.headers[PROOF]

    def test_local_429_and_missing_evidence(self):
        """GW-55L-01/04. Unknown producer and bad/missing nonce or key stay unsigned."""
        self.headers['X-RateLimit-Origin'] = 'UPSTREAM'
        self.headers[PROOF] = VECTOR['attestation']
        self.assertIsNone(self.run_filter())
        self.assertIsNone(self.headers['X-RateLimit-Origin'])
        for k, v in [('Limit', '10'), ('Remaining', '0'), ('Reset', '12.001')]:
            self.headers['X-RateLimit-' + k] = v
        proof = self.run_filter()
        self.assertEqual('APISIX', verified_origin([proof], method='GET', target=VECTOR['target'],
                                                   nonce=VECTOR['exchangeId'], now=self.now))
        self.assertEqual(self.headers['Retry-After'], '13')
        for seed in (None, 'short'):
            self.assertIsNone(self.run_filter(seed))
            self.assertEqual(self.headers['Retry-After'], '13')
        self.request['x-ouf-exchange-id'] = VECTOR['exchangeId']
        self.assertIsNone(self.run_filter())
        self.request['x-ouf-exchange-id'] = None
        self.ctx.provider_access = True
        self.assertIsNone(self.run_filter())

    def test_upstream_emits_exact_vector_and_preserves_valid_delay(self):
        """GW-55L-02/04. The production Lua signs the fixed bytes using OpenSSL."""
        self.ctx.provider_access = self.ctx.provider_forwarded = True
        self.ctx.provider_exchange = VECTOR['exchangeId']
        self.var.upstream_addr, self.var.upstream_status = 'adapter.invalid:8443', '429'
        valid = ('0007', 'Sun, 06 Nov 1994 08:49:37 GMT', 'Sunday, 06-Nov-94 08:49:37 GMT',
                 'Sun Nov  6 08:49:37 1994', 'Sun, 06 Nov 1960 08:49:37 GMT')
        for delay in (*valid, '4.5', '7, 8', 'Sun, 06 Nov 1994 08:49:37 GMT junk',
                      'Sun, 31 Feb 1994 08:49:37 GMT', None):
            self.headers['Retry-After'] = delay
            self.assertEqual(VECTOR['attestation'], self.run_filter())
            self.assertEqual(delay if delay in valid else None, self.headers['Retry-After'])
        self.var.upstream_status = '502, 429'
        self.assertIsNone(self.run_filter())
