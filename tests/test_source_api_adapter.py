"""Task-61f-a: Gateway southbound `fetch` adapter for ouf.vertical-source.v1.

Real TLS (ephemeral CA, SNI and name verification) towards a fictitious vertical on loopback,
with DNS answers and the approved address injected. Every SSRF vector is refused before any
connection; the error table of ouf.source-api.v1 section 2.2 is exercised row by row.
"""
import copy
import fcntl
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time

import jsonschema
import pytest

from tests import source_api_vertical_fixture as fx
from tools import source_api_adapter as sa

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas' / 'source-api-binding-registry-v1.json').read_text(encoding='utf-8'))
EXAMPLE = ROOT / 'tests' / 'fixtures' / 'source-api-binding-registry-example.json'
SENTINEL = 'sentinel-bearer-61fa-0123456789abcdef'
KEY = '0123456789abcdef' * 4
REF = 'gateway://sources/vertical-lab'
RESTRICTED = 'gateway://sources/vertical-restricted'
ADMISSION = sa.Admission('lab-installation', 'https://iam.example.invalid/realms/ouf', 'ouf-gateway',
                         'ouf.source.api.fetch', {'INGESTION': 'ouf-ingestion', 'ONBOARDING': 'ouf-onboarding'})
PATH = '/internal/sources/v1/fetch'


def binding(ref=REF, **changes):
    value = {'bindingRef': ref, 'title': 'Verticale di prova', 'contract': 'ouf.vertical-source.v1',
             'origin': 'https://%s:%d' % (fx.HOST, fx.PORT), 'allowedNetworks': ['192.0.2.0/24'],
             'credentialRef': 'secret://vertical-read', 'trustRef': 'trust://vertical-ca',
             'tenants': ['tenant-a'], 'collections': ['*'],
             'limits': {'maxPageBytes': 65536, 'timeout': 'PT2S', 'maxRequestsPerMinute': 600, 'maxConcurrency': 4},
             'status': 'ACTIVE'}
    value.update(changes)
    return value


def registry(*bindings):
    return {'schema': 'ouf.source-api-binding-registry.v1', 'revision': 1,
            'bindings': list(bindings) or [binding(), binding(RESTRICTED, collections=['edicole'])]}


def private(path, data):
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)
    return path


class Env:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        (tmp_path / 'pki').mkdir()
        self.vertical = fx.FakeVertical(tmp_path / 'pki')
        self.network = fx.Network(self.vertical)
        for name in ('secrets', 'trust', 'state'):
            (tmp_path / name).mkdir(mode=0o700)
        private(tmp_path / 'secrets' / 'vertical-read', SENTINEL + '\n')
        (tmp_path / 'trust' / 'vertical-ca').write_bytes(self.vertical.ca_file.read_bytes())
        self.write_registry(registry())
        self.config = sa.AdapterConfiguration(PATH, ADMISSION, KEY, str(tmp_path / 'registry.json'),
                                              str(tmp_path / 'secrets'), str(tmp_path / 'trust'),
                                              str(tmp_path / 'state'), 10)
        self.config.validate()
        self.clock = [1_800_000_000.0]
        self.limiter = sa.BindingLimiter(str(tmp_path / 'state'), clock=lambda: self.clock[0])

    def write_registry(self, document):
        private(self.tmp / 'registry.json', json.dumps(document))

    def body(self, parameters, ref=REF, correlation='3f2c8a0e-6d2b-4c47-9a51-0a1b2c3d4e5f'):
        return json.dumps({'bindingRef': ref, 'parameters': parameters, 'correlationId': correlation}).encode()

    def headers(self, body, *, role='INGESTION', tenant='tenant-a', claims=None, receipt=None, extra=()):
        message = http.client.HTTPMessage()
        message['Content-Type'] = 'application/json'
        now = int(time.time())
        value = {'purpose': sa.PURPOSE, 'installation': ADMISSION.installation, 'issuer': ADMISSION.issuer,
                 'audience': ADMISSION.audience, 'workload': ADMISSION.workloads[role], 'tenant': tenant,
                 'subject': 'service-account-' + role.lower(), 'actor': 'SERVICE', 'scope': ADMISSION.scope,
                 'requestHash': sa.request_hash('POST', PATH, body), 'iat': now, 'exp': now + 30}
        value.update(claims or {})
        message[sa.HEADER] = receipt if receipt is not None else sa.sign_receipt(KEY, value)
        for name, item in extra:
            message[name] = item
        return message

    def call(self, parameters, ref=REF, *, body=None, **options):
        body = self.body(parameters, ref) if body is None else body
        headers = options.pop('headers', None) or self.headers(body, **options)
        return sa.dispatch(self.config, 'POST', PATH, headers, body, resolver=self.network.resolver,
                           connection_factory=self.network.connection_factory, limiter=self.limiter)

    def failure(self, parameters, ref=REF, **options):
        with pytest.raises(sa.SourceFailure) as caught:
            self.call(parameters, ref, **options)
        return caught.value


@pytest.fixture
def env(tmp_path):
    value = Env(tmp_path)
    yield value
    value.vertical.close()


def items_parameters(**extra):
    return {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'CURSOR', 'limit': 100, **extra}


# --- registry ---------------------------------------------------------------------------

def test_example_registry_is_valid_and_fictitious():
    raw = EXAMPLE.read_bytes()
    jsonschema.Draft202012Validator(SCHEMA).validate(json.loads(raw))
    revision, bindings = sa.load_registry(raw)
    assert revision == 1 and set(bindings) == {'gateway://sources/vertical-mock'}
    text = raw.decode()
    assert 'example.invalid' in text and '192.0.2.0/24' in text  # D-058: placeholders only


REGISTRY_VARIANTS = [
    ('extra binding key', lambda r: r['bindings'][0].update(endpoint='https://x.example.invalid')),
    ('missing limits', lambda r: r['bindings'][0].pop('limits')),
    ('bad ref', lambda r: r['bindings'][0].update(bindingRef='gateway://sources/../x')),
    ('http origin', lambda r: r['bindings'][0].update(origin='http://vertical.example.invalid')),
    ('origin with path', lambda r: r['bindings'][0].update(origin='https://vertical.example.invalid/api')),
    ('origin with credentials', lambda r: r['bindings'][0].update(origin='https://u:p@vertical.example.invalid')),
    ('uppercase host', lambda r: r['bindings'][0].update(origin='https://Vertical.example.invalid')),
    ('no networks', lambda r: r['bindings'][0].update(allowedNetworks=[])),
    ('file credential path', lambda r: r['bindings'][0].update(credentialRef='secret://../etc/passwd')),
    ('plain credential', lambda r: r['bindings'][0].update(credentialRef='Bearer abc')),
    ('mixed wildcard', lambda r: r['bindings'][0].update(collections=['*', 'edicole'])),
    ('bad collection', lambda r: r['bindings'][0].update(collections=['Edicole'])),
    ('timeout too long', lambda r: r['bindings'][0]['limits'].update(timeout='PT61S')),
    ('page too large', lambda r: r['bindings'][0]['limits'].update(maxPageBytes=50000001)),
    ('concurrency', lambda r: r['bindings'][0]['limits'].update(maxConcurrency=0)),
    ('status', lambda r: r['bindings'][0].update(status='ENABLED')),
    ('contract', lambda r: r['bindings'][0].update(contract='ouf.vertical-source.v2')),
    ('schema', lambda r: r.update(schema='ouf.source-api-binding-registry.v2')),
    ('revision', lambda r: r.update(revision=0)),
    ('tenant control', lambda r: r['bindings'][0].update(tenants=['tenant\na'])),
]


@pytest.mark.parametrize('name,change', REGISTRY_VARIANTS, ids=[v[0] for v in REGISTRY_VARIANTS])
def test_schema_rejection_implies_code_rejection(name, change):
    document = registry(binding())
    change(document)
    assert not jsonschema.Draft202012Validator(SCHEMA).is_valid(document), name
    with pytest.raises(sa.ConfigurationDenied):
        sa.load_registry(json.dumps(document).encode())


@pytest.mark.parametrize('change,code', [
    (lambda r: r['bindings'][0].update(allowedNetworks=['192.0.2.1/24']), 'BINDING_NETWORKS_INVALID'),
    (lambda r: r['bindings'][0].update(allowedNetworks=['300.0.0.0/8']), 'BINDING_NETWORKS_INVALID'),
    (lambda r: r['bindings'][0].update(credentialRef='workload://vertical-read'), 'CREDENTIAL_PROVIDER_UNAVAILABLE'),
    (lambda r: r['bindings'].append(copy.deepcopy(r['bindings'][0])), 'REGISTRY_DUPLICATE_BINDING'),
    # JSON Schema 2020-12 treats 60.0 as an integer; the adapter accepts only JSON integers.
    (lambda r: r['bindings'][0]['limits'].update(maxRequestsPerMinute=60.0), 'BINDING_LIMITS_INVALID'),
])
def test_code_is_stricter_than_schema_where_json_schema_cannot_express_it(change, code):
    document = registry(binding())
    change(document)
    with pytest.raises(sa.ConfigurationDenied, match=code):
        sa.load_registry(json.dumps(document).encode())


def test_registry_rejects_duplicate_keys_and_non_finite_numbers():
    raw = json.dumps(registry(binding())).encode()
    with pytest.raises(sa.ConfigurationDenied):
        sa.load_registry(raw.replace(b'"revision": 1', b'"revision": 1, "revision": 2'))
    with pytest.raises(sa.ConfigurationDenied):
        sa.load_registry(raw.replace(b'"revision": 1', b'"revision": NaN'))


# --- happy paths ------------------------------------------------------------------------

def upstream(env):
    assert len(env.vertical.requests) == 1
    return env.vertical.requests[0]


def test_items_cursor_reaches_registered_origin_with_bearer_and_bytes_unchanged(env):
    reply = fx.Reply.json(fx.items())
    env.vertical.plan = lambda path: reply
    result = env.call(items_parameters(cursor='eyJzIjoxfQ.c2ln'))
    assert result.status == 200 and result.body == reply.body
    assert result.headers['X-Ouf-Source-Schema-Version'] == fx.EDICOLE
    assert result.headers['X-Ouf-Source-Epoch'] == fx.EPOCH
    request = upstream(env)
    assert request['path'] == '/collections/edicole/items?mode=CURSOR&limit=100&cursor=eyJzIjoxfQ.c2ln'
    headers = dict(request['headers'])
    assert headers['authorization'] == 'Bearer ' + SENTINEL
    assert headers['host'] == '%s:%d' % (fx.HOST, fx.PORT)
    assert set(headers) == {'host', 'accept', 'accept-encoding', 'authorization', 'user-agent'}
    assert env.network.lookups == [(fx.HOST, fx.PORT)]
    assert env.network.connections == [(fx.HOST, fx.PORT, fx.ADDRESS)]


def test_onboarding_and_ingestion_read_catalog_and_schema(env):
    for role in ('INGESTION', 'ONBOARDING'):
        catalog = env.call({'resource': 'COLLECTIONS'}, role=role)
        assert json.loads(catalog.body) == fx.catalog() and 'X-Ouf-Catalog-Filtered' not in catalog.headers
        schema = env.call({'resource': 'SCHEMA', 'collection': 'musei'}, role=role)
        assert json.loads(schema.body)['schemaVersion'] == fx.MUSEI
        assert schema.headers['X-Ouf-Source-Schema-Version'] == fx.MUSEI
    assert [r['path'] for r in env.vertical.requests] == ['/collections', '/collections/musei/schema'] * 2


def test_watermark_and_snapshot_queries_follow_the_closed_templates(env):
    env.call({'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK',
              'changedSince': '2026-11-24T22:05:00.123456789Z', 'afterId': 'E 0/1?à'})
    env.call({'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK', 'cursor': 'abc.def'})
    env.call({'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'SNAPSHOT', 'page': 'p-1', 'limit': 1000})
    env.call({'resource': 'ITEMS', 'collection': 'edicole'})
    assert [r['path'] for r in env.vertical.requests] == [
        '/collections/edicole/items?mode=WATERMARK&changedSince=2026-11-24T22%3A05%3A00.123456789Z'
        '&afterId=E%200%2F1%3F%C3%A0',
        '/collections/edicole/items?mode=WATERMARK&cursor=abc.def',
        '/collections/edicole/items?mode=SNAPSHOT&limit=1000&page=p-1',
        '/collections/edicole/items',
    ]


def test_restricted_binding_filters_catalog_and_recomputes_digest(env):
    result = env.call({'resource': 'COLLECTIONS'}, RESTRICTED)
    document = json.loads(result.body)
    assert [c['collection'] for c in document['collections']] == ['edicole']
    expected = hashlib.sha256(b'[["edicole","' + fx.EDICOLE.encode() + b'"]]').hexdigest()
    assert document['schemaVersion'] == expected == result.headers['X-Ouf-Source-Schema-Version']
    assert result.headers['X-Ouf-Catalog-Filtered'] == 'true'
    assert document['epoch'] == fx.EPOCH
    assert env.failure({'resource': 'SCHEMA', 'collection': 'musei'}, RESTRICTED).code == 'SOURCE_BINDING_NOT_ALLOWED'


def test_catalog_digest_matches_the_mock_rule_for_the_full_catalog():
    pairs = [['musei', fx.MUSEI], ['edicole', fx.EDICOLE]]
    assert sa.catalog_digest(pairs) == fx.catalog()['schemaVersion']


# --- SSRF and grammar: refused before any connection -----------------------------------

SSRF_VECTORS = [
    ('dot-dot collection', {'resource': 'SCHEMA', 'collection': '../admin'}),
    ('encoded slash', {'resource': 'SCHEMA', 'collection': 'edicole%2F..%2Fadmin'}),
    ('admin path', {'resource': 'SCHEMA', 'collection': '/admin'}),
    ('admin segment', {'resource': 'ITEMS', 'collection': 'admin/expected'}),
    ('host in collection', {'resource': 'SCHEMA', 'collection': 'evil.example.invalid'}),
    ('uppercase collection', {'resource': 'SCHEMA', 'collection': 'Edicole'}),
    ('unknown resource', {'resource': 'ADMIN'}),
    ('free path', {'resource': 'ITEMS', 'collection': 'edicole', 'path': '/admin/reset'}),
    ('free url', {'resource': 'COLLECTIONS', 'url': 'https://evil.example.invalid/'}),
    ('caller headers', {'resource': 'COLLECTIONS', 'headers': {'Authorization': 'Bearer x'}}),
    ('crlf in token', items_parameters(cursor='abc\r\nX-Injected: 1')),
    ('url in token', items_parameters(cursor='https://evil.example.invalid/x')),
    ('query delimiter in token', items_parameters(cursor='a&admin=1')),
    ('percent in token', items_parameters(cursor='a%2Fadmin')),
    ('fragment in token', items_parameters(cursor='a#b')),
    ('space in token', items_parameters(cursor='a b')),
    ('control in afterId', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK',
                            'changedSince': '2026-11-24T22:05:00Z', 'afterId': 'E\u0000'}),
    ('afterId without changedSince', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK',
                                      'cursor': 'a', 'afterId': 'E'}),
    ('watermark both positions', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK',
                                  'cursor': 'a', 'changedSince': '2026-11-24T22:05:00Z'}),
    ('watermark no position', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK'}),
    ('bad changedSince', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK',
                          'changedSince': '24/11/2026'}),
    ('cursor in snapshot', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'SNAPSHOT', 'cursor': 'a'}),
    ('page in cursor', items_parameters(page='p')),
    ('position without mode', {'resource': 'ITEMS', 'collection': 'edicole', 'cursor': 'a'}),
    ('null mode', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': None}),
    ('limit zero', items_parameters(limit=0)),
    ('limit over', items_parameters(limit=1001)),
    ('limit text', items_parameters(limit='100')),
    ('limit bool', items_parameters(limit=True)),
    ('collection on catalog', {'resource': 'COLLECTIONS', 'collection': 'edicole'}),
    ('mode on schema', {'resource': 'SCHEMA', 'collection': 'edicole', 'mode': 'CURSOR'}),
    # Review 61f-a: wrong JSON types are grammar errors (400), never a transient adapter failure.
    ('resource list', {'resource': ['ITEMS']}),
    ('resource object', {'resource': {'ITEMS': True}}),
    ('mode list', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': ['CURSOR']}),
    ('lone surrogate in afterId', {'resource': 'ITEMS', 'collection': 'edicole', 'mode': 'WATERMARK',
                                   'changedSince': '2026-11-24T22:05:00Z', 'afterId': '\ud800'}),
]


@pytest.mark.parametrize('name,parameters', SSRF_VECTORS, ids=[v[0] for v in SSRF_VECTORS])
def test_grammar_vectors_are_refused_before_any_connection(env, name, parameters):
    failure = env.failure(parameters)
    assert failure.code == 'SOURCE_REQUEST_INVALID' and failure.status == 400
    assert env.vertical.requests == [] and env.network.lookups == [] and env.network.connections == []


@pytest.mark.parametrize('ref', ['gateway://sources/../admin', 'https://evil.example.invalid/', 'gateway://sources/',
                                 'gateway://sources/vertical-lab/admin', 'gateway://sources/Vertical'])
def test_binding_reference_vectors_are_refused(env, ref):
    assert env.failure({'resource': 'COLLECTIONS'}, ref).code == 'SOURCE_REQUEST_INVALID'
    assert env.vertical.requests == [] and env.network.lookups == []


@pytest.mark.parametrize('body', [
    b'{"bindingRef":"gateway://sources/vertical-lab","parameters":{"resource":"COLLECTIONS"}}',
    b'{"bindingRef":"gateway://sources/vertical-lab","parameters":{"resource":"COLLECTIONS"},"correlationId":"a",'
    b'"bindingRef":"gateway://sources/other"}',
    b'{"bindingRef":"gateway://sources/vertical-lab","parameters":{"resource":"ITEMS","collection":"edicole",'
    b'"limit":1.0},"correlationId":"a"}',
    b'{"bindingRef":"gateway://sources/vertical-lab","parameters":{"resource":"COLLECTIONS"},"correlationId":"a\\nb"}',
    b'[]', b'not json', b'{"bindingRef":"gateway://sources/vertical-lab","parameters":{"resource":"COLLECTIONS"},'
                       b'"correlationId":"a","target":"https://evil.example.invalid"}',
])
def test_malformed_bodies_are_refused(env, body):
    assert env.failure(None, body=body).code == 'SOURCE_REQUEST_INVALID'
    assert env.vertical.requests == []


def test_deeply_nested_json_is_malformed_input_not_an_adapter_failure():
    with pytest.raises(ValueError, match='JSON_TOO_DEEP'):
        sa.strict_json(b'[' * 100000 + b']' * 100000)


def test_tokens_are_opaque_query_values_that_never_change_path_or_host(env):
    env.call(items_parameters(cursor='../../admin/reset'))
    env.call(items_parameters(cursor='evil.example.invalid'))
    paths = [r['path'] for r in env.vertical.requests]
    assert paths == ['/collections/edicole/items?mode=CURSOR&limit=100&cursor=..%2F..%2Fadmin%2Freset',
                     '/collections/edicole/items?mode=CURSOR&limit=100&cursor=evil.example.invalid']
    assert env.network.lookups == [(fx.HOST, fx.PORT)] * 2


@pytest.mark.parametrize('answers,log', [
    (['203.0.113.7'], 'EGRESS_DNS_REBINDING_OR_CIDR_MISMATCH'),
    (['192.0.2.10', '198.51.100.9'], 'EGRESS_DNS_REBINDING_OR_CIDR_MISMATCH'),
    (['127.0.0.1'], 'EGRESS_FORBIDDEN_ADDRESS_CLASS'),
    (['169.254.169.254'], 'EGRESS_FORBIDDEN_ADDRESS_CLASS'),
    ([], 'EGRESS_DNS_RESOLUTION_EMPTY'),
    (['::1'], 'EGRESS_FORBIDDEN_ADDRESS_CLASS'),
    (['::ffff:127.0.0.1'], 'EGRESS_FORBIDDEN_ADDRESS_CLASS'),
    (['fe80::1'], 'EGRESS_FORBIDDEN_ADDRESS_CLASS'),
])
def test_dns_answers_outside_the_binding_networks_never_connect(env, answers, log):
    env.network.answers = {fx.HOST: answers}
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log == log
    assert env.network.connections == [] and env.vertical.requests == []


def test_ipv4_mapped_answer_of_an_allowed_address_never_connects(env):
    # An IPv6 form of an approved IPv4 address is outside the IPv4 networks of the binding.
    env.network.answers = {fx.HOST: ['::ffff:' + fx.ADDRESS]}
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log.startswith('EGRESS_')
    assert env.network.connections == [] and env.vertical.requests == []


def test_tls_name_is_verified_even_with_the_trusted_ca(env):
    # Same trusted CA, but the registered host differs from the certificate name.
    other = 'other.example.invalid'
    env.write_registry(registry(binding(origin='https://%s:%d' % (other, fx.PORT))))
    env.network.answers = {other: [fx.ADDRESS]}
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log == 'TLS_REJECTED'
    assert env.network.connections == [(other, fx.PORT, fx.ADDRESS)] and env.vertical.requests == []


def test_tls_name_verification_and_trust_anchor_are_enforced(env, tmp_path):
    other = tmp_path / 'other-pki'
    other.mkdir()
    ca, _, _ = fx.make_pki(other, 'other.example.invalid')
    (tmp_path / 'trust' / 'vertical-ca').write_bytes(ca.read_bytes())
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log == 'TLS_REJECTED'
    assert env.vertical.requests == []


# --- admission ----------------------------------------------------------------------------

def test_not_allowed_is_identical_for_unknown_inactive_foreign_and_out_of_scope(env, monkeypatch):
    env.write_registry(registry(binding(), binding('gateway://sources/vertical-off', status='INACTIVE'),
                                binding(RESTRICTED, collections=['edicole'])))
    reads = []
    original = sa.AdapterConfiguration.credential
    monkeypatch.setattr(sa.AdapterConfiguration, 'credential', lambda self, b: reads.append(b) or original(self, b))
    answers = [
        env.failure({'resource': 'COLLECTIONS'}, 'gateway://sources/vertical-unknown'),
        env.failure({'resource': 'COLLECTIONS'}, 'gateway://sources/vertical-off'),
        env.failure({'resource': 'COLLECTIONS'}, tenant='tenant-b'),
        env.failure({'resource': 'ITEMS', 'collection': 'musei'}, RESTRICTED),
        env.failure(items_parameters(), role='ONBOARDING'),
    ]
    assert {(a.status, a.body()) for a in answers} == {(403, b'{"code":"SOURCE_BINDING_NOT_ALLOWED"}')}
    assert reads == [] and env.vertical.requests == [] and env.network.lookups == []


@pytest.mark.parametrize('case', ['missing', 'double', 'signature', 'expired', 'long', 'purpose', 'body', 'actor',
                                  'workload', 'scope', 'audience', 'installation', 'bearer'])
def test_receipt_failures_stop_before_grammar_and_transport(env, case):
    body = env.body({'resource': 'COLLECTIONS'})
    now = int(time.time())
    if case == 'missing':
        headers = env.headers(body)
        del headers[sa.HEADER]
    elif case == 'double':
        headers = env.headers(body)
        headers[sa.HEADER] = headers[sa.HEADER]
    elif case == 'signature':
        good = env.headers(body)[sa.HEADER]
        headers = env.headers(body, receipt=good[:-1] + ('0' if good[-1] != '0' else '1'))
    elif case == 'bearer':
        headers = env.headers(body, extra=[('Authorization', 'Bearer caller-token')])
    else:
        claims = {'expired': {'iat': now - 60, 'exp': now - 30}, 'long': {'iat': now, 'exp': now + 31},
                  'purpose': {'purpose': 'ouf-semantic-provider-owner-v1'},
                  'body': {'requestHash': sa.request_hash('POST', PATH, body + b' ')},
                  'actor': {'actor': 'HUMAN'}, 'workload': {'workload': 'ouf-mcp-server'},
                  'scope': {'scope': 'ouf.semantic.read'}, 'audience': {'audience': 'other'},
                  'installation': {'installation': 'other-installation'}}[case]
        headers = env.headers(body, claims=claims)
    failure = env.failure(None, body=body, headers=headers)
    assert failure.code == 'SOURCE_ADMISSION_DENIED' and failure.status == 403
    assert env.vertical.requests == [] and env.network.lookups == []


def test_semantic_provider_receipt_cannot_be_replayed_here(env):
    body = env.body({'resource': 'COLLECTIONS'})
    import base64, hmac
    head = env.headers(body)[sa.HEADER].split('.')[0]
    claims = json.loads(base64.urlsafe_b64decode(head + '=' * (-len(head) % 4)))
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    other = encoded + '.' + hmac.new(KEY.encode(), ('ouf-semantic-provider-owner-v1.' + encoded).encode(),
                                     hashlib.sha256).hexdigest()
    assert env.failure(None, body=body, headers=env.headers(body, receipt=other)).code == 'SOURCE_ADMISSION_DENIED'


# --- error table (ouf.source-api.v1 section 2.2) -----------------------------------------

def error(status, code, version=fx.EDICOLE, headers=(), **fields):
    return fx.Reply.json({'code': code, 'message': 'fixed', 'schemaVersion': version, **fields}, status=status,
                         headers=list(headers))


@pytest.mark.parametrize('reply,expected', [
    (error(410, 'CURSOR_EXPIRED', reason='RETENTION'),
     {'code': 'SOURCE_CURSOR_EXPIRED', 'reason': 'RETENTION', 'schemaVersion': fx.EDICOLE}),
    (error(410, 'CURSOR_EXPIRED', reason='EPOCH_CHANGED', epoch='ffeeddccbbaa99887766554433221100'),
     {'code': 'SOURCE_CURSOR_EXPIRED', 'reason': 'EPOCH_CHANGED', 'schemaVersion': fx.EDICOLE,
      'epoch': 'ffeeddccbbaa99887766554433221100'}),
    (error(429, 'RATE_LIMITED', headers=[('Retry-After', '17')]),
     {'code': 'SOURCE_RATE_LIMITED', 'schemaVersion': fx.EDICOLE, 'retryAfter': 17}),
    (error(429, 'RATE_LIMITED', headers=[('Retry-After', 'Wed, 21 Oct 2026 07:28:00 GMT')]),
     {'code': 'SOURCE_RATE_LIMITED', 'schemaVersion': fx.EDICOLE}),
    (error(503, 'SOURCE_UNAVAILABLE', headers=[('Retry-After', '5')]),
     {'code': 'SOURCE_UNAVAILABLE', 'schemaVersion': fx.EDICOLE, 'retryAfter': 5}),
    (error(503, 'SOURCE_UNAVAILABLE'), {'code': 'SOURCE_UNAVAILABLE', 'schemaVersion': fx.EDICOLE}),
    (fx.Reply.json({'code': 'UNAUTHENTICATED'}, status=401), {'code': 'SOURCE_CREDENTIAL_REJECTED'}),
    (fx.Reply.json({'code': 'FORBIDDEN'}, status=403), {'code': 'SOURCE_CREDENTIAL_REJECTED'}),
    (error(400, 'INVALID_POSITION'),
     {'code': 'SOURCE_REQUEST_REJECTED', 'reason': 'INVALID_POSITION', 'schemaVersion': fx.EDICOLE}),
    (error(404, 'UNKNOWN_COLLECTION'),
     {'code': 'SOURCE_REQUEST_REJECTED', 'reason': 'UNKNOWN_COLLECTION', 'schemaVersion': fx.EDICOLE}),
    # Review 61f-a: an error body over 64 KiB is discarded, the status mapping still applies.
    (error(410, 'CURSOR_EXPIRED', reason='RETENTION', padding='x' * 70000),
     {'code': 'SOURCE_CURSOR_EXPIRED', 'schemaVersion': fx.EDICOLE}),
    (fx.Reply(500, b'boom'), {'code': 'SOURCE_UNAVAILABLE'}),
    (fx.Reply(302, b'', [('Location', 'https://evil.example.invalid/admin')]), {'code': 'SOURCE_RESPONSE_INVALID'}),
])
def test_source_errors_map_to_the_typed_table(env, reply, expected):
    env.vertical.plan = lambda path: reply
    failure = env.failure(items_parameters(cursor='a'))
    assert json.loads(failure.body()) == expected
    assert failure.status == sa.SourceFailure.STATUS[expected['code']]
    assert len(env.vertical.requests) == 1  # one attempt, redirects never followed
    if 'retryAfter' in expected:
        assert failure.headers() == {'Retry-After': str(expected['retryAfter'])}


def test_deadline_bounds_a_slow_source(env):
    env.vertical.plan = lambda path: fx.Reply.json(fx.items(), delay=3.5)
    started = time.monotonic()
    failure = env.failure(items_parameters())
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log == 'DEADLINE_EXCEEDED'
    assert time.monotonic() - started < 3.0  # binding timeout PT2S covers DNS, TLS and body


@pytest.mark.parametrize('mode', ['normal', 'chunked'])
def test_page_at_the_limit_passes_and_limit_plus_one_fails_without_partial_body(env, mode):
    envelope = fx.items(count=0)
    base = json.dumps(envelope, separators=(',', ':')).encode()
    limit = 65536
    padded = dict(envelope, padding='x' * (limit - len(base) - len(',"padding":""')))
    body = json.dumps(padded, separators=(',', ':')).encode()
    assert len(body) == limit
    headers = [('Content-Type', 'application/json'), ('X-Schema-Version', fx.EDICOLE)]
    env.vertical.plan = lambda path: fx.Reply(200, body, headers, mode=mode)
    assert env.call(items_parameters()).body == body
    over = json.dumps(dict(padded, padding=padded['padding'] + 'y'), separators=(',', ':')).encode()
    env.vertical.plan = lambda path: fx.Reply(200, over, headers, mode=mode)
    failure = env.failure(items_parameters())
    assert failure.code == 'SOURCE_RESPONSE_TOO_LARGE' and failure.status == 502
    assert failure.body() == b'{"code":"SOURCE_RESPONSE_TOO_LARGE"}'


@pytest.mark.parametrize('mode,log', [('incomplete', 'RESPONSE_INCOMPLETE'), ('chunked-incomplete', 'TRANSPORT_FAILED')])
def test_incomplete_response_is_unavailable(env, mode, log):
    env.vertical.plan = lambda path: fx.Reply.json(fx.items(), mode=mode)
    failure = env.failure(items_parameters())
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log == log
    assert failure.body() == b'{"code":"SOURCE_UNAVAILABLE"}'


@pytest.mark.parametrize('reply,log', [
    (fx.Reply(200, json.dumps(fx.items()).encode(), [('Content-Type', 'application/json')]), None),
    (fx.Reply(200, json.dumps({k: v for k, v in fx.items().items() if k != 'schemaVersion'}).encode(),
              [('Content-Type', 'application/json')]), 'SCHEMA_VERSION_REJECTED'),
    (fx.Reply.json(fx.items(), version='d' * 64), 'SCHEMA_VERSION_REJECTED'),
    (fx.Reply(200, json.dumps(fx.items()).encode(), [('Content-Type', 'text/html')]), 'MEDIA_REJECTED'),
    (fx.Reply(200, b'{"schemaVersion":"' + fx.EDICOLE.encode() + b'","schemaVersion":"x"}',
              [('Content-Type', 'application/json')]), 'JSON_REJECTED'),
    (fx.Reply.json(fx.items(collection='musei')), 'COLLECTION_MISMATCH'),
    (fx.Reply.json(dict(fx.items(), epoch='bad epoch')), 'EPOCH_REJECTED'),
    (fx.Reply(200, json.dumps(fx.items()).encode(), [('Content-Type', 'application/json'),
                                                     ('Content-Encoding', 'gzip')]), 'ENCODING_REJECTED'),
])
def test_success_responses_must_declare_a_consistent_schema_version(env, reply, log):
    env.vertical.plan = lambda path: reply
    if log is None:
        assert env.call(items_parameters()).headers['X-Ouf-Source-Schema-Version'] == fx.EDICOLE
        return
    failure = env.failure(items_parameters())
    assert failure.code == 'SOURCE_RESPONSE_INVALID' and failure.log == log


# --- limits -------------------------------------------------------------------------------

def test_rate_limit_per_binding_with_retry_after(env):
    env.write_registry(registry(binding(limits={'maxPageBytes': 65536, 'timeout': 'PT2S',
                                                'maxRequestsPerMinute': 3, 'maxConcurrency': 4})))
    for _ in range(3):
        env.call({'resource': 'COLLECTIONS'})
        env.clock[0] += 1
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_RATE_LIMITED' and failure.status == 429 and failure.retry_after == 57
    assert len(env.vertical.requests) == 3
    env.clock[0] += 57
    env.call({'resource': 'COLLECTIONS'})
    assert len(env.vertical.requests) == 4


def test_concurrency_limit_is_shared_across_workers(env):
    env.write_registry(registry(binding(limits={'maxPageBytes': 65536, 'timeout': 'PT2S',
                                                'maxRequestsPerMinute': 600, 'maxConcurrency': 2})))
    key = hashlib.sha256(REF.encode()).hexdigest()[:32]
    held = []
    for index in range(2):  # another forked worker holds both slots
        fd = os.open(os.path.join(env.config.state_directory, key + '.slot' + str(index)), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held.append(fd)
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.retry_after == 1 and env.vertical.requests == []
    os.close(held.pop())
    env.call({'resource': 'COLLECTIONS'})
    os.close(held.pop())


def test_registry_rotation_and_revocation_apply_to_the_next_request(env):
    env.call({'resource': 'COLLECTIONS'})
    env.write_registry(registry(binding(status='INACTIVE')))
    assert env.failure({'resource': 'COLLECTIONS'}).code == 'SOURCE_BINDING_NOT_ALLOWED'
    private(env.tmp / 'secrets' / 'vertical-read', 'rotated-bearer-61fa-fedcba9876543210')
    env.write_registry(registry(binding()))
    env.call({'resource': 'COLLECTIONS'})
    assert dict(env.vertical.requests[-1]['headers'])['authorization'] == 'Bearer rotated-bearer-61fa-fedcba9876543210'
    env.write_registry({'schema': 'broken'})
    assert env.failure({'resource': 'COLLECTIONS'}).log == 'REGISTRY_UNAVAILABLE'


@pytest.mark.parametrize('damage', ['mode', 'symlink', 'missing', 'malformed'])
def test_credential_must_be_a_private_custodian_file(env, damage):
    path = env.tmp / 'secrets' / 'vertical-read'
    if damage == 'mode':
        path.chmod(0o640)
    elif damage == 'symlink':
        target = private(env.tmp / 'elsewhere', SENTINEL)
        path.unlink()
        path.symlink_to(target)
    elif damage == 'missing':
        path.unlink()
    else:
        private(path, 'short')
    failure = env.failure({'resource': 'COLLECTIONS'})
    assert failure.code == 'SOURCE_UNAVAILABLE' and failure.log == 'CREDENTIAL_UNAVAILABLE'
    assert env.vertical.requests == [] and env.network.lookups == []


# --- process boundary: server, logs and secrets -------------------------------------------



@pytest.fixture
def adapter(env, tmp_path):
    (tmp_path / 'adapter-pki').mkdir()
    ca, cert, key = fx.make_pki(tmp_path / 'adapter-pki', 'source-adapter.example.invalid')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    log = tmp_path / 'adapter.log'
    stream = open(log, 'a', buffering=1, encoding='utf-8')
    server = sa.BoundedTLSServer(('127.0.0.1', 0), env.config, context, 4, log_stream=stream,
                                 resolver=env.network.resolver, connection_factory=env.network.connection_factory)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = ssl.create_default_context(cafile=str(ca))

    def post(body, headers):
        connection = http.client.HTTPSConnection('source-adapter.example.invalid', server.server_address[1],
                                                 context=client, timeout=10)
        connection.sock = client.wrap_socket(socket.create_connection(('127.0.0.1', server.server_address[1])),
                                             server_hostname='source-adapter.example.invalid')
        connection.request('POST', PATH, body=body, headers=dict(headers.items()))
        response = connection.getresponse()
        value = (response.status, dict(response.getheaders()), response.read())
        connection.close()
        return value

    yield post, log
    server.shutdown()
    server.server_close()
    stream.close()


def test_forked_server_serves_and_logs_only_code_duration_bytes_and_correlation(env, adapter):
    post, log = adapter
    secret_cursor = 'cursor-value-never-logged'
    reply = fx.Reply.json(fx.items())
    env.vertical.plan = lambda path: reply
    body = env.body(items_parameters(cursor=secret_cursor))
    status, headers, payload = post(body, env.headers(body))
    assert status == 200 and payload == reply.body and headers['X-Ouf-Source-Schema-Version'] == fx.EDICOLE
    plans = [error(410, 'CURSOR_EXPIRED', reason='RETENTION'), fx.Reply.json({'code': 'UNAUTHENTICATED'}, status=401),
             error(429, 'RATE_LIMITED', headers=[('Retry-After', '9')])]
    statuses = []
    for plan in plans:
        env.vertical.plan = lambda path, plan=plan: plan
        statuses.append(post(body, env.headers(body))[0])
    statuses.append(post(body, env.headers(body, tenant='tenant-b'))[0])
    statuses.append(post(b'{}', env.headers(b'{}'))[0])
    assert statuses == [410, 502, 429, 403, 400]
    deadline = time.monotonic() + 5
    while len(log.read_text().splitlines()) < 6 and time.monotonic() < deadline:
        time.sleep(0.05)
    lines = log.read_text().splitlines()
    assert len(lines) == 6
    import re
    for line in lines:
        assert re.fullmatch(r'SOURCE_API_FETCH code=[A-Z0-9_]+ durationMs=[0-9]+ bytes=[0-9]+ correlationId=[A-Za-z0-9._:-]+',
                            line), line
    text = log.read_text()
    for forbidden in (SENTINEL, secret_cursor, fx.HOST, '/collections', 'Bearer', REF):
        assert forbidden not in text


def test_sentinel_bearer_never_appears_in_errors(env):
    outcomes = []
    for plan in [error(410, 'CURSOR_EXPIRED', reason='RETENTION'), fx.Reply(500, SENTINEL.encode()),
                 fx.Reply.json({'code': 'UNAUTHENTICATED', 'echo': SENTINEL}, status=401),
                 fx.Reply.json(fx.items(), delay=3.5)]:
        env.vertical.plan = lambda path, plan=plan: plan
        failure = env.failure(items_parameters())
        outcomes.append(failure.body() + str(failure).encode() + failure.log.encode() + repr(failure.__cause__).encode())
    assert all(SENTINEL.encode() not in item for item in outcomes)


def test_workload_credentials_are_refused_until_a_provider_exists(env):
    with pytest.raises(sa.ConfigurationDenied, match='CREDENTIAL_PROVIDER_UNAVAILABLE'):
        sa.load_registry(json.dumps(registry(binding(credentialRef='workload://vertical-read'))).encode())


def test_configuration_is_closed_and_fails_on_invalid_registry(env, tmp_path):
    (tmp_path / 'cfg-pki').mkdir()
    _, cert, key = fx.make_pki(tmp_path / 'cfg-pki', 'source-adapter.example.invalid')
    private(tmp_path / 'receipt.key', KEY)
    config = {'listenAddress': '127.0.0.1', 'listenPort': 9443, 'maxWorkers': 4, 'requestTimeoutSeconds': 30,
              'fetchPath': PATH, 'admission': {'installation': ADMISSION.installation, 'issuer': ADMISSION.issuer,
                                               'audience': ADMISSION.audience, 'scope': ADMISSION.scope,
                                               'workloads': dict(ADMISSION.workloads)},
              'receiptKeyFile': str(tmp_path / 'receipt.key'), 'registryFile': env.config.registry_file,
              'secretsDirectory': env.config.secrets_directory, 'trustDirectory': env.config.trust_directory,
              'stateDirectory': env.config.state_directory, 'tlsCertificateFile': str(cert),
              'tlsPrivateKeyFile': str(key)}
    path = tmp_path / 'adapter.json'
    path.write_text(json.dumps(config))
    _, loaded, _ = sa.load_configuration(path)
    assert loaded.fetch_path == PATH and loaded.admission.role('ouf-onboarding') == 'ONBOARDING'
    path.write_text(json.dumps(dict(config, extra=True)))
    with pytest.raises(sa.ConfigurationDenied):
        sa.load_configuration(path)
    path.write_text(json.dumps(dict(config, admission=dict(config['admission'],
                                                            workloads={'INGESTION': 'same', 'ONBOARDING': 'same'}))))
    with pytest.raises(Exception):
        sa.load_configuration(path)
    path.write_text(json.dumps(config))
    env.write_registry({'schema': 'broken'})
    with pytest.raises(sa.ConfigurationDenied):
        sa.load_configuration(path)
