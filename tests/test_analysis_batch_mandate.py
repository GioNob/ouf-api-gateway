import base64
import concurrent.futures
import http.client
import secrets
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from tools.analysis_batch_mandate import DISCOVERY_BINDING_HEADER, BatchMandates, Clock
from tools.analysis_batch_protocol import (
    Denied, OPERATIONS, START_DOMAIN, TTL_MS, arguments, digest, mac, parse, sign_binding, wire,
)
from tools.analysis_batch_service import AUTHORIZATION_PATH, BASE, Authorization, Listener, tls_context
from tools.analysis_batch_store import BatchMandateAudit
from tools.operational_incidents import SQLiteOperationalIncidentStore


def new_id():
    return str(uuid.uuid4())


def hash_text(text):
    return digest(text.encode('ascii'))


def key():
    return secrets.token_hex(32).encode('ascii')


SEARCH = 'semantic.search.batch'
REQUEST = 'semantic.discovery.request'
STATUS = 'semantic.discovery.status'
CANDIDATES = 'semantic.discovery.candidates'
SCOPE = 'ouf.semantic.discovery ouf.semantic.search'


class Time:
    def __init__(self):
        self.utc = time.time_ns() // 1_000_000
        self.tick = 0
        self.offset = 0

    def advance(self, delta):
        self.utc += delta
        self.tick += delta

    def clock(self):
        return Clock(1000, lambda: self.utc + self.offset, lambda: self.tick)


class WorkEvidence:
    def __init__(self, clock):
        self.clock = clock
        self.epoch = hash_text('policy')
        self.plans = {}
        self.discovery = {}
        self.stale = False
        self.receipt_queries = []

    def envelope(self, raw, **value):
        now = self.clock.utc
        return dict(requestHash=digest(raw) if not self.stale else hash_text('previous request'),
                    clockSynchronized=True, observedAtMs=now, validUntilMs=now + 10_000, **value)

    def state(self, raw):
        q = parse(raw)
        saved = self.plans.get((q['tenant'], q['subject'], q['commandKey']))
        bound = (saved is not None and all(saved[k] == q[k] for k in ('profileId', 'assetId', 'schemaHash'))
                 and saved['analysisId'] == q['analysisId'])
        if not bound:
            return self.envelope(raw, bound=False)
        work_ref = hash_text(saved['analysisId'] + 'first-column')
        return self.envelope(raw, bound=True, analysisId=saved['analysisId'], policyEpoch=self.epoch,
                             phase=saved['phase'], workRef=work_ref, **self.discovery.get(saved['analysisId'], {}))

    def receipt_context(self, raw):
        self.receipt_queries.append(parse(raw))
        return self.envelope(raw, active=True, allowed=True, policyEpoch=self.epoch, decisionRef=new_id(),
                             acr='verified', scope=SCOPE, roles=['analyst'])


class AuthorizationOwner:
    """Private HTTPS peer, shared by all listeners but backed by neither local store."""
    def __init__(self, clock, workload):
        self.clock, self.workload = clock, workload
        self.lock = threading.Lock()
        self.keys, self.rows = {}, {}
        self.calls, self.admissions = [], []
        self.receipt_claims = []
        self.inactive = False
        self.failure = None
        self.lost_reply = None
        self.admit_hook = None
        self.corrupt_admit = None
        self.epoch = hash_text('policy')

    def view(self, ref):
        view = self.rows[ref]
        if view['state'] == 'ACTIVE' and self.clock.utc >= view['expiresAtMs']:
            view.update(state='EXPIRED', version=2)
        return dict(view)

    def execute(self, action, payload, bearer):
        self.calls.append((action, payload, bearer))
        if self.failure:
            raise Denied(*self.failure)
        if action == 'admit' and self.admit_hook:
            self.admit_hook()
        with self.lock:
            return self.decide(action, dict(payload), bearer)

    def decide(self, action, q, bearer):
        if action == 'issue':
            proof = q.pop('proof', None)
            key_used = tuple(q[k] for k in ('issuer', 'tenant', 'subject', 'issueKey'))
            if key_used in self.keys:
                ref, previous = self.keys[key_used]
                if previous != q:
                    raise Denied(409, 'ISSUE_KEY_CONFLICT')
                return self.view(ref)
            if proof is None:
                raise Denied(403, 'HUMAN_PROOF_REQUIRED')
            if self.inactive:
                raise Denied(403, 'PRINCIPAL_INACTIVE')
            ref = new_id()
            self.rows[ref] = dict(mandateRef=ref, generation=1, version=1, state='ACTIVE',
                                  analysisId=q['analysisId'], expiresAtMs=self.clock.utc + TTL_MS)
            self.keys[key_used] = ref, q
            return self.view(ref)
        if q['mandateRef'] not in self.rows:
            raise Denied(404, 'MANDATE_NOT_FOUND')
        view = self.view(q['mandateRef'])
        if view['generation'] != q['generation']:
            raise Denied(409, 'MANDATE_GENERATION_CHANGED')
        if action == 'read':
            return view
        if action == 'revoke' and bearer not in ('Bearer holder', 'Bearer authorized-ths'):
            raise Denied(403, 'REVOCATION_DENIED')
        if action == 'admit' and view['state'] != 'ACTIVE':
            raise Denied(403, 'MANDATE_REVOKED' if view['state'] == 'REVOKED' else 'MANDATE_EXPIRED')
        if action == 'expire' and view['state'] != 'ACTIVE':
            return view
        if q['expectedVersion'] != view['version']:
            raise Denied(409, 'MANDATE_VERSION_CHANGED')
        if action == 'revoke':
            self.rows[q['mandateRef']].update(state='REVOKED', version=2)
            return self.view(q['mandateRef'])
        if q['analysisId'] != view['analysisId']:
            raise Denied(403, 'MANDATE_BINDING_MISMATCH')
        if action == 'expire':
            self.rows[q['mandateRef']].update(state='EXPIRED', version=2)
            return self.view(q['mandateRef'])
        if q['workload'] != self.workload:
            raise Denied(403, 'GATEWAY_WORKLOAD_DENIED')
        if q['policyEpoch'] != self.epoch:
            raise Denied(403, 'POLICY_EPOCH_CHANGED')
        if self.inactive:
            raise Denied(403, 'PRINCIPAL_INACTIVE')
        self.admissions.append(q)
        binding = next(saved for ref, saved in self.keys.values() if ref == q['mandateRef'])
        claims = {k: binding[k] for k in ('issuer', 'tenant', 'subject', 'client', 'workload', 'scope')}
        claims.update(actorType='HUMAN', decisionRef=new_id(), acr='admitted-acr',
                      roles=['reviewer', 'analyst'], validUntilMs=self.clock.utc + 5_000)
        self.receipt_claims.append(claims)
        return self.corrupt_admit or dict(view, receiptContext=claims)


class AuthorizationHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        cert = self.connection.getpeercert(binary_form=True)
        action = self.path.removeprefix(AUTHORIZATION_PATH)
        body = self.rfile.read(int(self.headers['Content-Length']))
        bearer = self.headers.get('Authorization')
        status, headers = 200, {}
        try:
            if not cert or self.server.pins.get(digest(cert)) != 'gateway':
                raise Denied(403, 'GATEWAY_WORKLOAD_DENIED')
            if action not in ('issue', 'admit', 'revoke', 'expire', 'read') or (bearer and action != 'revoke'):
                raise Denied(400, 'INVALID_REQUEST')
            result = self.server.owner.execute(action, parse(body), bearer)
            if self.server.owner.lost_reply == action:
                self.server.owner.lost_reply = None
                return
        except Denied as error:
            status, result = error.status, {'code': error.code}
            if error.retry_after:
                headers['Retry-After'] = error.retry_after
        raw = wire(result)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        for name, value in headers.items():
            self.send_header(name, value)
        try:
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            # The caller can time out after this simulated owner commits.
            pass



class Owner:
    def __init__(self):
        self.calls = []
        self.requests = {}
        self.lose_ack = False
        self.hook = None

    def send(self, path, body, headers, _):
        self.calls.append((path, body, headers))
        if self.hook is not None:
            self.hook()
        envelope = parse(body)
        args = envelope['Arguments']
        if path.endswith('/request'):
            identity = envelope['Identity']
            key = identity['PrincipalID'], identity['TenantID'], args['idempotencyKey']
            request_id = self.requests.setdefault(key, new_id())
            if self.lose_ack:
                self.lose_ack = False
                raise Denied(503, 'ANALYSIS_OWNER_OUTCOME_UNCERTAIN')
            return 200, wire({'requestId': request_id}), {}
        return 200, b'{}', {}


class TLSFixture:
    def __init__(self, directory):
        self.address = socket.getaddrinfo(None, 0, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        now = datetime.now(timezone.utc)
        self.directory = directory
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mandate-test-ca')])
        ca_key = Ed25519PrivateKey.generate()

        def certificate(subject, public_key, *, ca=False):
            return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                    .not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                                   critical=False)
                    .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
                    .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False, key_agreement=False,
                                                key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False),
                                   critical=True))

        ca = certificate(issuer, ca_key.public_key(), ca=True).sign(ca_key, None)
        self.ca = directory / 'ca.pem'
        self.ca.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        self.profiles, self.pins = {}, {}
        for role in ('server', 'mcp', 'human', 'foreign', 'gateway'):
            private = Ed25519PrivateKey.generate()
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)])
            cert = (certificate(subject, private.public_key())
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(self.address[0]))]), False)
                    .sign(ca_key, None))
            cert_file, key_file = directory / (role + '-cert.pem'), directory / (role + '-key.pem')
            cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            self.profiles[role] = dict(caFile=str(self.ca), certFile=str(cert_file), keyFile=str(key_file))
            if role in ('human', 'mcp', 'gateway'):
                self.pins[digest(cert.public_bytes(serialization.Encoding.DER))] = role

    def server(self, api):
        return Listener(self.address, api, tls_context(self.profiles['server'], server=True), self.pins, 2, 4)

    def client(self, server, role):
        context = (tls_context(self.profiles[role], server=False) if role
                   else ssl.create_default_context(cafile=self.ca))
        return http.client.HTTPSConnection(*server.server_address, context=context, timeout=5)


class BatchMandatePET(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        certificates = tempfile.TemporaryDirectory()
        cls.addClassCleanup(certificates.cleanup)
        cls.tls = TLSFixture(Path(certificates.name))

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.time = Time()
        self.work = WorkEvidence(self.time)
        self.semantic = Owner()
        self.settings = SimpleNamespace(
            installation='install-one', issuer='test-issuer', audience='test-gateway', workload='test-mcp',
            start_key=key(), binding_key=key(), owner_keys={'read': key(), 'discovery': key()},
            max_result_bytes=264192,
        )
        self.authorization = AuthorizationOwner(self.time, self.settings.workload)
        remote = ThreadingHTTPServer(self.tls.address, AuthorizationHandler)
        remote.owner, remote.pins = self.authorization, self.tls.pins
        remote.socket = tls_context(self.tls.profiles['server'], server=True).wrap_socket(remote.socket, server_side=True)
        self.run_server(remote)
        self.authorization_server = remote
        self.servers = [self.replica('a'), self.replica('b')]

    def run_server(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def replica(self, name):
        path = self.directory / (name + '.db')
        SQLiteOperationalIncidentStore(path).close()
        host, port = self.authorization_server.server_address
        owner = Authorization(dict(url=f'https://{host}:{port}', **self.tls.profiles['gateway']), 1)
        api = BatchMandates(self.settings, BatchMandateAudit(path, self.settings.installation), owner,
                            SimpleNamespace(evidence=self.work.receipt_context), SimpleNamespace(evidence=self.work.state),
                            self.semantic, self.time.clock())
        server = self.tls.server(api)
        self.run_server(server)
        return server

    def call(self, replica, action, data, role='mcp', *, with_headers=False, **extra):
        headers = {'Content-Type': 'application/json', **extra}
        connection = self.tls.client(self.servers[replica], role)
        try:
            connection.request('POST', BASE + action, wire(data), headers)
            with connection.getresponse() as response:
                result = response.status, parse(response.read())
                return (*result, response.headers) if with_headers else result
        finally:
            connection.close()

    def plan(self, tenant='tenant-one', command=None):
        args = dict(mode='BATCH_V1', assetId=new_id(), profileId=new_id(), schemaHash=hash_text('schema'),
                    commandKey=command or new_id())
        iat = self.time.utc // 1000
        return dict(v=1, installation=self.settings.installation, issuer=self.settings.issuer,
                    audience=self.settings.audience, workload=self.settings.workload, tenant=tenant,
                    subject='human-one', client='same-oauth-client', actor='HUMAN', scope=SCOPE,
                    authTime=iat - 2, iat=iat, exp=iat + 60, plan=args)

    def prepare(self, plan):
        proof = sign_binding(self.settings.start_key, START_DOMAIN, plan)
        request = {'startProof': proof}
        status, pending = self.call(0, 'prepare', request)
        self.assertEqual((status, pending['state']), (200, 'PENDING'))
        self.assertEqual(self.call(1, 'prepare', request), (200, pending))
        args = plan['plan']
        return dict(mandateRef=pending['mandateRef'], generation=1, startBinding=pending['startBinding'],
                    commandKey=args['commandKey'], analysisId=hash_text(plan['tenant'] + args['profileId']),
                    policyEpoch=self.work.epoch, startProof=proof)

    def save_mcp(self, plan, issue):
        args = plan['plan']
        self.work.plans[plan['tenant'], plan['subject'], args['commandKey']] = {
            **args, 'analysisId': issue['analysisId'], 'phase': 'FIRST_ROUND',
        }

    def active(self, plan=None):
        plan = plan or self.plan()
        issue = self.prepare(plan)
        self.save_mcp(plan, issue)
        status, view = self.call(1, 'issue', issue)
        self.assertEqual((status, view['state']), (200, 'ACTIVE'))
        self.assertNotEqual(view['mandateRef'], issue['mandateRef'])
        return view

    def dispatch_data(self, view, name=SEARCH, args=None):
        if args is None:
            args = dict(contract='ouf.semantic.published-batch.v1', limitPerIntent=4,
                        intents=[dict(intentId='first', intent='private-column-label', preferredLanguages=['it'],
                                      requestedArtifactType='PROPERTY', context={})])
        return dict(mandateRef=view['mandateRef'], generation=view['generation'], analysisId=view['analysisId'],
                    mandateBinding=view['mandateBinding'], operation=name, arguments=args,
                    correlationId=new_id(), attemptId=new_id())

    def discovery_data(self, view, args=None):
        args = args or dict(requestedArtifactType='PROPERTY', intent='private-discovery-intent',
                            preferredLanguages=['it'], idempotencyKey=new_id())
        self.work.discovery[view['analysisId']] = {'discoveryArgumentsHash': arguments(REQUEST, args)}
        return self.dispatch_data(view, REQUEST, args)

    def save_discovery_binding(self, view, headers):
        self.work.discovery[view['analysisId']]['discoveryBinding'] = headers[DISCOVERY_BINDING_HEADER]

    def read(self, view, replica=1):
        return self.call(replica, 'read', {k: view[k] for k in ('mandateRef', 'generation', 'mandateBinding')})

    def revoke(self, view, bearer='Bearer holder'):
        req = dict(mandateRef=view['mandateRef'], generation=view['generation'], expectedVersion=view['version'])
        return self.call(0, 'revoke', req, role='human', Authorization=bearer)

    def denied(self, data, expected, replica=1, role='mcp'):
        count = len(self.semantic.calls)
        status, result = self.call(replica, 'dispatch', data, role)
        self.assertEqual((status, result['code']), expected)
        self.assertEqual(len(self.semantic.calls), count)

    def events(self, name):
        with closing(sqlite3.connect(self.directory / (name + '.db'))) as db:
            return [parse(event) for event, in db.execute('select event from analysis_batch_audit_v1 order by sequence')]

    def test_issue_attests_human_and_replays_after_lost_response_and_restart(self):
        plan = self.plan()
        issue = self.prepare(plan)
        self.assertEqual(self.call(1, 'issue', issue), (403, {'code': 'ANALYSIS_WORK_NOT_BOUND'}))
        self.save_mcp(plan, issue)
        replay = {k: v for k, v in issue.items() if k != 'startProof'}
        self.assertEqual(self.call(1, 'issue', replay), (403, {'code': 'HUMAN_PROOF_REQUIRED'}))
        self.authorization.lost_reply = 'issue'
        self.assertEqual(self.call(0, 'issue', issue)[0], 503)
        action, sent, bearer = self.authorization.calls[-1]
        self.assertEqual((action, bearer), ('issue', None))
        fields = ('analysisId assetId profileId schemaHash issuer tenant subject client workload startRef commandKey '
                  'issueKey policyEpoch scope generation expectedVersion proof')
        self.assertEqual(set(sent), set(fields.split()))
        self.assertEqual((sent['startRef'], sent['issueKey']), (issue['mandateRef'], issue['commandKey']))
        self.assertEqual((sent['generation'], sent['expectedVersion']), (1, 0))
        self.assertEqual(sent['proof']['authenticatedAtMs'], plan['authTime'] * 1000)
        self.assertEqual((sent['proof']['actorType'], sent['proof']['mode'], sent['proof']['phase']),
                         ('HUMAN', 'BATCH_V1', 'FIRST_ROUND'))
        self.assertTrue(0 < sent['proof']['validUntilMs'] - sent['proof']['observedAtMs'] <= 30_000)
        self.time.advance(61_000)
        self.servers.append(self.replica('restarted'))
        status, active = self.call(2, 'issue', replay)
        self.assertEqual((status, active['state']), (200, 'ACTIVE'))
        self.assertEqual(active['expiresAtMs'], sent['proof']['observedAtMs'] + TTL_MS)
        self.assertEqual(self.call(2, 'issue', issue), (403, {'code': 'ANALYSIS_START_PROOF_DENIED'}))
        self.assertEqual(len(self.authorization.rows), 1)
        status, revoked = self.revoke(active)
        self.assertEqual((status, revoked['state']), (200, 'REVOKED'))
        self.assertEqual(self.call(2, 'issue', replay), (200, revoked))
        self.assertEqual(self.call(2, 'issue', {**replay, 'policyEpoch': hash_text('different policy')}),
                         (409, {'code': 'ISSUE_KEY_CONFLICT'}))

    def test_positive_all_four_operations_and_receipts(self):
        active = self.active()
        self.assertEqual(self.call(0, 'dispatch', self.dispatch_data(active))[0], 200)
        create = self.discovery_data(active)
        status, job, headers = self.call(1, 'dispatch', create, with_headers=True)
        self.assertEqual(status, 200)
        self.save_discovery_binding(active, headers)
        for name in (STATUS, CANDIDATES):
            self.assertEqual(self.call(0, 'dispatch', self.dispatch_data(active, name, job))[0], 200)
        self.assertEqual([q['operation'] for q in self.authorization.admissions], list(OPERATIONS))
        for q, (path, body, headers), op in zip(self.authorization.admissions, self.semantic.calls,
                                               OPERATIONS.values(), strict=True):
            self.assertEqual(path, op.path)
            fields = ('mandateRef generation expectedVersion analysisId workload policyEpoch operation '
                      'argumentsHash attemptId correlationId')
            if q['operation'] in (STATUS, CANDIDATES):
                fields += ' requestId'
                self.assertEqual(q['requestId'], job['requestId'])
            self.assertEqual(set(q), set(fields.split()))
            self.assertEqual((q['expectedVersion'], q['workload']), (active['version'], self.settings.workload))
            self.assertNotIn('Authorization', headers)
            proof = headers[f'X-OUF-Semantic-{op.family.title()}-Receipt']
            encoded, tag = proof.split('.')
            receipt = parse(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            self.assertEqual(tag, mac(self.settings.owner_keys[op.family], f'ouf-semantic-{op.family}-owner-v1', encoded))
            self.assertEqual(receipt['bodyHash'], digest(body))
            self.assertLessEqual(receipt['exp'] - receipt['iat'], 30)
        audit = wire(self.events('b'))
        self.assertNotIn(b'private-', audit)
        self.assertNotIn(create['arguments']['idempotencyKey'].encode(), audit)

    def test_semantic_receipt_uses_claims_from_each_admit(self):
        data = self.dispatch_data(self.active(self.plan(tenant='tenant-two')))
        for replica in (0, 1):
            self.assertEqual(self.call(replica, 'dispatch', data)[0], 200)
            claims = self.authorization.receipt_claims[-1]
            _, body, headers = self.semantic.calls[-1]
            encoded, _ = headers['X-OUF-Semantic-Read-Receipt'].split('.')
            receipt = parse(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            self.assertEqual(receipt['bodyHash'], digest(body))
            self.assertEqual({k: receipt[k] for k in ('issuer', 'tenant', 'subject', 'workload', 'acr')},
                             {k: claims[k] for k in ('issuer', 'tenant', 'subject', 'workload', 'acr')})
            self.assertEqual(receipt['roles'].split(), claims['roles'])
            self.assertEqual(receipt['scope'].split(), claims['scope'])
            envelope = parse(body)
            self.assertEqual(envelope['AuthorizationDecisionRef'], claims['decisionRef'])
            self.assertEqual(envelope['Identity'], dict(ServicePrincipalID=claims['client'],
                                                       PrincipalID=claims['subject'], TenantID=claims['tenant'],
                                                       ActorType=claims['actorType'], AuthenticationContextRef=claims['acr']))
            self.assertLessEqual(receipt['exp'] * 1000, claims['validUntilMs'])
        self.assertEqual(self.work.receipt_queries, [])

    def test_discovery_admit_hash_covers_rewritten_idempotency_key(self):
        create = self.discovery_data(self.active())
        self.assertEqual(self.call(1, 'dispatch', create)[0], 200)
        _, body, headers = self.semantic.calls[-1]
        envelope = parse(body)
        forwarded_args = envelope['Arguments']
        self.assertNotEqual(forwarded_args['idempotencyKey'], create['arguments']['idempotencyKey'])
        self.assertEqual(forwarded_args['idempotencyKey'], envelope['IdempotencyKey'])
        self.assertEqual(forwarded_args['idempotencyKey'], headers['Idempotency-Key'])
        self.assertEqual(self.authorization.admissions[-1]['argumentsHash'], digest(wire(forwarded_args)))
        self.assertEqual(envelope['RequestHash'], self.authorization.admissions[-1]['argumentsHash'])

    def test_remote_revocation_with_distinct_stores_blocks_retries_and_reads(self):
        self.assertNotEqual(self.servers[0].api.audit.uri, self.servers[1].api.audit.uri)
        active = self.active()
        search, create = self.dispatch_data(active), self.discovery_data(active)
        self.assertEqual(self.call(1, 'dispatch', search)[0], 200)
        status, job, headers = self.call(1, 'dispatch', create, with_headers=True)
        self.assertEqual(status, 200)
        self.save_discovery_binding(active, headers)
        status, revoked = self.revoke(active)
        self.assertEqual((status, revoked['state']), (200, 'REVOKED'))
        self.assertEqual(self.read(active), (200, revoked))
        attempts = len(self.authorization.calls)
        allowed, forwarded = len(self.authorization.admissions), len(self.semantic.calls)
        for data in (search, create, *(self.dispatch_data(active, op, job) for op in (STATUS, CANDIDATES))):
            self.denied(data, (403, 'MANDATE_REVOKED'))
        self.assertEqual(len(self.authorization.admissions), allowed)
        self.assertEqual(len(self.semantic.calls), forwarded)
        self.assertEqual([action for action, _, _ in self.authorization.calls[attempts:]], ['admit'] * 4)

    def test_unreachable_authorization_denies_repeated_attempt(self):
        data = self.dispatch_data(self.active())
        self.assertEqual(self.call(0, 'dispatch', data)[0], 200)
        self.authorization_server.shutdown()
        self.authorization_server.server_close()
        self.denied(data, (503, 'ANALYSIS_AUTHORIZATION_UNAVAILABLE'))
        self.assertEqual(len(self.authorization.admissions), 1)

    def test_authorization_timeout_denies_without_forwarding(self):
        active = self.active()
        self.authorization.lost_reply = 'admit'
        self.denied(self.dispatch_data(active), (503, 'ANALYSIS_AUTHORIZATION_UNAVAILABLE'))
        self.assertEqual(len(self.authorization.admissions), 1)
        unblock = threading.Event()
        self.authorization.admit_hook = lambda: unblock.wait(4)
        try:
            self.denied(self.dispatch_data(active), (503, 'ANALYSIS_AUTHORIZATION_UNAVAILABLE'))
        finally:
            unblock.set()

    def test_inactive_principal_denied_by_authorization_on_repeated_attempt(self):
        data = self.dispatch_data(self.active())
        for replica in (0, 1):
            self.assertEqual(self.call(replica, 'dispatch', data)[0], 200)
        self.assertEqual([q['attemptId'] for q in self.authorization.admissions], [data['attemptId']] * 2)
        self.authorization.inactive = True
        self.denied(data, (403, 'PRINCIPAL_INACTIVE'))
        self.assertEqual(len(self.authorization.admissions), 2)
        self.assertEqual(sum(action == 'admit' for action, *_ in self.authorization.calls), 3)

    def test_remote_outage_retry_after_restart_and_recovery(self):
        data = self.dispatch_data(self.active())
        self.authorization.failure = (503, 'CURRENT_RIGHTS_UNAVAILABLE', '300')
        status, result, headers = self.call(0, 'dispatch', data, with_headers=True)
        self.assertEqual((status, result['code'], headers['Retry-After']), (503, 'CURRENT_RIGHTS_UNAVAILABLE', '300'))
        self.time.advance(3 * 60 * 60 * 1000)
        self.servers.append(self.replica('restarted'))
        self.denied(data, (503, 'CURRENT_RIGHTS_UNAVAILABLE'), replica=2)
        self.authorization.failure = None
        self.assertEqual(self.call(2, 'dispatch', data)[0], 200)
        self.assertEqual(len(self.semantic.calls), 1)

    def test_local_audit_unavailable_cannot_decide_dispatch(self):
        data = self.dispatch_data(self.active())
        path = self.directory / 'b.db'
        path.rename(self.directory / 'b.paused')
        self.assertEqual(self.call(1, 'dispatch', data)[0], 200)
        with self.assertLogs('tools.analysis_batch_mandate') as logs:
            self.denied({**data, 'operation': 'semantic.discovery.adopt'}, (403, 'ANALYSIS_OPERATION_NOT_ALLOWED'))
        self.assertIn('ANALYSIS_LOCAL_AUDIT_UNAVAILABLE', str(logs.output))
        self.assertFalse(path.exists())

    def test_mismatched_owner_success_does_not_authorize_dispatch(self):
        active = self.active()
        view = {k: v for k, v in active.items() if k != 'mandateBinding'}
        data = self.dispatch_data(active)
        self.assertEqual(self.call(1, 'dispatch', data)[0], 200)
        claims = self.authorization.receipt_claims[-1]
        view['receiptContext'] = claims
        for change in (dict(analysisId=hash_text('another analysis')), dict(generation=True),
                       dict(state='REVOKED', version=2), dict(expiresAtMs=active['expiresAtMs'] + 1),
                       dict(receiptContext={**claims, 'subject': 'another-human'}),
                       dict(receiptContext={**claims, 'acr': None})):
            with self.subTest(change=change):
                self.authorization.corrupt_admit = {**view, **change}
                self.denied(data, (502, 'ANALYSIS_AUTHORIZATION_RESPONSE_INVALID'))
        view.pop('receiptContext')
        self.authorization.corrupt_admit = view
        self.denied(data, (502, 'ANALYSIS_AUTHORIZATION_RESPONSE_INVALID'))
        self.authorization.corrupt_admit = dict(view, receiptContext={**claims, 'validUntilMs': self.time.utc})
        self.denied(data, (403, 'ANALYSIS_EVIDENCE_EXPIRED'))

    def test_cross_analysis_and_cross_tenant_reject_discovery_binding_swap(self):
        command = new_id()
        first = self.active(self.plan(command=command))
        create = self.discovery_data(first)
        _, first_job, first_headers = self.call(0, 'dispatch', create, with_headers=True)
        for foreign in (self.active(self.plan(command=command, tenant='tenant-two')), self.active()):
            self.denied({**self.dispatch_data(foreign), 'mandateBinding': first['mandateBinding']},
                        (403, 'ANALYSIS_MANDATE_BINDING_MISMATCH'))
            data = self.discovery_data(foreign, create['arguments'])
            _, job, _ = self.call(1, 'dispatch', data, with_headers=True)
            self.assertNotEqual(job['requestId'], first_job['requestId'])
            self.save_discovery_binding(foreign, first_headers)
            for op in (STATUS, CANDIDATES):
                self.denied(self.dispatch_data(foreign, op, first_job), (403, 'ANALYSIS_DISCOVERY_REQUEST_NOT_BOUND'))

    def test_pinned_workload_and_fresh_evidence_required(self):
        data = self.dispatch_data(self.active())
        for role in (None, 'foreign', 'human'):
            self.denied(data, (403, 'ANALYSIS_WORKLOAD_PROOF_REQUIRED'), role=role)
        self.denied({**data, 'mandateBinding': 'forged'}, (403, 'ANALYSIS_BINDING_PROOF_DENIED'))
        self.work.stale = True
        self.denied(data, (503, 'ANALYSIS_EVIDENCE_UNVERIFIED'))
        self.assertEqual(self.authorization.admissions, [])

    def test_expiry_for_closed_phase_and_at_deadline(self):
        for phase in ('FIRST_ROUND_COMPLETE', 'CLOSED', 'CANCELLED'):
            active = self.active()
            saved = next(plan for plan in self.work.plans.values() if plan['analysisId'] == active['analysisId'])
            saved['phase'] = phase
            self.denied(self.dispatch_data(active), (403, 'ANALYSIS_MANDATE_EXPIRED'))
            self.assertEqual(self.read(active)[1]['state'], 'EXPIRED')
            action, payload, _ = self.authorization.calls[-2]
            self.assertEqual((action, payload['reason']), ('expire', phase))
        active = self.active()
        self.time.advance(TTL_MS)
        self.denied(self.dispatch_data(active), (403, 'MANDATE_EXPIRED'))
        self.assertEqual(self.read(active)[1]['state'], 'EXPIRED')

    def test_revocation_commit_wins_while_admission_is_pending(self):
        active = self.active()
        data = self.dispatch_data(active)
        entered, resume = threading.Event(), threading.Event()

        def pause():
            entered.set()
            resume.wait(4)

        self.authorization.admit_hook = pause
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(self.call, 1, 'dispatch', data)
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(self.revoke(active)[0], 200)
            finally:
                resume.set()
            self.assertEqual(pending.result(), (403, {'code': 'MANDATE_REVOKED'}))
        self.assertEqual(self.authorization.admissions, [])
        self.assertEqual(self.semantic.calls, [])

    def test_ambiguous_discovery_creation_reconciles_on_other_listener(self):
        active = self.active()
        data = self.discovery_data(active)
        self.semantic.lose_ack = True
        self.assertEqual(self.call(0, 'dispatch', data)[0], 503)
        for change in (dict(intent='changed'), dict(idempotencyKey=new_id())):
            self.denied({**data, 'arguments': {**data['arguments'], **change}}, (409, 'ANALYSIS_DISCOVERY_KEY_CONFLICT'))
        status, job, headers = self.call(1, 'dispatch', {**data, 'attemptId': new_id()}, with_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(list(self.semantic.requests.values()), [job['requestId']])
        self.save_discovery_binding(active, headers)
        self.assertEqual(self.call(0, 'dispatch', self.dispatch_data(active, STATUS, job))[0], 200)

    def test_already_admitted_call_can_finish_after_revocation(self):
        active = self.active()
        data = self.discovery_data(active)
        entered, resume = threading.Event(), threading.Event()

        def pause():
            entered.set()
            resume.wait(4)

        self.semantic.hook = pause
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(self.call, 1, 'dispatch', data, with_headers=True)
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(self.revoke(active)[0], 200)
                self.denied(data, (403, 'MANDATE_REVOKED'))
            finally:
                resume.set()
            status, job, headers = pending.result()
        self.assertEqual(status, 200)
        self.save_discovery_binding(active, headers)
        self.denied(self.dispatch_data(active, STATUS, job), (403, 'MANDATE_REVOKED'))

    def test_revocation_forwards_bearer_and_reconciles_ambiguous_outcome(self):
        active = self.active()
        self.assertEqual(self.revoke(active, 'Bearer unauthorized'), (403, {'code': 'REVOCATION_DENIED'}))
        self.authorization.lost_reply = 'revoke'
        self.time.offset = -5000
        self.assertEqual(self.revoke(active, 'Bearer authorized-ths'),
                         (503, {'code': 'ANALYSIS_REVOCATION_OUTCOME_UNCERTAIN'}))
        revoke, read = self.authorization.calls[-2:]
        self.assertEqual((revoke[0], revoke[2]), ('revoke', 'Bearer authorized-ths'))
        self.assertEqual((read[0], read[2]), ('read', None))
        self.assertEqual(self.read(active)[1]['state'], 'REVOKED')
        self.assertNotIn(b'authorized-ths', wire(self.events('a')))


if __name__ == '__main__':
    unittest.main()
