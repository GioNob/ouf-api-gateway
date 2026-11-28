import base64
import concurrent.futures
import http.client
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from tools.analysis_batch_mandate import BatchMandates, Clock
from tools.analysis_batch_protocol import (
    Denied, OPERATIONS, START_DOMAIN, TTL_MS, b64, digest, mac, parse, wire,
)
from tools.analysis_batch_service import BASE, Listener, tls_context
from tools.analysis_batch_store import BatchMandateStore
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


class Authorities:
    def __init__(self, clock):
        self.clock = clock
        self.epoch = hash_text('policy')
        self.plans = {}
        self.active = True
        self.allowed = True
        self.scope = SCOPE
        self.grant = hash_text('grant')
        self.phase = 'FIRST_ROUND'
        self.rights_hook = None
        self.revoke_as = None
        self.dispatched_rights = []
        self.stale = False
        self.stale_attempt = None
        self.unavailable = False
        self.time_error = 0

    def envelope(self, raw, value):
        when = self.clock.utc + self.time_error
        return dict(requestHash=digest(raw) if not self.stale else hash_text('previous request'),
                    clockSynchronized=True, observedAtMs=when, validUntilMs=when + 10_000, **value)

    def state(self, raw, _):
        q = parse(raw)
        saved = self.plans.get((q['tenant'], q['subject'], q['commandKey']))
        bound = saved is not None and saved['profileId'] == q['profileId'] and saved['assetId'] == q['assetId']
        if q['action'] == 'dispatch' and q['attemptId'] == self.stale_attempt:
            bound = False
        if not bound:
            return self.envelope(raw, dict(bound=False))
        return self.envelope(raw, dict(bound=True, analysisId=saved['analysisId'], policyEpoch=self.epoch,
                                       phase=self.phase, workRef=hash_text(saved['analysisId'] + 'first-column')))

    def rights(self, raw, bearer):
        q = parse(raw)
        action = q['action']
        if action == 'clock':
            return self.envelope(raw, {})
        if action == 'revoke':
            if not bearer:
                raise Denied(403, 'HUMAN_REQUIRED')
            return self.envelope(raw, dict(active=True, allowed=True, actorType='HUMAN', issuer=q['issuer'],
                                           subject=q['subject'], tenant=q['tenant'], client=q['client'],
                                           operatorAuthorized=False) | (self.revoke_as or {}))
        if action == 'dispatch':
            self.dispatched_rights.append((q['subject'], q['tenant'], q['operation']))
            if self.rights_hook is not None:
                self.rights_hook()
            if self.unavailable:
                raise Denied(503, 'IAM_UNAVAILABLE')
        return self.envelope(raw, dict(active=self.active, allowed=self.allowed, policyEpoch=self.epoch,
                                       decisionRef=new_id(), acr='verified', scope=self.scope, roles=['analyst'],
                                       grants=dict.fromkeys(OPERATIONS, self.grant)))


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

        def certificate(subject, public_key):
            return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                    .not_valid_after(now + timedelta(days=1)))

        ca = certificate(issuer, ca_key.public_key()).add_extension(x509.BasicConstraints(ca=True, path_length=0),
                                                                     critical=True).sign(ca_key, None)
        self.ca = directory / 'ca.pem'
        self.ca.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        self.profiles, self.pins = {}, {}
        for role in ('server', 'mcp', 'human', 'foreign'):
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
            if role in ('human', 'mcp'):
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
        cls.certificates = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.certificates.cleanup)
        cls.tls = TLSFixture(Path(cls.certificates.name))

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'operations.db'
        SQLiteOperationalIncidentStore(self.path).close()
        self.time = Time()
        self.authorities = Authorities(self.time)
        self.owner = Owner()
        self.settings = SimpleNamespace(
            installation='install-one', issuer='test-issuer', audience='test-gateway', workload='test-mcp',
            ths_client='test-ths', storage_epoch=hash_text('registry'), start_key=key(),
            owner_keys={'read': key(), 'discovery': key()}, max_result_bytes=264192,
            rates=dict.fromkeys(OPERATIONS, 20),
        )
        self.servers = [self.replica(), self.replica()]

    def replica(self, *, initialize=True):
        store = BatchMandateStore(self.path, self.settings.installation, self.settings.storage_epoch,
                                  initialize=initialize)
        api = BatchMandates(self.settings, store, SimpleNamespace(evidence=self.authorities.rights),
                            SimpleNamespace(evidence=self.authorities.state), self.owner, self.time.clock())
        server = self.tls.server(api)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def call(self, replica, action, data, role='mcp', **extra):
        headers = {'Content-Type': 'application/json', **extra}
        connection = self.tls.client(self.servers[replica], role)
        try:
            connection.request('POST', BASE + action, wire(data), headers)
            with connection.getresponse() as response:
                raw = response.read()
                return response.status, parse(raw)
        finally:
            connection.close()

    def plan(self, subject='human-one', tenant='tenant-one', start_key=None):
        p = dict(mode='BATCH_V1', assetId=new_id(), profileId=new_id(), schemaHash=hash_text('schema'),
                 commandKey=start_key or new_id())
        return dict(v=1, installation=self.settings.installation, issuer=self.settings.issuer,
                    audience=self.settings.audience, workload=self.settings.workload, tenant=tenant,
                    subject=subject, client='same-oauth-client', actor='HUMAN', scope=SCOPE,
                    iat=self.time.utc // 1000, exp=self.time.utc // 1000 + 60, plan=p)

    def prepare(self, plan, replica=0):
        payload = b64(wire(plan))
        proof = payload + '.' + mac(self.settings.start_key, START_DOMAIN, payload)
        return self.call(replica, 'prepare', {'startProof': proof})

    def save_mcp(self, plan):
        p = plan['plan']
        self.authorities.plans[plan['tenant'], plan['subject'], p['commandKey']] = {
            **p, 'analysisId': hash_text(plan['tenant'] + plan['subject'] + p['profileId']),
        }

    def issue(self, plan, view, replica=1):
        return self.call(replica, 'issue', dict(mandateRef=view['mandateRef'], generation=view['generation'],
                                                commandKey=plan['plan']['commandKey']))

    def active(self, plan=None):
        plan = plan or self.plan()
        status, view = self.prepare(plan)
        self.assertEqual(status, 200)
        self.assertEqual(view['state'], 'PENDING')
        self.save_mcp(plan)
        status, view = self.issue(plan, view)
        self.assertEqual(status, 200)
        self.assertEqual(view['state'], 'ACTIVE')
        return view

    def dispatch_data(self, view, name=SEARCH, args=None):
        if args is None:
            args = dict(contract='ouf.semantic.published-batch.v1', limitPerIntent=4,
                        intents=[dict(intentId='first', intent='private-column-label', preferredLanguages=['it'],
                                      requestedArtifactType='PROPERTY', context={})])
        return dict(mandateRef=view['mandateRef'], generation=view['generation'], analysisId=view['analysisId'],
                    operation=name, arguments=args, correlationId=new_id(), attemptId=new_id())

    def terminal_data(self, view):
        return dict(mandateRef=view['mandateRef'], generation=view['generation'], expectedVersion=view['version'])

    def revoke(self, view, replica=1):
        return self.call(replica, 'revoke', self.terminal_data(view), role='human',
                         Authorization='Bearer ' + secrets.token_urlsafe(20))

    def denied(self, data, statuses, replica=1, role='mcp', **extra):
        before = len(self.owner.calls)
        status, body = self.call(replica, 'dispatch', data, role, **extra)
        self.assertIn(status, statuses, body)
        self.assertEqual(len(self.owner.calls), before)
        return body['code']

    def events(self):
        with self.servers[0].api.store.transaction() as db:
            return [parse(row[0]) for row in db.execute('select event from analysis_batch_audit_v1 order by sequence')]

    def test_replay_after_restart_and_revoked_tombstone(self):
        plan = self.plan()
        _, pending = self.prepare(plan)
        self.assertEqual(self.prepare(plan, 1), (200, pending))
        self.assertEqual(self.issue(plan, pending)[0], 403)
        self.save_mcp(plan)
        self.time.advance(61_000)
        self.servers.append(self.replica())
        status, active = self.issue(plan, pending, 2)
        self.assertEqual(status, 200)
        self.assertEqual(active['state'], 'ACTIVE')
        self.assertEqual(active['expiresAtMs'], self.time.utc + TTL_MS)
        self.assertEqual(self.issue(plan, pending, 0), (200, active))
        status, revoked = self.revoke(active)
        self.assertEqual(status, 200)
        self.assertEqual(revoked['state'], 'REVOKED')
        self.assertEqual(self.issue(plan, pending, 2), (200, revoked))
        self.denied(self.dispatch_data(active), (403,), 2)
        self.assertEqual(sum(e['outcome'] == 'ISSUED' for e in self.events()), 1)

    def test_concurrent_issue_and_revoke_compare_and_swap(self):
        plan = self.plan()
        _, pending = self.prepare(plan)
        self.save_mcp(plan)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first = pool.submit(self.issue, plan, pending, 0)
            second = pool.submit(self.issue, plan, pending, 1)
            self.assertEqual(first.result(), second.result())
            _, active = first.result()
            first = pool.submit(self.revoke, active, 0)
            second = pool.submit(self.revoke, active, 1)
            self.assertEqual(sorted([first.result()[0], second.result()[0]]), [200, 409])
        self.denied(self.dispatch_data(active), (403,), 0)
        self.denied(self.dispatch_data(active), (403,), 1)

    def test_positive_all_four_operations_and_owner_receipts(self):
        active = self.active()
        self.assertEqual(self.call(0, 'dispatch', self.dispatch_data(active))[0], 200)
        args = dict(requestedArtifactType='PROPERTY', intent='private-discovery-intent',
                    preferredLanguages=['it'], idempotencyKey=new_id())
        status, owner = self.call(1, 'dispatch', self.dispatch_data(active, REQUEST, args))
        self.assertEqual(status, 200)
        for name in (STATUS, CANDIDATES):
            data = self.dispatch_data(active, name, {'requestId': owner['requestId']})
            self.assertEqual(self.call(0, 'dispatch', data)[0], 200)
        self.assertEqual(len(self.authorities.dispatched_rights), 4)
        for (path, body, headers), op in zip(self.owner.calls, OPERATIONS.values()):
            self.assertEqual(path, op.path)
            self.assertNotIn('Authorization', headers)
            proof = headers[f'X-OUF-Semantic-{op.family.title()}-Receipt']
            encoded, tag = proof.split('.')
            receipt = parse(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            self.assertEqual(tag, mac(self.settings.owner_keys[op.family], f'ouf-semantic-{op.family}-owner-v1', encoded))
            self.assertEqual(receipt['bodyHash'], digest(body))
            self.assertEqual(receipt['subject'], 'human-one')
            self.assertEqual(receipt['tenant'], 'tenant-one')
            self.assertLessEqual(receipt['exp'] - receipt['iat'], 30)
        audit = wire(self.events())
        self.assertNotIn(b'private-', audit)
        self.assertNotIn(args['idempotencyKey'].encode(), audit)
        self.assertNotIn(b'Receipt', audit)

    def test_cross_analysis_and_cross_tenant_with_same_client(self):
        key_used = new_id()
        first = self.active(self.plan(start_key=key_used))
        second = self.active(self.plan(subject='human-two', start_key=key_used))
        third = self.active(self.plan(subject='human-two', tenant='tenant-two', start_key=key_used))
        self.assertEqual(len({view['analysisId'] for view in (first, second, third)}), 3)
        args = dict(requestedArtifactType='PROPERTY', intent='first', preferredLanguages=['it'], idempotencyKey=new_id())
        status, created = self.call(0, 'dispatch', self.dispatch_data(first, REQUEST, args))
        self.assertEqual(status, 200)
        for replica, foreign in enumerate((second, third)):
            swapped = self.dispatch_data(foreign)
            swapped['mandateRef'] = first['mandateRef']
            self.denied(swapped, (403,), replica)
            for name in (STATUS, CANDIDATES):
                data = self.dispatch_data(foreign, name, {'requestId': created['requestId']})
                self.denied(data, (403,), replica)
        self.assertEqual(self.call(1, 'dispatch', self.dispatch_data(second))[0], 200)

    def test_stolen_reference_requires_the_pinned_tls_peer(self):
        data = self.dispatch_data(self.active())
        for replica in (0, 1):
            for role in (None, 'foreign', 'human'):
                code = self.denied(data, (403,), replica, role, **{'X-OUF-Workload': self.settings.workload})
                self.assertEqual(code, 'ANALYSIS_WORKLOAD_PROOF_REQUIRED')
        self.assertEqual(len(self.events()), 7)

    def test_current_state_denials_across_replicas(self):
        data = self.dispatch_data(self.active())
        mutations = [('active', False), ('allowed', False), ('epoch', hash_text('new policy')),
                     ('scope', 'ouf.semantic.search'), ('grant', hash_text('new grant')), ('stale', True),
                     ('time_error', 2000), ('unavailable', True)]
        for attr, value in mutations:
            with self.subTest(attr=attr):
                previous = getattr(self.authorities, attr)
                setattr(self.authorities, attr, value)
                for replica in (0, 1):
                    self.denied(data, (403, 503), replica)
                setattr(self.authorities, attr, previous)
        self.denied({**data, 'generation': 2}, (403,), 0)
        self.denied({**data, 'operation': 'semantic.discovery.adopt'}, (403,), 0)
        self.authorities.stale_attempt = data['attemptId']
        self.denied(data, (403,), 1)
        self.assertEqual(len(self.owner.calls), 0)

    def test_store_outage_clock_rollback_restart_and_recovery(self):
        active = self.active()
        data = self.dispatch_data(active)
        self.time.advance(15_000)
        self.assertEqual(self.call(0, 'dispatch', data)[0], 200)
        self.time.offset = -500
        self.denied(data, (503,), 0)
        self.servers.append(self.replica())
        self.denied(data, (503,), 2)
        self.time.offset = 0
        paused = self.path.with_suffix('.paused')
        self.path.rename(paused)
        try:
            with self.assertLogs('tools.analysis_batch_mandate', level='WARNING') as logs:
                self.denied(data, (503,), 0)
                self.denied(data, (503,), 1)
            self.assertNotIn('private-column-label', str(logs.output))
            self.time.advance(3 * 60 * 60 * 1000)
        finally:
            paused.rename(self.path)
        self.assertEqual(self.call(2, 'dispatch', data)[0], 200)
        self.assertEqual(self.servers[1].api.store.get(active['mandateRef'])['expires_ms'], active['expiresAtMs'])

    def test_new_listener_is_live_while_existing_registry_is_unavailable(self):
        data = self.dispatch_data(self.active())
        paused = self.path.with_suffix('.paused')
        self.path.rename(paused)
        try:
            self.servers.append(self.replica(initialize=False))
            for path, status in (('/health/live', 204), ('/health/ready', 503)):
                connection = self.tls.client(self.servers[2], None)
                try:
                    connection.request('GET', path)
                    with connection.getresponse() as response:
                        self.assertEqual(response.status, status)
                finally:
                    connection.close()
            with self.assertLogs('tools.analysis_batch_mandate', level='WARNING'):
                self.denied(data, (503,), 2)
            self.assertFalse(self.path.exists())
        finally:
            paused.rename(self.path)
        self.servers[2].api.sweep()
        self.assertEqual(self.call(2, 'dispatch', data)[0], 200)

    def test_expiry_at_deadline_and_owner_phase(self):
        for phase in ('FIRST_ROUND_COMPLETE', 'CLOSED', 'CANCELLED'):
            active = self.active()
            self.authorities.phase = phase
            self.denied(self.dispatch_data(active), (403,), 0)
            self.denied(self.dispatch_data(active), (403,), 1)
            self.assertEqual(self.servers[1].api.store.get(active['mandateRef'])['state'], 'EXPIRED')
            self.authorities.phase = 'FIRST_ROUND'
        active = self.active()
        self.time.advance(TTL_MS)
        self.servers[0].api.sweep()
        self.denied(self.dispatch_data(active), (403,), 1)
        self.assertEqual(len([e for e in self.events() if e['outcome'] == 'EXPIRED']), 4)

    def test_revoke_after_fresh_check_and_before_admission(self):
        active = self.active()
        entered, resume = threading.Event(), threading.Event()

        def pause():
            entered.set()
            self.assertTrue(resume.wait(8))

        self.authorities.rights_hook = pause
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(self.call, 0, 'dispatch', self.dispatch_data(active))
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.revoke(active)[0], 200)
            finally:
                resume.set()
            self.assertEqual(pending.result()[0], 409)
        self.assertEqual(len(self.owner.calls), 0)

    def test_ambiguous_create_reconciles_on_the_other_replica(self):
        active = self.active()
        args = dict(requestedArtifactType='PROPERTY', intent='first', preferredLanguages=['it'], idempotencyKey=new_id())
        data = self.dispatch_data(active, REQUEST, args)
        self.owner.lose_ack = True
        self.assertEqual(self.call(0, 'dispatch', data)[0], 503)
        self.denied({**data, 'arguments': {**args, 'intent': 'changed'}}, (409,), 1)
        self.denied({**data, 'arguments': {**args, 'idempotencyKey': new_id()}}, (409,), 1)
        status, recovered = self.call(1, 'dispatch', {**data, 'attemptId': new_id()})
        self.assertEqual(status, 200)
        self.assertEqual(list(self.owner.requests.values()), [recovered['requestId']])
        read = self.dispatch_data(active, STATUS, recovered)
        self.assertEqual(self.call(0, 'dispatch', read)[0], 200)

    def test_already_admitted_owner_call_can_finish_after_revocation(self):
        active = self.active()
        args = dict(requestedArtifactType='PROPERTY', intent='first', preferredLanguages=['it'], idempotencyKey=new_id())
        data = self.dispatch_data(active, REQUEST, args)
        entered, resume = threading.Event(), threading.Event()

        def pause():
            entered.set()
            self.assertTrue(resume.wait(8))

        self.owner.hook = pause
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            pending = pool.submit(self.call, 0, 'dispatch', data)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.revoke(active)[0], 200)
                self.denied(data, (403,), 1)
            finally:
                resume.set()
            status, result = pending.result()
        self.assertEqual(status, 200)
        self.denied(self.dispatch_data(active, STATUS, result), (403,), 0)
        self.assertEqual(len(self.owner.calls), 1)

    def test_revocation_requires_owner_or_authorized_ths_and_survives_clock_pause(self):
        active = self.active()
        self.authorities.revoke_as = dict(subject='other-human', operatorAuthorized=True)
        self.assertEqual(self.revoke(active)[0], 403)
        self.authorities.revoke_as = dict(subject='operator', client=self.settings.ths_client, operatorAuthorized=False)
        self.assertEqual(self.revoke(active)[0], 403)
        self.authorities.revoke_as = dict(subject='operator', client=self.settings.ths_client, operatorAuthorized=True)
        self.time.offset = -5_000
        self.assertEqual(self.revoke(active)[0], 200)
        self.denied(self.dispatch_data(active), (403,), 0)

    def test_quota_is_shared_and_start_key_cannot_change_intent(self):
        plan = self.plan()
        active = self.active(plan)
        changed = {**plan, 'plan': {**plan['plan'], 'schemaHash': hash_text('different schema')}}
        self.assertEqual(self.prepare(changed, 1)[0], 409)
        self.settings.rates[SEARCH] = 1
        data = self.dispatch_data(active)
        self.assertEqual(self.call(0, 'dispatch', data)[0], 200)
        self.denied(data, (429,), 1)
        self.time.advance(60_000)
        self.assertEqual(self.call(1, 'dispatch', data)[0], 200)


if __name__ == '__main__':
    unittest.main()
