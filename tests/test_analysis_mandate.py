"""Synthetic Gateway PET C. The clock and both sides of the admission race are controlled."""
import base64
import copy
import io
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from tools.analysis_clients import RemoteIAM, Reservations
from tools.analysis_mandate import Mandates, new_ref
from tools.analysis_protocol import ACTIONS, BINDINGS, CONTRACT, SEARCH_BATCH, TOOL_NAMES, Catalog, Rejected, delegation, digest, parse, wire
from tools.analysis_store import MandateStore
from tools.analysis_service import handler
from tools.mcp_dispatch_contract import capability_contracts
from tools.operational_incidents import SQLiteOperationalIncidentStore

KEY = b'ab' * 32
ISSUER = 'https://iam.fixture.invalid'
PROFILE = dict(assetId='11111111-1111-4111-8111-111111111111', profileId='22222222-2222-4222-8222-222222222222',
               profileVersion=1, schemaHash='sha256:' + 'a' * 64, columnCount=2)
OP = 'semantic.discovery.request'
ARGS = {'requestedArtifactType': 'CLASS', 'idempotencyKey': 'analysis:' + 'c' * 64,
        'intent': 'pratica', 'preferredLanguages': ['it']}
WORKER = 'Bearer synthetic-worker'
SERVICE_SCOPES = ' '.join('ouf.analysis.mandate.' + action for action in ACTIONS)


class ReservationServer:
    def __init__(self):
        self.current, self.subject = True, 'human'
        self.records = {}
        self.request_owners = {}

    def reserve(self, b):
        query = {k: v for k, v in b.items() if k != 'arguments'}
        query.update(contract='ouf.analysis.reservation-check.v1', workload='worker',
                     argumentsHash=digest(wire(b['arguments'])))
        if 'requestId' in b['arguments']:
            query['requestId'] = b['arguments']['requestId']
        self.records[b['attemptId']] = wire(query)

    def evidence(self, body, headers):
        query = parse(body)
        del query['nonce']
        if self.records.get(query['attemptId']) != wire(query):
            raise Rejected(409)
        if 'requestId' in query and self.request_owners.get(query['requestId']) != (query['analysisId'], self.subject):
            raise Rejected(404)
        return dict(requestHash=digest(body), current=self.current, issuer=ISSUER, tenant='tenant', subject=self.subject,
                    reservationRef='reservation-1', ordinalsRef='ordinals-1', changeSeq='4', manifestChecksum='b' * 64,
                    profileHash=digest(wire(PROFILE)), validUntil=5000, requestId=query.get('requestId'))


class MandatePET(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'gateway.sqlite'
        SQLiteOperationalIncidentStore(self.path).db.close()
        self.store = MandateStore(self.path)
        self.now = 1000
        self.server = ReservationServer()
        self.iam_identity = Mock()
        self.claims = dict(active=True, iss=ISSUER, aud='gateway', client_id='worker', ouf_actor_type='SERVICE',
                           sub='worker-id', tenant_id='tenant', exp=6000, scope=SERVICE_SCOPES)
        self.iam_identity.evidence.return_value = self.claims
        self.policy = Mock()
        self.allowed = True
        self.admin = False
        self.policy.evidence.side_effect = self.decide
        self.iam = RemoteIAM(self.iam_identity, self.policy, ISSUER, 'gateway', 'worker')
        # Store/race PET uses the real pinned discovery binding. The wire PET
        # exercises Draft 2020-12 and the materialized Lua execute route.
        rows = capability_contracts()
        self.catalog = Catalog.__new__(Catalog)
        self.catalog.checksum = 'b' * 64
        validator = Mock()
        validator.is_valid.return_value = True
        self.catalog.entries = {op: (rows[cap], '/internal/capabilities/v1/execute' + suffix, validator)
                                for op, (cap, suffix) in BINDINGS.items()}
        self.owner = Mock()
        self.owner.post.return_value = (201, wire({'requestId': PROFILE['assetId']}), None)
        self.api = self.make_api()
        self.issue = dict(contract=CONTRACT, analysisId='a' * 64, profile=PROFILE, manifestChecksum='b' * 64,
                          commandKey=new_ref())
        self.m = self.send('issue', self.issue, self.proof())[1]
        self.b = dict(mandateId=self.m['mandateId'], generation='1', analysisId='a' * 64, intentKey='d' * 64,
                      attemptId=new_ref(), fence='2', operation=OP, arguments=ARGS)
        self.server.reserve(self.b)
        self.revoke = dict(mandateId=self.m['mandateId'], expectedGeneration='1', commandKey=new_ref())

    def make_api(self, **settings):
        return Mandates(MandateStore(self.path), self.catalog, self.iam, Reservations(self.server), self.owner, KEY,
                        clock=lambda: self.now, **{'enabled': True, **settings})

    def decide(self, body, _):
        query = parse(body)
        if not self.allowed or (query['action'] == 'admin-revoke' and not self.admin):
            return dict(requestHash=digest(body), allowed=False)
        return dict(requestHash=digest(body), allowed=True, policyRef='policy1', grantRef='grant1', decisionRef=new_ref(),
                    validUntil=5000, grantExpiresAt=4600 if query['action'] in ('issue', 'dispatch') else 5000,
                    allowedOperations=list(BINDINGS), roles=['viewer'],
                    client='human-client', acr='interactive')

    def proof(self, subject='human', scope='ouf.semantic.discovery ouf.semantic.search ouf.managed-source.preview'):
        return delegation(dict(v=1, purpose='mcp-execute', iss=ISSUER, aud='gateway', workload='worker', actor='HUMAN',
                               tenant='tenant', principal=subject, iat=self.now, exp=self.now+60, acr='interactive',
                               client='human-client', scope=scope), KEY)

    def send(self, action, b, proof=None):
        status, body, meta = self.api.handle(action, wire(b), WORKER, proof)
        return status, parse(body), meta

    def poll(self, generation='1', mandate=None):
        return self.send('status', dict(mandateId=mandate or self.m['mandateId'], generation=generation))

    def test_status_read_only_and_minimal_audit(self):
        """GW-51P-01. A paused worker can poll through WSGI with dispatch disabled."""
        self.api = self.make_api(enabled=False)
        request = wire(dict(mandateId=self.m['mandateId'], generation='1'))
        env = dict(PATH_INFO='/internal/analysis/v1/mandates/status', REQUEST_METHOD='POST',
                   CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(request)), HTTP_AUTHORIZATION=WORKER)
        previous = self.store.get(self.m['mandateId'])
        refs = []
        for _ in range(2):
            response = Mock()
            raw, = handler(self.api)({**env, 'wsgi.input': io.BytesIO(request)}, response)
            self.assertEqual(response.call_args.args[0], '200 OK')
            self.assertLessEqual(len(raw), 1024)
            reply = parse(raw)
            refs.append(reply.pop('decisionRef'))
            self.assertEqual(reply, dict(mandateId=self.m['mandateId'], generation='1',
                                         state='ACTIVE', expiresAt=self.m['expiresAt']))
        self.assertNotEqual(*refs)
        self.assertEqual(previous, self.store.get(self.m['mandateId']))
        with self.store.transaction() as db:
            for table, count in (('analysis_command_v1', 1), ('analysis_attempt_v1', 0), ('analysis_discovery_v1', 0)):
                self.assertEqual(db.execute(f'select count(*) from {table}').fetchone()[0], count)
            for ref in refs:
                row, = db.execute('select evidence from analysis_audit_v1 where decision=?', (ref,)).fetchone()
                audit = parse(row)
                self.assertEqual(set(audit), {'action', 'outcome', 'mandateId', 'generation', 'workloadRef'})
                self.assertEqual((audit['action'], audit['outcome']), ('status', 'ACTIVE'))
                self.assertRegex(audit['workloadRef'], '^[a-f0-9]{64}$')
        self.owner.post.assert_not_called()

    def test_status_revocation_and_superseded_generation(self):
        """GW-51P-02. Revoke during the read decision fences the old generation."""
        def revoke_during_status(raw, headers):
            if parse(raw)['action'] == 'status':
                self.policy.evidence.side_effect = self.decide
                self.assertEqual(self.send('revoke', self.revoke, self.proof())[0], 200)
            return self.decide(raw, headers)

        self.policy.evidence.side_effect = revoke_during_status
        self.assertEqual(self.poll()[:2], (409, {'code': 'ANALYSIS_STALE_EXECUTION'}))
        self.now = 4600
        status, reply, _ = self.poll('2')
        self.assertEqual((status, reply['state'], reply['generation']), (200, 'REVOKED', '2'))
        self.assertEqual(reply['expiresAt'], self.m['expiresAt'])

    def test_status_expired(self):
        """GW-51P-03. Expiry at the deadline is observed without changing the record."""
        self.now = 4599
        self.assertEqual(self.poll()[1]['state'], 'ACTIVE')
        self.now += 1
        self.assertEqual(self.poll()[1]['state'], 'EXPIRED')
        self.assertEqual(self.store.get(self.m['mandateId'])['state'], 'ACTIVE')
        self.assertEqual(self.poll('2')[:2], (409, {'code': 'ANALYSIS_STALE_EXECUTION'}))

    def test_status_foreign_subject(self):
        """GW-51P-04. Two HUMAN mandates share the same plan, tenant and MCP client."""
        second = self.send('issue', self.issue, self.proof('other'))[1]['mandateId']
        def authorize_read(raw, headers):
            q = parse(raw)
            self.assertEqual((q['action'], q['actor']), ('status', 'SERVICE'))
            if (q['workloadSubject'], q['tenant'], q['subject'], q['mandateId']) != (
                    'worker-id', 'tenant', 'human', self.m['mandateId']):
                return dict(requestHash=digest(raw), allowed=False)
            return self.decide(raw, headers)

        self.policy.evidence.side_effect = authorize_read
        self.assertEqual(self.poll()[0], 200)
        unknown = (404, {'code': 'ANALYSIS_MANDATE_UNKNOWN'}, {})
        self.assertEqual(self.poll('0', second), unknown)
        self.assertEqual(self.poll(mandate=new_ref()), unknown)
        self.claims['sub'] = 'other-worker-id'
        self.assertEqual(self.poll(), unknown)
        self.claims['tenant_id'] = 'other-tenant'
        self.assertEqual(self.poll(), unknown)
        self.iam.decisions = None
        self.claims.update(sub='worker-id', tenant_id='tenant')
        self.assertEqual(self.poll()[:2], (503, {'code': 'ANALYSIS_AUTHORITY_UNAVAILABLE'}))

    def test_status_foreign_workload(self):
        """GW-51P-05. An authenticated foreign service sees the unknown-reference error."""
        self.claims['client_id'] = 'other-service'
        self.assertEqual(self.poll()[:2], (404, {'code': 'ANALYSIS_MANDATE_UNKNOWN'}))
        self.claims['active'] = False
        self.assertEqual(self.poll()[0], 403)

    def test_status_quota(self):
        """GW-51P-06. Failed lookups consume quota shared across restarts and concurrent readers."""
        for value in (True, 0, 3601, '60'):
            with self.assertRaises(ValueError):
                self.make_api(status_reads_per_minute=value)
        self.api = self.make_api(status_reads_per_minute=2)
        self.assertEqual(self.poll(mandate=new_ref())[0], 404)
        self.api = self.make_api(status_reads_per_minute=2)
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.poll(), range(2)))
        self.assertEqual(sorted(r[0] for r in results), [200, 429])
        self.now += 59
        self.assertEqual(self.poll(), (429, {'code': 'ANALYSIS_BACKOFF'}, {'Retry-After': '1'}))
        self.assertEqual(self.send('revoke', self.revoke, self.proof())[0], 200)
        self.now += 1
        self.assertEqual(self.poll('2')[1]['state'], 'REVOKED')

    def test_status_input(self):
        """GW-51P-07. Exact wire body, bounded before reading the private request stream."""
        request = dict(mandateId=self.m['mandateId'], generation='1')
        for bad in ({}, dict(request, generation=1), dict(request, generation='01'),
                    dict(request, mandateId='unknown'), dict(request, subject='human')):
            self.assertEqual(self.send('status', bad)[:2], (400, {'code': 'ANALYSIS_INPUT_INVALID'}))
        response = Mock()
        raw, = handler(self.api)(dict(PATH_INFO='/internal/analysis/v1/mandates/status', REQUEST_METHOD='POST',
                                      CONTENT_TYPE='application/json', CONTENT_LENGTH='1025'), response)
        self.assertEqual(parse(raw), {'code': 'ANALYSIS_INPUT_INVALID'})

    def test_commands_restart_and_scope(self):
        """GW-51N-01. Issue idempotency, closed bodies, protected identity and versioned revoke."""
        self.api = self.make_api()
        self.assertEqual(self.send('issue', self.issue, self.proof())[1], self.m)
        self.assertEqual(self.send('issue', dict(self.issue, analysisId='f'*64), self.proof())[1]['code'],
                         'ANALYSIS_COMMAND_CONFLICT')
        self.assertEqual(self.send('issue', self.issue)[0], 403)
        self.assertEqual(self.send('issue', self.issue, self.proof()+'x')[0], 403)
        for patch in ({'extra': True}, {'commandKey': '00000000-0000-0000-0000-000000000000'},
                      {'profile': dict(PROFILE, columnCount=True)}, {'profile': dict(PROFILE, profileVersion=None)}):
            self.assertEqual(self.send('issue', dict(self.issue, **patch), self.proof())[0], 400)
        self.assertEqual(self.api.handle('issue', b'{"a":1,"a":2}', WORKER)[0], 400)
        self.assertEqual(self.send('revoke', self.revoke, self.proof('other'))[0], 404)
        self.assertEqual(self.send('revoke', self.revoke)[0], 404)
        self.admin = True
        reply = self.send('revoke', self.revoke)
        self.assertEqual(reply[1]['generation'], '2')
        self.assertEqual(reply, self.send('revoke', self.revoke))
        self.assertEqual(self.send('revoke', dict(self.revoke, commandKey=new_ref()))[1]['code'],
                         'ANALYSIS_COMMAND_CONFLICT')

    def test_dispatch_rechecks_and_one_admission(self):
        """GW-51N-02. Each admitted attempt consumes its own current decision and proof."""
        self.assertEqual(self.send('dispatch', self.b)[0], 201)
        first, headers, _, path = self.owner.post.call_args.args
        body = parse(first)
        self.assertEqual(body['Arguments'], ARGS)
        self.assertTrue(path.endswith('/semantic/discovery/request'))
        self.assertEqual(headers['Idempotency-Key'], ARGS['idempotencyKey'])
        encoded = headers['X-OUF-Delegation'].split('.')[0]
        self.assertEqual(parse(base64.urlsafe_b64decode(encoded + '==='))['exp'], self.now+30)
        self.assertEqual(self.send('dispatch', self.b)[0], 409)
        again = dict(self.b, attemptId=new_ref())
        self.server.reserve(again)
        new_status, _, meta = self.send('dispatch', again)
        self.assertEqual(new_status, 201)
        self.assertNotEqual(meta['X-OUF-Analysis-Decision'], body['AuthorizationDecisionRef'])
        self.assertEqual(self.owner.post.call_count, 2)
        lower = dict(self.b, attemptId=new_ref(), fence='1')
        self.server.reserve(lower)
        self.assertEqual(self.send('dispatch', lower)[0], 409)
        for args in (dict(ARGS, intent='changed'), dict(ARGS, idempotencyKey='analysis:'+'e'*64)):
            changed = dict(self.b, attemptId=new_ref(), arguments=args)
            self.server.reserve(changed)
            self.assertEqual(self.send('dispatch', changed)[1]['code'], 'ANALYSIS_COMMAND_CONFLICT')

    def test_identity_reservation_and_current_authority(self):
        """GW-51N-03. Foreign subjects, stale fence, altered arguments, denied and unavailable IAM."""
        self.server.subject = 'other'
        self.assertEqual(self.send('dispatch', self.b)[1]['code'], 'ANALYSIS_MANDATE_UNKNOWN')
        self.server.subject = 'human'
        for changed in (dict(self.b, fence='1'), dict(self.b, arguments=dict(ARGS, intent='other'))):
            self.assertEqual(self.send('dispatch', changed)[1]['code'], 'ANALYSIS_STALE_EXECUTION')
        self.server.current = False
        self.assertEqual(self.send('dispatch', self.b)[0], 409)
        self.server.current = True
        self.claims['active'] = False
        self.assertEqual(self.send('dispatch', self.b)[0], 403)
        self.claims['active'] = True
        self.allowed = False
        self.assertEqual(self.send('dispatch', self.b)[0], 403)
        self.allowed = True
        self.iam.decisions = None
        self.assertEqual(self.send('dispatch', self.b)[:2], (503, {'code': 'ANALYSIS_AUTHORITY_UNAVAILABLE'}))
        self.owner.post.assert_not_called()

    def test_disabled_expiry_and_paused_revoke(self):
        """GW-51N-04. Disabled by default, exact expiry and a worker resumed after revocation."""
        api = Mandates(self.store, self.catalog, self.iam, Reservations(self.server), self.owner, KEY, clock=lambda:self.now)
        self.assertEqual(api.handle('dispatch', wire(self.b), WORKER)[0], 403)
        self.now = 4599
        self.assertEqual(self.send('dispatch', self.b)[0], 201)
        proof = self.owner.post.call_args.args[1]['X-OUF-Delegation'].split('.')[0]
        self.assertEqual(parse(base64.urlsafe_b64decode(proof+'==='))['exp'], 4600)
        self.now = 4600
        self.assertEqual(self.send('dispatch', self.b)[0], 410)
        self.assertEqual(self.send('revoke', self.revoke, self.proof())[0], 200)
        self.api = self.make_api()
        self.assertEqual(self.send('dispatch', self.b)[0], 409)
        self.assertEqual(self.owner.post.call_count, 1)

    def test_race_and_crash_evidence(self):
        """GW-51N-05 / GW-58F-01. Revocation while the admitted owner call is blocked."""
        entered, resume = threading.Event(), threading.Event()
        def slow(*_):
            entered.set()
            self.assertTrue(resume.wait(5))
            return 201, wire({'requestId': PROFILE['assetId']}), None
        self.owner.post.side_effect = slow
        with ThreadPoolExecutor(2) as pool:
            pending = pool.submit(self.send, 'dispatch', self.b)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.send('revoke', self.revoke, self.proof())[0], 200)
            finally:
                resume.set()
            status, body, headers = pending.result()
            self.assertEqual((status, body), (409, {'code': 'ANALYSIS_STALE_EXECUTION'}))
            self.assertEqual(headers['X-OUF-Analysis-Effect'], 'IN_FLIGHT')
            self.assertEqual(headers['X-OUF-Analysis-Stale-Cause'], 'REVOKED')
        with self.store.transaction() as db:
            rows = [parse(row[0]) for row in db.execute('select evidence from analysis_audit_v1 order by sequence')]
        self.assertEqual(rows[-2]['inFlightCount'], 1)
        self.assertTrue(rows[-1]['crossedRevocation'])
        self.assertEqual(rows[-1]['requestId'], PROFILE['assetId'])
        for sensitive in (WORKER, ARGS['intent'], ARGS['idempotencyKey'], 'X-OUF-Delegation'):
            self.assertNotIn(sensitive.encode(), wire(rows))

    def test_revoke_wins_before_admission_and_concurrent_commands(self):
        """GW-51N-12. A late positive IAM response cannot undo a committed revocation."""
        entered, release = threading.Event(), threading.Event()
        def decide(raw, headers):
            decision = self.decide(raw, headers)
            if parse(raw)['action'] == 'dispatch':
                entered.set()
                self.assertTrue(release.wait(5))
            return decision
        self.policy.evidence.side_effect = decide
        with ThreadPoolExecutor(3) as pool:
            attempt = pool.submit(self.send, 'dispatch', self.b)
            try:
                self.assertTrue(entered.wait(5))
                commands = [pool.submit(self.send, 'revoke', self.revoke, self.proof()) for _ in range(2)]
                results = [job.result() for job in commands]
                self.assertEqual(results[0], results[1])
                self.assertEqual(results[0][0], 200)
            finally:
                release.set()
            self.assertEqual(attempt.result()[1]['code'], 'ANALYSIS_STALE_EXECUTION')
        self.owner.post.assert_not_called()

    def test_expired_delegation_drift_and_backpressure(self):
        """GW-51N-13. Expired HUMAN, changed manifest/policy and explicit throttling fail closed."""
        old = self.proof()
        self.now += 60
        self.assertEqual(self.send('issue', self.issue, old)[0], 403)
        self.catalog.checksum = 'f'*64
        self.assertEqual(self.send('dispatch', self.b)[0], 409)
        self.catalog.checksum = 'b'*64
        self.policy.evidence.side_effect = lambda raw, h: dict(self.decide(raw,h), policyRef='new-policy')
        self.assertEqual(self.send('dispatch', self.b)[0], 403)
        self.policy.evidence.side_effect = Rejected(429, retry_after='15')
        self.assertEqual(self.send('dispatch', self.b), (429, {'code':'ANALYSIS_BACKOFF'}, {'Retry-After':'15'}))
        self.owner.post.assert_not_called()

    def test_higher_fence_supersedes_late_response(self):
        """GW-51N-15 / GW-58F-02. A newer fence supersedes a response on an active mandate."""
        self.check_superseded_response(revoke=False)

    def test_revoke_superseded_attempt(self):
        """GW-58F-03. Revocation takes precedence after the successor has returned."""
        self.check_superseded_response(revoke=True)

    def check_superseded_response(self, revoke):
        entered, resume = threading.Event(), threading.Event()
        def send(body, *_):
            if parse(body)['AttemptID'] == self.b['attemptId']:
                entered.set()
                self.assertTrue(resume.wait(5))
            return 200, wire({'requestId':PROFILE['assetId']}), None
        self.owner.post.side_effect = send
        successor = dict(self.b, attemptId=new_ref(), fence='3')
        self.server.reserve(successor)
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(self.send, 'dispatch', self.b)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.send('dispatch', successor)[0], 200)
                if revoke:
                    self.assertEqual(self.send('revoke', self.revoke, self.proof())[0], 200)
            finally:
                resume.set()
            status, body, headers = pending.result()
            self.assertEqual((status, body), (409, {'code': 'ANALYSIS_STALE_EXECUTION'}))
            self.assertEqual(headers['X-OUF-Analysis-Effect'], 'IN_FLIGHT')
            self.assertEqual(headers['X-OUF-Analysis-Stale-Cause'], 'REVOKED' if revoke else 'SUPERSEDED')

    def test_batch_rate_limit(self):
        """GW-58F-05. Batch throttles preserve the contracted response and integer wait."""
        contracted = b'{ "code": "SEM_BATCH_RATE_LIMITED", "observedSeconds": 0.5 }'
        for payload, retry, expected, wait in (
                (b'busy', '17', wire({'code': 'SEM_BATCH_RATE_LIMITED'}), '17'),
                (b'{"code":"unrelated"}', '-2', wire({'code': 'SEM_BATCH_RATE_LIMITED'}), None),
                (contracted, '0', contracted, '0')):
            with self.subTest(payload=payload):
                b = dict(self.b, operation=SEARCH_BATCH, attemptId=new_ref(), arguments={})
                self.server.reserve(b)
                self.owner.post.return_value = 429, payload, retry
                status, result, headers = self.api.handle('dispatch', wire(b), WORKER)
                self.assertEqual((status, result, headers.get('Retry-After')), (429, expected, wait))

    def test_issue_requires_preview_before_persistence(self):
        """GW-58F-06. A discovery-only intersection creates no mandate or command receipt."""
        issue = dict(self.issue, analysisId='f' * 64, commandKey=new_ref())
        denied = self.send('issue', issue, self.proof(scope='ouf.semantic.discovery'))
        self.assertEqual(denied[:2], (403, {'code': 'ANALYSIS_AUTHORITY_DENIED'}))
        with self.store.transaction() as db:
            self.assertIsNone(db.execute('select id from analysis_mandate_v1 where plan=?', (issue['analysisId'],)).fetchone())
            self.assertIsNone(db.execute('select reply from analysis_command_v1 where command=?', (issue['commandKey'],)).fetchone())

    def test_partial_issue_replay(self):
        """GW-58F-13. A replay cannot return a pre-upgrade receipt missing preview."""
        with self.store.transaction() as db:
            m = self.store.read(db, self.m['mandateId'])
            m['allowed'] = [OP]
            db.execute('update analysis_mandate_v1 set record=? where id=?', (wire(m), m['id']))
            db.execute('update analysis_command_v1 set reply=? where command=?',
                       (wire(dict(self.m, allowedOperations=[OP])), self.issue['commandKey']))
        self.assertEqual(self.send('issue', self.issue, self.proof())[:2], (403, {'code': 'ANALYSIS_AUTHORITY_DENIED'}))

    def test_denied_operations_and_ambiguous_send(self):
        """GW-51N-06. Neither an unknown operation nor a repeated uncertain attempt can forward."""
        other = dict(self.b, operation='semantic.discovery.adopt')
        self.server.reserve(other)
        self.assertEqual(self.send('dispatch', other)[0], 403)
        self.server.reserve(self.b)
        self.owner.post.side_effect = Rejected(503)
        self.assertEqual(self.send('dispatch', self.b)[0], 503)
        self.api = self.make_api()
        self.assertEqual(self.send('dispatch', self.b)[0], 409)
        self.assertEqual(self.send('revoke', self.revoke, self.proof())[0], 200)
        with self.store.transaction() as db:
            phase, crossed = db.execute('select phase,crossed_revocation from analysis_attempt_v1').fetchone()
        self.assertEqual((phase, crossed), ('UNCERTAIN', 1))

    def test_private_http_entry_and_proof_headers(self):
        """GW-51N-14. Exact private HTTP entry point and metadata. Ignore caller-supplied owner proofs."""
        serve = handler(self.api)
        def post(path, body, **changes):
            env = {'PATH_INFO':'/internal/analysis/v1/mandates/'+path, 'REQUEST_METHOD':'POST',
                   'CONTENT_TYPE':'application/json', 'CONTENT_LENGTH':str(len(body)), 'wsgi.input':io.BytesIO(body),
                   'HTTP_AUTHORIZATION':WORKER, 'HTTP_X_OUF_SEMANTIC_DISCOVERY_RECEIPT':'untrusted', **changes}
            response = Mock()
            result, = serve(env, response)
            status, headers = response.call_args.args
            return int(status[:3]), parse(result), dict(headers)
        self.assertEqual(post('dispatch/other', wire(self.b))[0], 400)
        self.assertEqual(post('dispatch', wire(self.b), QUERY_STRING='other=path')[0], 400)
        self.assertEqual(post('dispatch', wire(self.b), HTTP_CONTENT_ENCODING='gzip')[0], 400)
        status, result, headers = post('dispatch', wire(self.b), HTTP_X_OUF_DELEGATION='forged')
        self.assertEqual((status, result), (201, {'requestId':PROFILE['assetId']}))
        self.assertEqual(headers['X-Correlation-ID'], headers['X-OUF-Analysis-Decision'])
        forwarded = self.owner.post.call_args.args[1]
        self.assertNotIn('untrusted', forwarded.values())
        self.assertNotIn('forged', forwarded.values())


def test_current_pinned_catalog():
    """GW-51N-07. Only the five qualified bindings and COLUMNS for this profile are admissible."""
    rows = []
    for name, (cap, _) in BINDINGS.items():
        row = copy.deepcopy(capability_contracts()[cap])
        row.update(publicationState='ACTIVE', toolName=TOOL_NAMES.get(name, name))
        rows.append(row)
    catalog = Catalog(wire({'capabilities': rows}))
    assert set(catalog.entries) == set(BINDINGS)
    # GW-58A-01: the batch row keeps the MCP tool name; the operation name is not a tool.
    # GW-58O-01: the expected name is the literal of the real MCP manifest (1.17.0 onwards,
    # `internal/manifest/capabilities.json`), not derived from TOOL_NAMES itself.
    assert TOOL_NAMES == {SEARCH_BATCH: 'semantic.search.batch'}
    literal = copy.deepcopy(rows)
    for row in literal:
        if row['capabilityId'] == SEARCH_BATCH:
            row['toolName'] = 'semantic.search.batch'
    assert SEARCH_BATCH in Catalog(wire({'capabilities': literal})).entries
    renamed = copy.deepcopy(rows)
    for row in renamed:
        if row['capabilityId'] == SEARCH_BATCH:
            row['toolName'] = SEARCH_BATCH
    assert SEARCH_BATCH not in Catalog(wire({'capabilities': renamed})).entries
    args = {'view': 'COLUMNS', 'assetId': PROFILE['assetId'], 'profileId': PROFILE['profileId']}
    assert catalog.resolve({'operation':'source.file.preview', 'arguments':args}, PROFILE)[1].endswith('/managed.file/preview')
    for other in ({'view':'ASSETS'}, dict(args, assetId=new_ref())):
        with unittest.TestCase().assertRaises(Rejected):
            catalog.resolve({'operation':'source.file.preview', 'arguments':other}, PROFILE)
    rows[0]['gatewayBindingRef'] = 'capability://other'
    assert 'source.file.preview' not in Catalog(wire({'capabilities': rows})).entries
