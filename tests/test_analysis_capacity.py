"""GW-55G. Exercise the private WSGI listener with local IAM/MCP/owner fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import io
import math
from pathlib import Path
import sqlite3
from threading import Barrier, Event
import unittest
from unittest.mock import Mock, patch

from tests import test_analysis_mandate as fixtures
from tools.analysis_capacity import Capacity
from tools.analysis_mandate import new_ref
from tools.analysis_protocol import BASE, CAPACITY_FIELDS, RENEWALS, capacity_profile, parse, wire
from tools.analysis_renewal import Renewals
from tools.analysis_service import application, handler


class CapacityPET(unittest.TestCase):
    def setUp(self):
        self.pet = fixtures.MandatePET()
        self.addCleanup(self.pet.doCleanups)
        self.pet.setUp()
        self.capacity = Capacity({'dataSlots': 2, 'threadsPerProcess': 6, 'instanceConnections': 6})
        self.endpoint = Mock(path='/')
        self.app = handler(self.pet.api, Renewals(self.pet.api, self.endpoint, 'ths'), self.capacity)
        self.workers = ThreadPoolExecutor(max_workers=6)
        self.addCleanup(self.workers.shutdown)
        self.status = dict(mandateId=self.pet.m['mandateId'], generation='1')

    def post(self, path, body, bearer=fixtures.WORKER, proof=None):
        raw = wire(body)
        env = dict(PATH_INFO=path, REQUEST_METHOD='POST', CONTENT_TYPE='application/json',
                   CONTENT_LENGTH=str(len(raw)), HTTP_AUTHORIZATION=bearer, HTTP_X_OUF_DELEGATION=proof)
        response = Mock()
        result, = self.app({**env, 'wsgi.input': io.BytesIO(raw)}, response)
        status, headers = response.call_args.args
        return int(status[:3]), parse(result), dict(headers)

    def metrics(self):
        response = Mock()
        body, = self.app(dict(PATH_INFO='/metrics', REQUEST_METHOD='GET'), response)
        self.assertEqual(response.call_args.args[0], '200 OK')
        return dict(line.rsplit(' ', 1) for line in body.decode('ascii').splitlines())

    def value(self, metric, pool, percentile=None):
        labels = f'service="analysis_mandate",traffic_class="{pool}"'
        if percentile:
            labels += f',quantile="{percentile}"'
        return float(self.metrics()[f'{metric}{{{labels}}}'])

    @contextmanager
    def blocked_owners(self):
        pet = self.pet
        entered, release = Barrier(3), Event()

        def owner(*_):
            entered.wait(10)
            self.assertTrue(release.wait(15))
            return 201, wire({'requestId': fixtures.PROFILE['assetId']}), None

        pet.owner.post.side_effect = owner
        futures = []
        try:
            for digit in ('1', '2'):
                request = dict(pet.b, attemptId=new_ref(), intentKey=digit * 64,
                               arguments=dict(pet.b['arguments'], idempotencyKey='analysis:' + digit * 64))
                pet.server.reserve(request)
                futures.append(self.workers.submit(self.post, BASE + 'dispatch', request))
            entered.wait(10)
            yield futures
        finally:
            release.set()

    def assert_pressure(self, path, body):
        status, reply, headers = self.post(path, body)
        self.assertEqual((status, reply, headers['Retry-After']), (429, {'code': 'ANALYSIS_BACKOFF'}, '1'))

    def test_two_controls_under_data_pressure(self):
        """GW-55G-01 / C.2. Both controls reach IAM while both owners remain blocked."""
        pet = self.pet
        pet.admin = True
        entered, release_status, release_revoke = Barrier(3), Event(), Event()

        def policy(raw, headers):
            action = parse(raw)['action']
            if action in ('status', 'admin-revoke'):
                entered.wait(10)
                release = release_status if action == 'status' else release_revoke
                self.assertTrue(release.wait(10))
            return pet.decide(raw, headers)

        pet.policy.evidence.side_effect = policy
        with self.blocked_owners() as owners:
            self.assert_pressure(BASE + 'dispatch', pet.b)
            self.assert_pressure(BASE + 'issue', pet.issue)
            status = self.workers.submit(self.post, BASE + 'status', self.status)
            revoke = self.workers.submit(self.post, BASE + 'revoke', pet.revoke)
            try:
                entered.wait(10)
                self.assertEqual(self.value('gateway_inflight_requests', 'control'), 2)
                self.assertEqual(self.value('gateway_analysis_sqlite_connections', 'data'), 2)
                self.assertEqual(self.value('gateway_analysis_sqlite_connections', 'control'), 2)
                self.assert_pressure(BASE + 'renewal-check', {})
                self.assertEqual(self.value('gateway_analysis_sqlite_connections_opened_total', 'control'), 2)
                release_status.set()
                self.assertEqual(status.result(5)[1]['state'], 'ACTIVE')
            finally:
                release_status.set()
                release_revoke.set()
            self.assertEqual(revoke.result(5)[1]['state'], 'REVOKED')
        for owner in owners:
            status, _, headers = owner.result(5)
            self.assertEqual((status, headers['X-OUF-Analysis-Effect']), (409, 'IN_FLIGHT'))
        self.assertEqual(self.value('gateway_analysis_pressure_refusals_total', 'data'), 2)
        self.assertEqual(self.value('gateway_analysis_pressure_refusals_total', 'control'), 1)
        self.assertEqual(self.value('gateway_analysis_sqlite_connections', 'data'), 0)

    def test_nested_relay(self):
        """GW-55G-02 / C.3. A live decide obtains a control receipt under data and relay saturation."""
        pet = self.pet
        claims = dict(pet.claims, sub='human', client_id='ths', ouf_actor_type='HUMAN',
                      acr='interactive', scope='ouf.analysis.renewal.decide')
        pet.claims['scope'] = 'ouf.analysis.mandate.renewal-check'
        pet.iam_identity.evidence.side_effect = lambda raw, _: claims if raw == b'token=ths' else pet.claims
        command = dict(reviewRef='r' * 22, proposalVersion=1, proposalHash='a' * 64, expectedSeq='7',
                       commandKey=new_ref(), decision='APPROVE', items=[])
        check = dict(command, **self.status, analysisId=pet.issue['analysisId'], incidentId='incident-1')

        def policy(raw, headers):
            if parse(raw)['action'] == 'renew-budget':
                for name, occupancy in [('data', 2), ('relay', 1), ('control', 1)]:
                    self.assertEqual(self.value('gateway_inflight_requests', name), occupancy)
                self.assertEqual(self.value('gateway_analysis_sqlite_connections', 'relay'), 0)
                status = self.workers.submit(self.post, BASE + 'status', self.status)
                self.assertEqual(status.result(5)[1]['state'], 'ACTIVE')
            return pet.decide(raw, headers)

        def mcp(raw, headers, limit, path):
            self.assertEqual((raw, path), (wire(command), RENEWALS + 'decide'))
            self.assert_pressure(RENEWALS + 'read', {})
            nested = self.workers.submit(self.post, BASE + 'renewal-check', check,
                                         fixtures.WORKER, headers['X-OUF-Delegation'])
            status, receipt, _ = nested.result(5)
            return status, wire(receipt), None

        pet.policy.evidence.side_effect = policy
        self.endpoint.post.side_effect = mcp
        with self.blocked_owners() as owners:
            status, receipt, _ = self.workers.submit(
                self.post, RENEWALS + 'decide', command, 'Bearer ths').result(8)
            self.assertEqual((status, receipt['grantRef']), (200, 'grant1'))
        for owner in owners:
            self.assertEqual(owner.result(5)[0], 201)
        self.assertEqual(self.value('gateway_analysis_pressure_refusals_total', 'relay'), 1)

    def test_metrics_closed_dispatch_and_windows(self):
        """GW-55G-03 / C.2/C.3. Real SQLite lifetimes and bounded quantiles with dispatch closed."""
        pet = self.pet
        clock = Mock(return_value=0)
        capacity = Capacity({'latencyWindowSamples': 2, 'latencyWindowSeconds': 10}, clock=clock)
        self.app = handler(pet.make_api(enabled=False), capacity=capacity)
        for duration in (1, 3, 2):
            # start, admission decision, end of service
            start = clock.return_value
            clock.side_effect = [start, start + 0.125, start + duration + 0.125]
            self.assertEqual(self.post(BASE + 'dispatch', pet.b)[0], 403)
            clock.side_effect = None
            clock.return_value = start + duration + 0.125
        self.assertEqual(self.post(BASE + 'status', self.status)[1]['state'], 'ACTIVE')
        self.assertEqual(self.post(BASE + 'revoke', pet.revoke, proof=pet.proof())[1]['state'], 'REVOKED')
        for name, expected in [('0.50', 2), ('0.95', 3), ('0.99', 3)]:
            self.assertEqual(self.value('gateway_request_duration_seconds', 'data', name), expected)
            self.assertEqual(self.value('gateway_analysis_admission_wait_seconds', 'data', name), 0.125)
        self.assertEqual(self.value('gateway_analysis_sqlite_connections_opened_total', 'control'), 2)
        for name in ('data', 'control', 'relay'):
            self.assertEqual(self.value('gateway_analysis_sqlite_connections', name), 0)
        self.assertEqual(self.value('gateway_analysis_sqlite_connections_opened_total', 'data'), 3)
        clock.return_value += 10
        self.assertTrue(math.isnan(self.value('gateway_request_duration_seconds', 'data', '0.99')))
        self.assertEqual(self.value('gateway_request_duration_seconds_window_samples', 'data'), 0)
        pet.owner.post.assert_not_called()

    def test_installation_factory(self):
        """GW-55G-03. Reject invalid declarations before TLS/DB and load predecessor defaults."""
        for key, (_, minimum, maximum) in CAPACITY_FIELDS.items():
            for value in (True, minimum - 1, maximum + 1):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    capacity_profile({key: value})
        config_file = Path(self.pet.path).with_suffix('.json')
        manifest = config_file.with_suffix('.manifest')
        manifest.write_bytes(wire({'capabilities': []}))
        endpoint_config = dict.fromkeys(('url', 'caFile', 'clientCertFile', 'clientKeyFile'), 'fixture')
        cfg = dict(contract='ouf.analysis.installation.v1', store=str(self.pet.path), manifestFile=str(manifest),
                   issuer=fixtures.ISSUER, audience='gateway', workload='worker', delegationKeyEnv='TEST_KEY',
                   introspection=endpoint_config, decisions=None, reservations=endpoint_config, execute=endpoint_config,
                   timeoutSeconds=1, mandateTtlSeconds=3600, proofTtlSeconds=30, maxResultBytes=1048576)
        with patch.dict('os.environ', OUF_ANALYSIS_CONFIG=str(config_file), TEST_KEY='ab' * 32), \
                patch('tools.analysis_service.https_endpoint', return_value=Mock(path='/')) as endpoint, \
                patch('tools.analysis_service.Catalog', return_value=self.pet.catalog):
            for bad in (None, [], {'unknown': 1}, {'ControlReservedSlots': 1}, {'threadsPerProcess': 7},
                        {'instanceConnections': 7}, {'processes': 2, 'instanceConnections': 15}):
                config_file.write_bytes(wire(dict(cfg, capacity=bad)))
                with self.assertRaises(ValueError):
                    application()
            endpoint.assert_not_called()
            for extra, limit in [({}, 2), ({'capacity': {'processes': 2, 'instanceConnections': 16}}, 4)]:
                config_file.write_bytes(wire(dict(cfg, **extra)))
                self.app = application()
                self.assertEqual(self.value('gateway_analysis_instance_slot_limit', 'control'), limit)

    def test_physical_connection_cleanup(self):
        """GW-55G-03. Observe the physical open, busy timeout and close on an owner failure."""
        pet = self.pet
        connect = pet.api.store.connect
        opened = []

        def observe():
            db = connect()
            opened.append(db)
            return db

        def failed_owner(*_):
            db, = opened
            self.assertFalse(db.in_transaction)
            self.assertEqual(db.execute('pragma busy_timeout').fetchone(), (1000,))
            raise OSError('fixture')

        pet.owner.post.side_effect = failed_owner
        with patch.object(pet.api.store, 'connect', side_effect=observe):
            self.assertEqual(self.post(BASE + 'dispatch', pet.b)[0], 503)
            self.assertEqual(self.post(BASE + 'status', self.status)[0], 200)
        self.assertEqual(len(opened), 2)
        for db in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                db.execute('select 1')
        self.assertEqual(self.value('gateway_inflight_requests', 'data'), 0)
        self.assertEqual(self.value('gateway_analysis_sqlite_connections', 'data'), 0)
