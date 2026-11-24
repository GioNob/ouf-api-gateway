"""Offline Keycloak OUF PET. The HTTP fixture owns resource metadata and live UMA decisions."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import io
import threading
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import patch

from tests import test_analysis_mandate as fixtures
from tests.test_analysis_transport import tls_server
from tools.analysis_clients import RemoteIAM
from tools.analysis_mandate import new_ref
from tools.analysis_protocol import Rejected, b64, delegation, digest, parse, wire
from tools.iam_keycloak_decisions import CHECK, Verifier, VerifierStore, grant_name, limit, retry_seconds


ISSUER = 'https://iam.fixture.invalid/realms/fixture'
WORKLOAD = 'worker'
RS = 'assignment-server'
OP = fixtures.OP


def profile():
    quota = dict(value=600, default=60, maximum=600)
    return dict(contract='ouf.iam-profile.v1', kind='keycloak-ouf',
                trust=dict(issuer=ISSUER, gatewayAudience='gateway',
                           introspection='https://private.fixture.invalid/introspection',
                           decisions='https://private.fixture.invalid/decisions'),
                clients={k: dict(clientId=v, audience='gateway') for k, v in [('mcp', WORKLOAD), ('ths', 'ths')]},
                grant=dict(mechanism='authorization-resource', resourceType='assignment', grantRef='iam-resource-id',
                           lookup='current-resource-permission', decisionContract=CHECK, introspectionProtocol='RFC7662',
                           revocation='withdraw-permission-and-invalidate-assignment-credential',
                           revocationTtlSeconds=dict(value=12, default=10, maximum=30)),
                iam=dict(introspectionsPerMinute=quota.copy(), decisionsPerMinute=quota.copy()))


class Keycloak:
    def __init__(self):
        self.resources, self.permissions, self.identities = {}, {}, {}
        self.failure, self.duplicate = None, False
        self.evaluations = []
        self.resume = threading.Event()
        self.secret = new_ref()

    def assign(self, human, issue):
        credential = 'credential-' + human
        subject = 'principal-' + human
        self.identities[credential] = dict(iss=ISSUER, aud=['gateway'], sub=subject, tenant_id='tenant',
                                           client_id=WORKLOAD, exp=6000, ouf_actor_type='SERVICE', active=True,
                                           scope='ouf.analysis.mandate.renewal-check')
        identity = dict(issuer=ISSUER, tenant='tenant', workload=WORKLOAD, workloadSubject=subject)
        attrs = dict(**identity, analysisId=issue['analysisId'], manifestChecksum=issue['manifestChecksum'],
                     profileHash=digest(wire(issue['profile'])), grantExpiresAt='4800', policyRef='policy',
                     client='human-client', acr='interactive')
        grant = new_ref()
        self.resources[grant] = dict(_id=grant, name=grant_name(identity), type='assignment',
                                     owner={'id': human}, ownerManagedAccess=True,
                                     attributes={k: [v] for k, v in attrs.items()})
        self.permissions[credential, grant] = {'issue', 'dispatch', 'status', 'revoke', 'renew-budget', OP}
        return grant

    def http(self, method, path, headers, body):
        url = urlsplit(path)
        base = '/realms/fixture'
        form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        auth = headers.get('Authorization')
        if method == 'POST' and url.path.startswith(base + '/protocol/openid-connect/token'):
            if form.get('grant_type') == 'urn:ietf:params:oauth:grant-type:uma-ticket':
                assert url.path == base + '/protocol/openid-connect/token'
                assert form['audience'] == RS and form['response_mode'] == 'permissions' and form['submit_request'] == 'false'
                assert 'client_secret' not in form and 'rpt' not in form
                assert auth and auth.startswith('Bearer ')
                context = parse(base64.urlsafe_b64decode(form['claim_token'] + '==='))
                raw = context['ouf.authorityRequest'][0].encode()
                assert context['ouf.requestHash'] == [digest(raw)]
                self.evaluations.append(parse(raw))
                grant, _, requested = form['permission'].partition('#')
                if self.failure == 'timeout':
                    self.resume.wait(5)
                if self.failure == 'unavailable':
                    return 503, {}
                if self.failure == 'malformed':
                    return 200, b'{"'
                if self.failure == 'foreign':
                    return 200, [dict(rsid=new_ref(), scopes=['dispatch', OP])]
                if self.failure == 'ambiguous':
                    return 403, {'error': 'unexpected'}
                if grant not in self.resources:
                    return 400, {'error': 'invalid_resource'}
                scopes = self.permissions.get((auth[7:], grant))
                if requested and scopes:
                    scopes = scopes.intersection(requested.split(','))
                if not scopes:
                    return 403, {'error': 'access_denied'}
                return 200, [dict(rsid=grant, scopes=sorted(scopes))]
            assert form['client_id'] == RS and form['client_secret'] == self.secret and not auth
            if url.path == base + '/protocol/openid-connect/token/introspect':
                assert set(form) == {'token', 'client_id', 'client_secret'}
                return 200, self.identities.get(form['token'], {'active': False})
            assert form['grant_type'] == 'client_credentials'
            return 200, dict(access_token='test-pat', token_type='Bearer')
        root = base + '/authz/protection/resource_set'
        assert method == 'GET' and auth == 'Bearer test-pat'
        if url.path == root:
            params = parse_qs(url.query)
            assert params['exactName'] == ['true'] and params['max'] == ['2']
            ids = [k for k, v in self.resources.items() if v['name'] == params['name'][0]]
            return 200, ids * (2 if self.duplicate else 1)
        assert url.path.startswith(root + '/')
        grant = self.resources.get(url.path[len(root) + 1:])
        return (200, grant) if grant else (404, {})


class KeycloakPET(unittest.TestCase):
    def setUp(self):
        self.pet = fixtures.MandatePET()
        self.pet.setUp()
        self.addCleanup(self.pet.doCleanups)
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.kc = Keycloak()
        self.issue = dict(self.pet.issue, analysisId='c' * 64, commandKey=new_ref())
        self.grant = self.kc.assign('A', self.issue)
        self.cfg = profile()
        self.endpoint = stack.enter_context(tls_server(http_dispatch=self.kc.http))('/realms/fixture')
        self.store = VerifierStore(self.pet.path)
        self.app = Verifier(self.cfg, RS, self.kc.secret, self.endpoint, self.store,
                            gateway_principal='gateway', clock=lambda: self.pet.now)
        self.decisions = []

        def serve(method, path, headers, raw):
            env = dict(PATH_INFO=path, REQUEST_METHOD=method, CONTENT_TYPE=headers.get('Content-Type'),
                       CONTENT_LENGTH=str(len(raw)), SSL_CLIENT_VERIFY='SUCCESS', REMOTE_USER='gateway')
            self.assertNotIn('Authorization', headers)
            response = []
            body, = self.app({**env, 'wsgi.input': io.BytesIO(raw)}, lambda status, _: response.append(int(status[:3])))
            if path == '/decisions':
                self.decisions.append((raw, parse(body)))
            return response[0], body

        private = stack.enter_context(tls_server(http_dispatch=serve))
        self.pet.api.iam = RemoteIAM(private('/introspection'), private('/decisions'), ISSUER, 'gateway', WORKLOAD, keycloak=True)
        self.pet.server.subject = 'A'
        self.patch_issuer = patch.object(fixtures, 'ISSUER', ISSUER)
        self.patch_issuer.start()
        self.addCleanup(self.patch_issuer.stop)
        status, self.m = self.call('issue', self.issue, proof=self.pet.proof('A'))
        self.assertEqual(status, 200)

    def call(self, action, payload, caller='A', proof=None):
        status, raw, _ = self.pet.api.handle(action, wire(payload), 'Bearer credential-' + caller, proof)
        return status, parse(raw)

    def status(self, mandate=None, generation='1'):
        return self.call('status', dict(mandateId=(mandate or self.m)['mandateId'], generation=generation))

    def attempt(self, mandate=None):
        b = dict(self.pet.b, mandateId=(mandate or self.m)['mandateId'], analysisId=self.issue['analysisId'], attemptId=new_ref())
        self.pet.server.reserve(b)
        return b

    def test_isolation(self):
        """GW-55H-01. A and B share tenant, client and plan. Even B's valid reservation cannot admit A."""
        second = dict(self.issue, commandKey=new_ref())
        self.kc.assign('B', second)
        status, other = self.call('issue', second, 'B', self.pet.proof('B'))
        self.assertEqual(status, 200)
        self.assertEqual(self.status()[0], 200)
        self.assertEqual(self.call('status', dict(mandateId=other['mandateId'], generation='1'), 'B')[0], 200)
        self.assertEqual(self.status(other), (404, {'code': 'ANALYSIS_MANDATE_UNKNOWN'}))
        self.pet.server.subject = 'B'
        self.assertEqual(self.call('dispatch', self.attempt(other))[0], 403)
        self.assertEqual(self.kc.evaluations[-1]['action'], 'dispatch')
        # A broad IAM scope still cannot substitute A for B's bound assignment principal.
        other_id = self.pet.store.get(other['mandateId'])['grantRef']
        self.kc.permissions['credential-A', other_id] = {'status', 'dispatch', OP}
        self.assertEqual(self.status(other)[0], 404)
        self.assertEqual(self.call('dispatch', self.attempt(other))[0], 403)
        self.pet.owner.post.assert_not_called()

    def test_revocation(self):
        """GW-55H-02. Revocation during a pause is visible before the preceding allow expires."""
        self.assertEqual(self.status()[0], 200)
        scopes = self.kc.permissions['credential-A', self.grant]
        scopes.remove('status')
        self.pet.now += 1
        self.assertEqual(self.status(), (404, {'code': 'ANALYSIS_MANDATE_UNKNOWN'}))
        scopes.add('status')
        del self.kc.resources[self.grant]
        self.assertEqual(self.status()[0], 404)

    def test_stale_generation(self):
        """GW-55H-03. An authorized revoke advances the generation observed on the next poll."""
        cmd = dict(mandateId=self.m['mandateId'], expectedGeneration='1', commandKey=new_ref())
        self.assertEqual(self.call('revoke', cmd)[0], 404)
        self.assertEqual(self.call('revoke', cmd, proof=self.pet.proof('A'))[0], 200)
        self.assertEqual(self.status(), (409, {'code': 'ANALYSIS_STALE_EXECUTION'}))
        self.assertEqual(self.status(generation='2')[1]['state'], 'REVOKED')

    def test_observe_only(self):
        """GW-55H-04. Observe an expired execution with only the current status permission."""
        before = self.pet.store.get(self.m['mandateId'])
        self.kc.permissions['credential-A', self.grant] = {'status'}
        self.pet.now = before['expires']
        self.assertEqual(self.status()[1]['state'], 'EXPIRED')
        self.assertEqual(self.status()[1]['expiresAt'], self.m['expiresAt'])
        self.assertEqual(self.pet.store.get(self.m['mandateId']), before)
        self.pet.owner.post.assert_not_called()

    def test_unavailable(self):
        """GW-55H-05. IAM errors at dispatch always stop before owner admission."""
        self.endpoint.timeout = 1
        try:
            for failure in ('unavailable', 'malformed', 'foreign', 'ambiguous', 'timeout'):
                with self.subTest(failure=failure):
                    self.kc.failure = failure
                    self.assertEqual(self.call('dispatch', self.attempt()), (503, {'code': 'ANALYSIS_AUTHORITY_UNAVAILABLE'}))
        finally:
            self.kc.resume.set()
        self.pet.owner.post.assert_not_called()

    def test_stable_issue_and_wire_binding(self):
        """GW-55H-06. Replay selects the same IAM resource, with separate nonce and byte-bound proof."""
        first = self.decisions[-1]
        self.assertEqual(self.call('issue', self.issue, proof=self.pet.proof('A')), (200, self.m))
        second = self.decisions[-1]
        self.assertNotEqual(first[0], second[0])
        for raw, result in (first, second):
            self.assertEqual(result['grantRef'], self.grant)
            self.assertEqual(result['requestHash'], digest(raw))
            self.assertEqual(result['validUntil'], self.pet.now + 12)
        endpoint = self.pet.api.iam.decisions
        headers = {'Content-Type': 'application/json'}
        self.assertEqual(endpoint.post(second[0], headers)[0], 503)
        q = dict(parse(second[0]), nonce=new_ref())
        raw = wire(q) + b'\n'
        self.app.introspect(urlencode({'token': 'credential-A', 'ouf_authority_request': b64(raw)}).encode(), 'gateway')
        self.assertEqual(endpoint.post(raw + b' ', headers)[0], 503)
        with ThreadPoolExecutor(2) as pool:
            replies = [job.result() for job in [pool.submit(endpoint.post, raw, headers) for _ in range(2)]]
        self.assertEqual(sorted(status for status, _, _ in replies), [200, 503])
        self.assertEqual([parse(body)['requestHash'] for status, body, _ in replies if status == 200], [digest(raw)])
        self.kc.duplicate = True
        self.assertEqual(self.call('issue', self.issue, proof=self.pet.proof('A'))[0], 503)
        self.kc.duplicate = False
        del self.kc.resources[self.grant]
        self.kc.assign('A', self.issue)
        self.assertEqual(self.call('issue', self.issue, proof=self.pet.proof('A')),
                         (409, {'code': 'ANALYSIS_COMMAND_CONFLICT'}))

    def test_dispatch_and_ths_authority(self):
        self.assertEqual(self.call('dispatch', self.attempt())[0], 201)
        cmd = dict(reviewRef='r' * 22, proposalVersion=2, proposalHash='e' * 64, expectedSeq='7',
                   commandKey=new_ref(), decision='APPROVE', items=[])
        renewal = dict(**cmd, mandateId=self.m['mandateId'], generation='1', analysisId=self.issue['analysisId'], incidentId='incident')
        proof = delegation(dict(v=1, purpose='analysis-renewal-decide', iss=ISSUER, aud='gateway', workload=WORKLOAD,
                                actor='HUMAN', tenant='tenant', principal='A', iat=self.pet.now, exp=self.pet.now+30,
                                acr='interactive', client='ths', scope='ouf.analysis.renewal.decide',
                                requestHash=digest(wire(cmd))), fixtures.KEY)
        self.assertEqual(self.call('renewal-check', renewal, proof=proof)[0], 200)
        q = self.kc.evaluations[-1]
        for key in ('incidentId', 'generation', 'mandateId', 'commandKey', 'proposalHash', 'proposalVersion'):
            self.assertEqual(q[key], renewal[key])
        self.assertEqual(q['commandHash'], digest(wire(cmd)))
        self.kc.permissions['credential-A', self.grant].remove('renew-budget')
        self.assertEqual(self.call('renewal-check', renewal, proof=proof)[0], 403)
        self.kc.permissions['credential-A', self.grant].add('admin-revoke')
        revoke = dict(mandateId=self.m['mandateId'], expectedGeneration='1', commandKey=new_ref())
        self.assertEqual(self.call('revoke', revoke)[0], 200)

    def test_rate_survives_restart(self):
        self.app.limits['introspectionsPerMinute'] = 1
        self.app.store = VerifierStore(self.pet.path)
        self.assertEqual(self.status()[0], 429)
        self.pet.now += 60
        self.app.limits['introspectionsPerMinute'] = 2
        self.assertEqual(self.status()[0], 200)
        self.assertEqual(self.status()[0], 429)

    def test_private_listener_and_live_identity(self):
        response = []
        self.app({'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS', 'HTTP_REMOTE_USER': 'gateway'},
                 lambda status, _: response.append(status))
        self.assertEqual(response, ['403 Forbidden'])
        q = dict(parse(self.decisions[-1][0]), nonce=new_ref())
        form = urlencode({'token': 'credential-A', 'ouf_authority_request': b64(wire(q))}).encode()
        with self.assertRaises(Rejected) as denied:
            self.app.introspect(form, 'probe')
        self.assertEqual(denied.exception.status, 403)
        identity = self.kc.identities['credential-A']
        for field, changed in (('tenant_id', 'other'), ('sub', 'foreign'), ('exp', self.pet.now)):
            with self.subTest(field=field), patch.dict(identity, {field: changed}), self.assertRaises(Rejected) as denied:
                self.app.introspect(form, 'gateway')
            self.assertEqual(denied.exception.status, 403)
        attrs = self.kc.resources[self.grant]['attributes']
        for field, changed in (('profileHash', 'a'*64), ('issuer', 'other'), ('policyRef', 'changed')):
            with self.subTest(field=field), patch.dict(attrs, {field: [changed]}):
                self.assertEqual(self.status()[0], 404)
        self.kc.identities['credential-A']['exp'] = self.pet.now + 1
        self.assertEqual(self.status()[0], 200)
        self.assertEqual(self.decisions[-1][1]['validUntil'], self.pet.now + 1)


class InstallationPET(unittest.TestCase):
    def test_limits_and_retry_after(self):
        for invalid in (dict(value=True, default=1, maximum=5), dict(value=0, default=1, maximum=5),
                        dict(value=6, default=1, maximum=5), dict(value=1, default=6, maximum=5)):
            with self.assertRaises(ValueError):
                limit(invalid)
        self.assertEqual(retry_seconds('Thu, 01 Jan 1970 00:01:00 GMT', 10), '50')
        self.assertEqual(retry_seconds('15', 10), '15')
        self.assertIsNone(retry_seconds('unknown', 10))
        with self.assertRaises(ValueError):
            Verifier(profile(), WORKLOAD, 'fixture', None, None, gateway_principal='gateway')
