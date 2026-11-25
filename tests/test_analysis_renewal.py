"""Gateway renewal PET with an introspection adapter, current policy and MCP owner fixture."""
import io
import json
import re
import ssl
from unittest.mock import Mock, patch

import pytest

from tests import test_analysis_mandate as fixtures
from tests.release_bundle_fixture import RENEWAL_IDS, canonical_json, pre_58f_body, sha256
from tests.test_execute_delegation import Engine, human
from tests.test_value_type_schemas import matched_route_context, routes
from tools.analysis_clients import Endpoint
from tools.analysis_mandate import new_ref
from tools.analysis_protocol import BASE, RENEWALS, digest, parse, wire
from tools.analysis_renewal import Renewals
from tools.analysis_service import handler
from tools.gateway_release_bundle import generate
from tools.plan_semantic_search import restore_plan, search_plan


REVIEW_REF = '0123456789abcdefghij_-'


def proposal():
    def budget(n):
        return dict(Calls=n, Attempts=n, Objects=n, Bytes=n, Millis=n)

    return dict(contract='ouf.analysis.renewal.v1', reviewRef=REVIEW_REF, analysisId='a' * 64,
                incidentId='incident-1', mandateId=fixtures.PROFILE['assetId'], generation='1', expectedSeq='7',
                proposalHash='e' * 64, proposalVersion=2, reason='ANALYSIS_BUDGET_EXHAUSTED', remainingOrdinals=[4, 7, 9],
                initialMaximum=budget(12), consumed=budget(11), increment=budget(2), totalMaximum=budget(14),
                expiresAt='2030-01-01T11:00:00Z', previous=None, requestedChanges=[], proposalState='OPEN',
                planLabel='esempio.csv · 18 colonne')


class Channel:
    def __init__(self, pet):
        self.pet = pet
        self.human = dict(pet.claims, sub='human', client_id='ths', ouf_actor_type='HUMAN', acr='interactive',
                          scope='ouf.analysis.renewal.read ouf.analysis.renewal.decide')
        pet.iam_identity.evidence.side_effect = lambda b, _: self.human if b == b'token=ths-user' else pet.claims
        self.endpoint = Mock(path='/')
        self.app = handler(pet.api, Renewals(pet.api, self.endpoint, 'ths'))
        self.command = dict(reviewRef=REVIEW_REF, proposalVersion=1, proposalHash='e' * 64, expectedSeq='7',
                            decision='APPROVE', commandKey=new_ref(), items=[])
        self.check = dict(self.command, mandateId=pet.m['mandateId'], generation='1', analysisId=pet.issue['analysisId'],
                          incidentId='incident-1')
        self.endpoint.post.return_value = (200, wire(proposal()), None)

    def post(self, path, body, bearer='Bearer ths-user', proof=None):
        raw = body if isinstance(body, bytes) else wire(body)
        env = dict(PATH_INFO=path, REQUEST_METHOD='POST', CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(raw)),
                   HTTP_AUTHORIZATION=bearer, HTTP_X_OUF_DELEGATION=proof)
        response = Mock()
        data, = self.app({**env, 'wsgi.input': io.BytesIO(raw)}, response)
        status, headers = response.call_args.args
        return int(status[:3]), parse(data), dict(headers)

    def proof(self, action='decide', command=None):
        body = self.command if action == 'decide' else {'reviewRef': self.command['reviewRef']}
        if command is not None:
            body = command
        assert self.post(RENEWALS + action, body)[0] == 200
        raw, headers, _, path = self.endpoint.post.call_args.args
        assert set(headers) == {'Content-Type', 'X-OUF-Delegation'}
        assert raw == wire(body) and path == RENEWALS + action
        return headers['X-OUF-Delegation']

    def authorize(self, proof, body=None):
        return self.post(BASE + 'renewal-check', self.check if body is None else body, fixtures.WORKER, proof)


@pytest.fixture
def channel():
    pet = fixtures.MandatePET()
    pet.setUp()
    try:
        yield Channel(pet)
    finally:
        pet.doCleanups()


def test_current_holder_and_exact_request(channel):
    """GW-55C-01. Separate THS decision and worker credentials, exact IAM query and short receipt."""
    c, pet = channel, channel.pet
    proof = c.proof()
    raw = json.dumps(c.check, indent=2).encode()
    expected = {k: c.check[k] for k in ('mandateId', 'analysisId', 'generation', 'incidentId', 'reviewRef',
                                         'proposalVersion', 'proposalHash', 'expectedSeq', 'commandKey', 'decision')}
    expected.update(action='renew-budget', actor='HUMAN', actorRef='human', subject='human', grantRef='grant1',
                    policyRef='policy1', tenant='tenant', workloadSubject='worker-id', commandHash=digest(wire(c.command)))

    def policy(body, headers):
        matches = all(parse(body).get(k) == v for k, v in expected.items())
        return dict(pet.decide(body, headers), allowed=matches, decisionRef='iam-decision', grantExpiresAt=1017)

    pet.policy.evidence.side_effect = policy
    assert c.authorize(proof, raw)[:2] == (200, dict(requestHash=digest(raw), decisionRef='iam-decision',
                                                    grantRef='grant1', validUntil=1017))
    for field, value in [('proposalHash', 'd' * 64), ('proposalVersion', 2), ('commandKey', new_ref()),
                         ('reviewRef', REVIEW_REF[::-1]), ('expectedSeq', '8'), ('items', [{'field': 'Calls', 'comment': 'x'}]),
                         ('incidentId', 'incident-2')]:
        assert c.authorize(proof, dict(c.check, **{field: value}))[:2] == (403, {'code': 'ANALYSIS_AUTHORITY_DENIED'})
    for wrong in (None, pet.proof(), c.proof('read')):
        assert c.authorize(wrong)[0] == 403
    c.human['sub'] = 'other-human'
    assert c.authorize(c.proof())[:2] == (404, {'code': 'ANALYSIS_MANDATE_UNKNOWN'})
    c.human['client_id'] = 'other-client'
    assert c.post(RENEWALS + 'decide', c.command)[0] == 403
    assert c.post(RENEWALS + 'decide', c.command, fixtures.WORKER)[0] == 403
    pet.claims['scope'] = 'ouf.analysis.mandate.status'
    assert c.authorize(proof)[0] == 403
    pet.owner.post.assert_not_called()


def test_revocation_between_read_and_confirmation(channel):
    """GW-55C-02. A late IAM allow cannot release a revoked mandate or start a new session."""
    c, pet = channel, channel.pet
    assert c.post(RENEWALS + 'read', {'reviewRef': REVIEW_REF})[0] == 200
    commits = []

    def decide(body, headers):
        reply = pet.decide(body, headers)
        if parse(body)['action'] == 'renew-budget':
            assert pet.send('revoke', pet.revoke, pet.proof())[0] == 200
        return reply

    def mcp_commit(body, headers, limit, path):
        status, receipt, _ = c.authorize(headers['X-OUF-Delegation'])
        if status == 200:
            commits.append(receipt)
        return status, wire(receipt), None

    c.endpoint.post.side_effect = mcp_commit
    pet.policy.evidence.side_effect = decide
    for _ in range(2):
        assert c.post(RENEWALS + 'decide', c.command)[:2] == (409, {'code': 'ANALYSIS_STALE_EXECUTION'})
    assert commits == []
    pet.owner.post.assert_not_called()


def test_expiry_policy_and_owner_outcomes(channel):
    """GW-55C-02. Rights checked again on confirmation, typed MCP outcomes and Retry-After preserved."""
    c, pet = channel, channel.pet
    proof = c.proof()
    pet.policy.evidence.side_effect = lambda raw, h: dict(pet.decide(raw, h), grantRef='new-grant')
    assert c.authorize(proof)[0] == 403
    pet.policy.evidence.side_effect = lambda raw, h: dict(pet.decide(raw, h), requestHash='0' * 64)
    assert c.authorize(proof)[0] == 503
    pet.allowed = False
    pet.policy.evidence.side_effect = pet.decide
    assert c.authorize(proof)[0] == 403
    pet.now = 4600
    assert c.authorize(c.proof())[:2] == (410, {'code': 'ANALYSIS_MANDATE_EXPIRED'})
    for status, code in [(409, 'ANALYSIS_RENEWAL_USED'), (409, 'ANALYSIS_COMMAND_CONFLICT'),
                         (429, 'ANALYSIS_BACKOFF'), (503, 'ANALYSIS_AUTHORITY_UNAVAILABLE')]:
        retry = '15' if status in (429, 503) else None
        c.endpoint.post.return_value = status, wire({'code': code}), retry
        result, body, headers = c.post(RENEWALS + 'decide', c.command)
        assert (result, body, headers.get('Retry-After')) == (status, {'code': code}, retry)
    calls = c.endpoint.post.call_count
    for delta in ({'subject': 'human'}, {'decisionRef': 'forged'}, {'decision': 'OTHER'}, {'expectedSeq': 2},
                  {'items': [{'field': 'Calls'}]}, {'proposalVersion': True}, {'proposalVersion': 0},
                  {'proposalVersion': 2**63}, {'proposalVersion': '01'}):
        assert c.post(RENEWALS + 'decide', dict(c.command, **delta))[:2] == (400, {'code': 'ANALYSIS_INPUT_INVALID'})
    assert c.endpoint.post.call_count == calls


@pytest.mark.parametrize('decision', ['APPROVE', 'CHANGES_REQUESTED', 'CLOSE_PARTIAL'])
def test_decision_and_feedback_cannot_be_substituted(channel, decision):
    c = channel
    command = dict(c.command, decision=decision, proposalVersion=2, items=[dict(field='Calls', comment='Review')])
    check = {**c.check, **command}
    proof = c.proof(command=command)
    assert c.authorize(proof, check)[0] == 200
    changed = 'CLOSE_PARTIAL' if decision == 'APPROVE' else 'APPROVE'
    assert c.authorize(proof, dict(check, decision=changed))[0] == 403
    assert c.authorize(proof, dict(check, proposalVersion=3))[0] == 403
    assert c.authorize(proof, dict(check, items=[]))[0] == 403
    c.pet.now += c.pet.api.proof_ttl
    assert c.authorize(proof, check)[0] == 403


def test_receipt_replay_returns_to_mcp_for_read_authorization(channel):
    """GW-55C-02. A synthetic MCP owns consumption, including read authorization on an identical replay."""
    c = channel
    receipts = {}
    readable = True

    def mcp(body, headers, limit, path):
        command = parse(body)
        key = command['commandKey']
        if not readable:
            return 404, wire({'code': 'ANALYSIS_MANDATE_UNKNOWN'}), None
        if key in receipts:
            previous, receipt = receipts[key]
            if previous != body:
                return 409, wire({'code': 'ANALYSIS_COMMAND_CONFLICT'}), None
            return 200, receipt, None
        if receipts:
            return 409, wire({'code': 'ANALYSIS_RENEWAL_USED'}), None
        status, receipt, _ = c.authorize(headers['X-OUF-Delegation'], {**c.check, **command})
        assert status == 200
        receipts[key] = body, wire(receipt)
        return 200, wire(receipt), None

    c.endpoint.post.side_effect = mcp
    path = RENEWALS + 'decide'
    first = c.post(path, c.command)
    assert first[0] == 200
    c.pet.now += 1
    assert c.post(path, json.dumps(c.command, indent=2).encode()) == first
    assert c.post(path, dict(c.command, expectedSeq='8'))[:2] == (409, {'code': 'ANALYSIS_COMMAND_CONFLICT'})
    assert c.post(path, dict(c.command, commandKey=new_ref()))[:2] == (409, {'code': 'ANALYSIS_RENEWAL_USED'})
    readable = False
    assert c.post(path, c.command)[:2] == (404, {'code': 'ANALYSIS_MANDATE_UNKNOWN'})
    assert c.endpoint.post.call_count == 5 and len(receipts) == 1


def test_bundle_selectors_scopes_and_assets(routes):
    """GW-55C-03. Page, assets and decision reach only their owner on the declared method."""
    root = '/trusted-human/analysis-renewal/'
    for method, path, expected in [('GET', REVIEW_REF, 'read'), ('GET', 'review.js', 'read'),
                                   ('GET', 'assets/review.css', 'read'), ('POST', REVIEW_REF + '/decision', 'decide'),
                                   ('POST', REVIEW_REF, None), ('GET', REVIEW_REF + '/decision', None),
                                   ('POST', 'a/b/decision', None), ('PUT', REVIEW_REF + '/decision', None),
                                   ('GET', 'short', None), ('POST', 'short/decision', None),
                                   ('GET', 'a' * 129, None), ('POST', 'a' * 128 + '/decision', 'decide'),
                                   ('GET', REVIEW_REF + '=', None), ('GET', REVIEW_REF + '.x', None)]:
        matches = [r for r in routes.values() if r.get('uri') == root + '*' and method in r['methods']
                   and re.fullmatch(r['vars'][0][2], root + path)]
        assert [r['id'] for r in matches] == ([] if expected is None else ['trusted-human-analysis-renewal-' + expected])
    for key in RENEWAL_IDS:
        route = routes[key]
        assert route['upstream']['retries'] == 0
        if key.startswith('trusted-human'):
            assert 'proxy-rewrite' not in route['plugins'] and 'serverless-pre-function' in route['plugins']
            engine = Engine(human(), {'Cookie': 'session', 'X-OUF-Principal-ID': 'forged', 'X-OUF-Delegation': 'forged'})
            guard, = route['plugins']['serverless-pre-function']['functions']
            engine.lua.execute(guard.encode())(None, matched_route_context(engine, route))
            assert engine.headers == {b'cookie': b'session'}
        else:
            oidc = route['plugins']['openid-connect']
            assert oidc['required_scopes'] == [route['labels']['ouf-capability']]
            assert oidc['bearer_only'] and oidc['ssl_verify'] and route['methods'] == ['POST']
            assert route['upstream']['scheme'] == 'https' and route['labels']['ouf-exposure'] == 'internal'


def test_idempotent_bundle_and_fenced_restore(routes, tmp_path):
    """GW-55C-04. Two releases, five creates, exact restore and duplicate/drift protection."""
    def snapshot():
        generate(tmp_path, '5' * 40, '.github/workflows/ci.yml', '55')
        return {p.name: p.read_bytes() for p in tmp_path.iterdir()}

    assert snapshot() == snapshot()
    desired = list(routes.values())
    predecessor = [r for r in desired if r['id'] not in RENEWAL_IDS]
    rev = routes['onboarding-analysis-renewal-read']['labels']['ouf-installation-revision']

    def inventory(entries):
        return {'total': len(entries), 'list': [{'value': r} for r in entries]}

    plan = search_plan(desired, inventory(predecessor), rev, renewals=True)
    assert len(predecessor) == 35 and {c.logical_id for c in plan} == RENEWAL_IDS
    assert all(c.action == 'create' for c in plan)
    assert all(c.action == 'unchanged' for c in search_plan(desired, inventory(desired), rev, renewals=True))
    restored = dict(routes)
    for change in restore_plan(plan, inventory(desired)):
        assert change.after is None and restored.pop(change.target_id) == change.before
    assert list(restored.values()) == predecessor
    duplicate = dict(routes['trusted-human-analysis-renewal-read'], id='other', uri='/trusted-human/analysis-renewal/asset.js')
    with pytest.raises(ValueError):
        search_plan(desired, inventory(predecessor + [duplicate]), rev, renewals=True)
    with pytest.raises(ValueError):
        restore_plan(plan, inventory(desired + [duplicate]))
    changed = dict(routes)
    changed[plan[0].target_id] = dict(plan[0].after, priority=5)
    with pytest.raises(ValueError, match='drift'):
        restore_plan(plan, inventory(changed.values()))

    # Restore the pre-58f relay and the two #103 public selectors, then check the frozen digest.
    segment = '[A-Za-z0-9_~-][A-Za-z0-9._~-]*'
    old_path = '^/trusted-human/analysis-renewal/' + segment
    old_regex = {
        'trusted-human-analysis-renewal-read': old_path + f'(?:/(?:{segment}/)*{segment}' + r'\.(?:js|css))?$',
        'trusted-human-analysis-renewal-decide': old_path + '/decision$',
    }
    original = json.loads((tmp_path / 'bundle.json').read_bytes())['resources']
    installed = {key: pre_58f_body(key, route) for key, route in routes.items()}
    for row in original:
        key = row['id']
        row['body'] = pre_58f_body(key, row['body'])
        if key in old_regex:
            selector = [['uri', '~~', old_regex[key]]]
            row['body']['vars'] = selector
            installed[key] = dict(routes[key], vars=selector)
    assert sha256(canonical_json(original)) == 'c2ca2af819386870eb6138308c2acf3b0b35187ffc5657cec074a93b4640dbb0'
    updates = search_plan(desired, inventory(installed.values()), rev, renewals=True)
    assert {c.logical_id: c.action for c in updates} == {k: 'update' for k in RENEWAL_IDS}
    assert all(c.after == installed[c.logical_id] for c in restore_plan(updates, inventory(desired)))
    key = 'trusted-human-analysis-renewal-read'
    modified = {**installed, key: dict(installed[key], priority=5)}
    with pytest.raises(ValueError, match='drift'):
        search_plan(desired, inventory(modified.values()), rev, renewals=True)
    installed[key] = dict(installed[key], vars=[['uri', '~~', '.*']])
    with pytest.raises(ValueError, match='drift'):
        search_plan(desired, inventory(installed.values()), rev, renewals=True)


def test_addendum_command_types_and_limits(channel):
    """GW-55C-05. The relay and the authority check enforce identical wire types."""
    c = channel
    item = dict(field='general', comment='🟢' * 500)
    command = dict(c.command, reviewRef='_' * 128, proposalVersion=2**53 - 1, items=[item] * 16)
    proof = c.proof(command=command)
    assert c.authorize(proof, {**c.check, **command})[0] == 200
    invalid = [(key, value) for key, values in (
        ('proposalVersion', [0, -1, True, 1.0, '1', '9007199254740991', 2**53]),
        ('reviewRef', ['a' * 21, 'b' * 129, REVIEW_REF + '=', REVIEW_REF + '.', REVIEW_REF + '~']),
        ('items', [[item] * 17, [dict(item, field='calls')], [dict(item, comment='🟢' * 501)],
                   [dict(item, comment=1)], [dict(item, extra=True)]]),
    ) for value in values]
    c.endpoint.post.reset_mock()
    c.pet.policy.evidence.reset_mock()
    for key, value in invalid:
        bad = {**command, key: value}
        expected = (400, {'code': 'ANALYSIS_INPUT_INVALID'})
        assert c.post(RENEWALS + 'decide', bad)[:2] == expected
        assert c.authorize(proof, {**c.check, **bad})[:2] == expected
        if key == 'reviewRef':
            assert c.post(RENEWALS + 'read', {key: value})[:2] == expected
    c.endpoint.post.assert_not_called()
    c.pet.policy.evidence.assert_not_called()


def test_read_addendum_forwarded(channel):
    """GW-55C-06. Forward the owner fields intact for every state and both history shapes."""
    data = proposal()
    body = {'reviewRef': REVIEW_REF}
    for state in ('OPEN', 'APPROVED', 'CLOSED_PARTIAL', 'CHANGES_REQUESTED', 'SUPERSEDED', 'EXPIRED'):
        data['proposalState'] = state
        channel.endpoint.post.return_value = 200, wire(data), None
        assert channel.post(RENEWALS + 'read', body)[:2] == (200, data)
        data['previous'] = {key: data[key] for key in ('proposalVersion', 'reason', 'remainingOrdinals',
                            'initialMaximum', 'consumed', 'increment', 'totalMaximum', 'expiresAt')}
        data['previous']['proposalVersion'] = 1
        data['requestedChanges'] = [dict(field=field, comment='à' * 500) for field in
                                    ('Calls', 'Attempts', 'Objects', 'Bytes', 'Millis', 'general')]
        data['planLabel'] = '🟢' * 200
    # remainingOrdinals: JSON integers 0..1023, strictly increasing, from none up to all 1024.
    for current, earlier in (([], list(range(1024))), (list(range(1024)), [0, 1023])):
        data['remainingOrdinals'], data['previous']['remainingOrdinals'] = current, earlier
        channel.endpoint.post.return_value = 200, wire(data), None
        assert channel.post(RENEWALS + 'read', body)[:2] == (200, data)
    channel.endpoint.post.return_value = 429, wire({'code': 'ANALYSIS_BACKOFF'}), '15'
    status, error, headers = channel.post(RENEWALS + 'read', body)
    assert (status, error, headers['Retry-After']) == (429, {'code': 'ANALYSIS_BACKOFF'}, '15')


def test_invalid_read_is_scrubbed(channel):
    """GW-55C-07. Invalid success and error responses expose only the Gateway error code."""
    data = proposal()
    version_keys = ('proposalVersion', 'reason', 'remainingOrdinals', 'initialMaximum', 'consumed',
                    'increment', 'totalMaximum', 'expiresAt')
    previous = {**{k: data[k] for k in version_keys}, 'proposalVersion': 1}
    invalid = [dict(data, **{key: value}) for key, value in (
        ('reviewRef', REVIEW_REF[::-1]), ('analysisId', 'malformed'), ('proposalState', 'UNKNOWN'),
        ('planLabel', 'x' * 201), ('proposalHash', []), ('requestedChanges', [dict(field='Calls', comment='x' * 501)]),
        ('requestedChanges', [dict(field='invalid', comment='example')]), ('requestedChanges', [{}] * 17),
        ('previous', []), ('previous', dict(previous, extra='private')), ('extra', 'private'))]
    for key in ('previous', 'requestedChanges', 'proposalState', 'planLabel', *version_keys):
        invalid.append({k: v for k, v in data.items() if k != key})
    ordinals = [True, 3, {}, [True], [1.0], [-1], [1024], [3, 2], [2, 2], ['1'], list(range(1024)) + [1023]]
    for key, value in [('proposalVersion', '1'), ('reason', 'free text'),
                       *(('remainingOrdinals', bad) for bad in ordinals), ('consumed', {'Calls': 3}), ('increment', dict(data['increment'], Bytes=-1)),
                       ('totalMaximum', dict(data['totalMaximum'], Bytes=900)),
                       ('expiresAt', '2030-02-31T11:00:00Z')]:
        invalid.extend([dict(data, **{key: value}), dict(data, previous={**previous, key: value})])
    cases = [(200, wire(obj)) for obj in invalid]
    cases.extend([(200, b'{"reason":1,"reason":2}'), (200, b'private'), (201, wire(data)),
                  (403, wire({'code': 'ANALYSIS_AUTHORITY_DENIED', 'extra': 'private'})), (503, b'private')])
    for status, raw in cases:
        channel.endpoint.post.return_value = status, raw, '15'
        status, body, headers = channel.post(RENEWALS + 'read', {'reviewRef': REVIEW_REF})
        assert (status, body) == (502, {'code': 'ANALYSIS_RENEWAL_RESPONSE_INVALID'})
        assert 'Retry-After' not in headers


def test_read_transport_bounds(channel):
    """GW-55C-07. Separate malformed HTTP responses from transport unavailability."""
    endpoint = Endpoint('https://mcp.invalid', ssl.create_default_context(), 1)
    channel.app = handler(channel.pet.api, Renewals(channel.pet.api, endpoint, 'ths'))
    request = {'reviewRef': REVIEW_REF}
    with patch('tools.analysis_clients.http.client.HTTPSConnection') as connect:
        response = connect.return_value.getresponse.return_value
        for status, raw in [(200, b'x' * 131073), (302, b'private')]:
            response.status = status
            response.read.return_value = raw
            assert channel.post(RENEWALS + 'read', request)[:2] == (502, {'code': 'ANALYSIS_RENEWAL_RESPONSE_INVALID'})
            response.read.assert_called_with(131073)
        connect.return_value.getresponse.side_effect = TimeoutError()
        assert channel.post(RENEWALS + 'read', request)[:2] == (503, {'code': 'ANALYSIS_AUTHORITY_UNAVAILABLE'})
