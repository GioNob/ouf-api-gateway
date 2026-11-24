"""Gateway renewal PET with an introspection adapter, current policy and MCP owner fixture."""
import io
import json
import re
from unittest.mock import Mock

import pytest

from tests import test_analysis_mandate as fixtures
from tests.release_bundle_fixture import RENEWAL_IDS
from tests.test_execute_delegation import Engine, human
from tests.test_value_type_schemas import matched_route_context, routes
from tools.analysis_mandate import new_ref
from tools.analysis_protocol import BASE, RENEWALS, digest, parse, wire
from tools.analysis_renewal import Renewals
from tools.analysis_service import handler
from tools.gateway_release_bundle import generate
from tools.plan_semantic_search import restore_plan, search_plan


class Channel:
    def __init__(self, pet):
        self.pet = pet
        self.human = dict(pet.claims, sub='human', client_id='ths', ouf_actor_type='HUMAN', acr='interactive',
                          scope='ouf.analysis.renewal.read ouf.analysis.renewal.decide')
        pet.claims['scope'] = 'ouf.analysis.mandate.renewal-check'
        pet.iam_identity.evidence.side_effect = lambda b, _: self.human if b == b'token=ths-user' else pet.claims
        self.endpoint = Mock(path='/')
        self.app = handler(pet.api, Renewals(pet.api, self.endpoint, 'ths'))
        self.command = dict(reviewRef='review-1', proposalVersion=1, proposalHash='e' * 64, expectedSeq='7',
                            decision='APPROVE', commandKey=new_ref(), items=[])
        self.check = dict(self.command, mandateId=pet.m['mandateId'], generation='1', analysisId=pet.issue['analysisId'],
                          incidentId='incident-1')
        self.endpoint.post.return_value = (200, wire({'reviewRef': 'review-1'}), None)

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
                         ('reviewRef', 'review-2'), ('expectedSeq', '8'), ('items', [{'field': 'Calls', 'comment': 'x'}]),
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
    assert c.post(RENEWALS + 'read', {'reviewRef': 'review-1'})[0] == 200
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
    command = dict(c.command, decision=decision, proposalVersion='2', items=[dict(field='Calls', comment='Review')])
    check = {**c.check, **command}
    proof = c.proof(command=command)
    assert c.authorize(proof, check)[0] == 200
    changed = 'CLOSE_PARTIAL' if decision == 'APPROVE' else 'APPROVE'
    assert c.authorize(proof, dict(check, decision=changed))[0] == 403
    assert c.authorize(proof, dict(check, proposalVersion=2))[0] == 403
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
    for method, path, expected in [('GET', 'review-1', 'read'), ('GET', 'review.js', 'read'),
                                   ('GET', 'assets/review.css', 'read'), ('POST', 'review-1/decision', 'decide'),
                                   ('POST', 'review-1', None), ('GET', 'review-1/decision', None),
                                   ('POST', 'a/b/decision', None), ('PUT', 'review-1/decision', None)]:
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
