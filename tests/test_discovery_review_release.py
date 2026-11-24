"""GW-51J regression tests on the five resolved bundle resources."""
import base64
import hashlib
import hmac
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from ops.apisix.deploy_internal_m2m_routes import apply, restore
from tests.release_bundle_fixture import DISCOVERY_REVIEW_IDS
from tests.test_execute_delegation import Denied, Engine, KEY, human, proof, workload
from tests.test_onboarding_review import request as review_request
from tests.test_semantic_discovery_execute import request as discovery_request
from tests.test_value_type_schemas import matched_route_context, routes, run_dispatch_rewrite
from tools.apisix_request_schema import inline_dispatch_schema
from tools.mcp_dispatch_contract import DISCOVERY_REVIEW_MANIFEST, DISCOVERY_SCOPE, envelope_refs


def test_snapshot_provenance():
    """GW-51J-MANIFEST. Canonical five-row extraction from MCP 868daf3."""
    assert hashlib.sha256(DISCOVERY_REVIEW_MANIFEST.read_bytes()).hexdigest() == (
        '1d92893b4e084b076cff500a862dbb5a224834a154b2ba852db98b446a4503e4')


@pytest.mark.parametrize('route_id', DISCOVERY_REVIEW_IDS)
def test_release_schema_matches_manifest(routes, route_id):
    """GW-51J-SCHEMA. Compare the entire wire Arguments tree, including local refs."""
    schema = routes[route_id]['plugins']['request-validation']['body_schema']
    fields = schema['properties']
    capability = fields['CapabilityID']['const']
    rows = json.loads(DISCOVERY_REVIEW_MANIFEST.read_bytes())
    row, = (r for r in rows if r['capabilityId'] == capability)
    args = row['inputSchema']
    args['properties'].pop('analysisId', None)
    expected = inline_dispatch_schema({'properties': {'Arguments': envelope_refs(args)}})
    assert fields['Arguments'] == expected['properties']['Arguments'], f'{route_id}: MCP Arguments drift'
    maximum = 1048576 if route_id.endswith(('adopt', 'prepare')) else 264192
    assert fields['MaxResultBytes']['maximum'] == maximum


def dispatch(routes, mode, *, scopes=None, actor='HUMAN', arguments=None):
    review = mode == 'review-prepare'
    route = routes[('mcp-managed-file-' if review else 'mcp-semantic-discovery-') + mode]
    body = review_request() if review else discovery_request(mode)
    if mode == 'adopt':
        body['OperationClass'] = 'COMMAND'
        body['Arguments'].update(candidateId=body['AttemptID'], commandKey=body['IdempotencyKey'])
    if arguments:
        body['Arguments'].update(arguments)
    scope = body['CapabilityID'] if review else DISCOVERY_SCOPE
    body['Identity']['ActorType'] = actor
    headers = {'X-OUF-Delegation': proof(dict(human(), scope=scopes or scope, ouf_actor_type=actor)),
               'X-Correlation-ID': body['CorrelationID'], 'Idempotency-Key': body['IdempotencyKey'],
               'X-Tool-Attempt-ID': body['AttemptID']}
    engine = Engine(workload(), headers, body, uri=route['uri'])
    keys = {b'DELEGATION_KEY': KEY.encode(), b'DISCOVERY_KEY': b'45' * 32, b'OWNER_KEY': b'cd' * 32}
    engine.lua.globals()[b'os'][b'getenv'] = keys.get
    ctx = matched_route_context(engine, route)
    original = engine.body
    run_dispatch_rewrite(engine, route, ctx)
    schema = route['plugins']['request-validation']['body_schema']
    if actor == 'HUMAN':
        Draft7Validator(schema, format_checker=FormatChecker()).validate(body)
    if mode in ('candidates', 'adopt'):
        # Simulate a validator that rewrites JSON whitespace after the rewrite phase.
        engine.body = json.dumps(body, separators=(',', ':')).encode()
    post, = route['plugins']['serverless-post-function']['functions']
    engine.lua.execute(post.encode())(None, ctx)
    assert engine.body == original
    purpose = 'managed-file' if review else 'semantic-proposal' if mode == 'adopt' else 'semantic-discovery'
    encoded, signed = engine.headers[f'x-ouf-{purpose}-receipt'.encode()].split(b'.')
    key = keys[b'OWNER_KEY' if review or mode == 'adopt' else b'DISCOVERY_KEY']
    prefix = f'ouf-{purpose}-owner-v1.'.encode()
    expected = base64.urlsafe_b64encode(hmac.digest(key, prefix + encoded, 'sha256')).rstrip(b'=')
    assert hmac.compare_digest(signed, expected)
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=' * (-len(encoded) % 4)))
    assert receipt['path'] == route['plugins']['proxy-rewrite']['uri']
    assert receipt['capability'] == body['CapabilityID'] and receipt['bodyHash'] == hashlib.sha256(original).hexdigest()
    assert not {b'authorization', b'x-ouf-delegation'} & engine.headers.keys()


@pytest.mark.parametrize('mode', ['request', 'status', 'candidates', 'adopt'])
def test_discovery_common_scope_and_signed_body(routes, mode):
    """GW-51J-FORWARD / GW-51J-SCOPE. Exercise the release Lua through owner handoff."""
    arguments = {'includeState': True} if mode == 'candidates' else {}
    dispatch(routes, mode, arguments=arguments)
    specific = 'ouf.semantic.discovery.' + mode
    with pytest.raises(Denied, match='403'):
        dispatch(routes, mode, arguments=arguments, scopes=specific)
    with pytest.raises(Denied, match='403'):
        dispatch(routes, mode, arguments=arguments, actor='AI_AGENT')


@pytest.mark.parametrize('mode', ['adopt', 'review-prepare'])
def test_command_key_matches_idempotency_key(routes, mode):
    """GW-51J-IDEMPOTENCY. Both command receipts require the same command intent."""
    with pytest.raises(Denied, match='409'):
        dispatch(routes, mode, arguments={'commandKey': 'other-command'})


@pytest.mark.parametrize('action', ['WITHDRAW', 'RESTART_DRAFT'])
def test_review_action_and_signed_body(routes, action):
    """GW-51J-REVIEW. Both candidate actions reach the same Onboarding receipt boundary."""
    dispatch(routes, 'review-prepare', arguments={'candidateAction': action})


@pytest.mark.parametrize('route_id', DISCOVERY_REVIEW_IDS)
def test_legacy_bulk_install_and_restore_blocked(route_id):
    """GW-51J-LEGACY. Reject before any Admin call, including snapshot rollback."""
    with pytest.raises(ValueError, match='governed Gateway release'):
        apply([{'id': route_id}], None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        restore({route_id: None}, None)
