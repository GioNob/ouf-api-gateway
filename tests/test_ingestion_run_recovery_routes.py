import base64
import hashlib
import hmac
import json
import re
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.release_bundle_fixture import ci_profile, load_release_routes
from tests.test_dispatch_schema_contract import THS_LINK_DISPATCH_CASES, dispatch_body
from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.test_file_loop_coherence import retained_installation
from tests.test_managed_file_mcp import request as managed_request
from tests.test_onboarding_review import request as review_request
from tools import gateway_release_bundle
from tools.apply_installation_projection import apply_projection
from tools.apisix_request_schema import inline_dispatch_schema
from tools.compile_config import ConfigError, compile_config
from tools.delegation_functions import function
from tools.materialize_managed_file_mcp import materialize as managed_file
from tools.materialize_onboarding_review import materialize
from tools.mcp_dispatch_contract import INVALID_TOOL_ARGUMENTS, capability_contracts, envelope_refs

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = '11111111-1111-4111-8111-111111111111'
RUNS = '/api/trusted-human/v1/ingestion/runs/'
LINK_ROUTE_IDS = [
    pytest.param('mcp-ingestion-run-recovery-link', id='ingestion-run-recovery'),
    pytest.param('mcp-semantic-review-link', id='semantic-review'),
]


@pytest.mark.parametrize('action,method,suffix', [
    ('read', 'GET', ''), ('resume', 'POST', '/resume'), ('abort', 'POST', '/abort'),
])
def test_ingestion_run_human_binding(action, method, suffix):
    runtime, existing = retained_installation()
    scope = 'ingestion.run.' + action
    route_id = 'trusted-human-ingestion-run-' + action
    binding = next(route for route in runtime['routes'] if route['id'] == route_id)
    assert binding['x-ouf-policy']['identity'] == 'OIDC'
    assert binding['x-ouf-policy']['requiredScope'] == scope
    assert binding['x-ouf-backend-binding'] == {'path': RUNS + '*', 'service': 'ouf-ingestion-runtime', 'port': 8080}
    assert binding['x-ouf-capability']['capabilityId'] == scope
    assert binding['x-ouf-capability']['humanRequired'] and not binding['x-ouf-capability']['toolEligible']

    routes = materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')['routes']
    route = next(route for route in routes if route['id'] == route_id)
    assert route['uri'] == RUNS + '*' and route['methods'] == [method]
    assert route['upstream']['nodes'] == {'ouf-ingestion-runtime:8080': 1}
    assert route['upstream']['retries'] == 0 and route['upstream']['timeout']['read'] == 15
    plugins = route['plugins']
    assert 'proxy-rewrite' not in plugins
    assert plugins['openid-connect']['required_scopes'] == [scope]
    assert plugins['openid-connect']['bearer_only'] is True
    assert route['vars'] == binding['vars']
    _, _, selector = route['vars'][0]
    for path, allowed in [
        (RUNS + RUN_ID + suffix, True),
        (RUNS + RUN_ID + suffix + '/extra', False),
        (RUNS + RUN_ID + '/pause', False),
        (RUNS + 'invalid' + suffix, False),
    ]:
        assert bool(re.search(selector, path)) == allowed

    engine = Engine(human(), {'X-OUF-Unlisted': 'forged', 'X-OUF-Delegation': 'forged'})
    bearer = engine.headers[b'authorization']
    engine.lua.execute(plugins['serverless-pre-function']['functions'][0].encode())(None, None)
    assert engine.headers[b'authorization'] == bearer
    assert not any(name.startswith(b'x-ouf-') for name in engine.headers)


def test_ingestion_run_page_preserves_owner_session_and_csrf():
    runtime, existing = retained_installation()
    routes = materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')['routes']
    page = next(route for route in routes if route['id'] == 'trusted-human-ingestion-run-recovery')
    assert page['uri'] == '/trusted-human/ingestion-run-recovery/*'
    assert page['methods'] == ['GET', 'POST']
    assert page['upstream']['nodes'] == {'ouf-onboarding:8080': 1}
    assert page['upstream']['retries'] == 0 and page['upstream']['timeout']['read'] == 35
    plugins = page['plugins']
    assert not {'openid-connect', 'proxy-rewrite'} & plugins.keys()
    engine = Engine(human(), {'Cookie': 'SESSION=fixture', 'X-CSRF-TOKEN': 'fixture',
                              'X-OUF-Unknown': 'forged'})
    engine.lua.execute(plugins['serverless-pre-function']['functions'][0].encode())(None, None)
    assert b'authorization' not in engine.headers and b'x-ouf-unknown' not in engine.headers
    assert engine.headers[b'cookie'] == b'SESSION=fixture'
    assert engine.headers[b'x-csrf-token'] == b'fixture'


@pytest.mark.parametrize('route_id', [
    pytest.param('mcp-ingestion-run-recovery-link', id='ingestion-run-recovery'),
    pytest.param('mcp-semantic-review-link', id='semantic-review'),
])
def test_ths_link_capability_is_present_in_pinned_manifest(route_id):
    path = ROOT / 'ouf-config/routes/northbound' / (route_id + '.json')
    cap = json.loads(path.read_bytes())['capabilityId']
    assert cap in capability_contracts(), f'{route_id}: synchronize the MCP manifest and set capabilityId'


@pytest.mark.parametrize('route_id', LINK_ROUTE_IDS)
def test_ths_link_stays_closed_until_manifest_binding(tmp_path, monkeypatch, route_id):
    config = tmp_path / 'ouf-config'
    shutil.copytree(ROOT / 'ouf-config', config)
    route_ids = THS_LINK_DISPATCH_CASES.keys()
    for pending_id in route_ids:
        pending_path = config / 'routes/northbound' / (pending_id + '.json')
        pending = json.loads(pending_path.read_bytes())
        pending_path.write_text(json.dumps(dict(pending, capabilityId=None)), encoding='utf-8')
    path = config / 'routes/northbound' / (route_id + '.json')
    declaration = json.loads(path.read_bytes())
    assert not (route_ids & {route['id'] for route in compile_config(config)['routes']})
    monkeypatch.setattr(gateway_release_bundle, 'ROOT', tmp_path)
    assert not (route_ids & {resource['id'] for resource in gateway_release_bundle.release_resources()})
    cap, scope = 'fixture.link.capability', 'fixture.link.scope'
    declaration['capabilityId'] = cap
    path.write_text(json.dumps(declaration), encoding='utf-8')
    with pytest.raises(ConfigError, match='MCP THS link capability missing'):
        compile_config(config)

    owner_path, accepted, rejected = THS_LINK_DISPATCH_CASES[route_id]
    args = accepted[0].copy()
    if route_id == 'mcp-ingestion-run-recovery-link':
        properties = {'sourceId': {'type': 'string'}, 'runId': {'type': 'string', 'format': 'uuid'},
                      'expectedVersion': {'type': 'integer', 'minimum': 0, 'maximum': 2**53 - 1}}
        args['sourceId'] = 'fixture/è/"\\\n\t\x00\x1f'
        args['expectedVersion'] = 2**53 - 1
        rejected = [*rejected, dict(args, expectedVersion=2**53), dict(args, expectedVersion=0.5)]
    else:
        properties = {'challengeId': {'type': 'string', 'minLength': 1}}
        args['challengeId'] = 'fixture/è/"\\\n\t\x00\x1f'
    input_schema = {
        'type': 'object', 'additionalProperties': False,
        'required': list(properties), 'properties': properties,
    }
    monkeypatch.setitem(capability_contracts(), cap, {
        'capabilityId': cap, 'gatewayBindingRef': 'capability://fixture.link.binding',
        'owner': 'onboarding', 'operationClass': 'COMMAND', 'toolEligible': False, 'publicationState': 'ACTIVE',
        'requiredAuthorizationCapability': scope, 'inputSchema': input_schema,
        'baseCostEnvelope': {'hardMaxResultBytes': 4096},
    })
    runtime = fixture_runtime(config)
    existing = managed_file(runtime, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY')
    routes = materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')['routes']
    route, = (route for route in routes if route['id'] in route_ids)
    assert route['id'] == route_id
    assert route['uri'] == '/internal/capabilities/v1/execute/fixture.link.binding'
    assert route['methods'] == ['POST']
    assert route['upstream'] == {
        'type': 'roundrobin', 'scheme': 'http', 'nodes': {'ouf-onboarding:8080': 1}, 'retries': 0,
        'timeout': {'connect': 3, 'send': 3, 'read': 3},
    }
    assert route['plugins']['proxy-rewrite']['uri'] == owner_path
    assert route['plugins']['client-control'] == {'max_body_size': 65536}
    assert route['plugins']['openid-connect']['bearer_only'] is True
    validation = route['plugins']['request-validation']
    assert validation['rejected_msg'] == INVALID_TOOL_ARGUMENTS
    schema = validation['body_schema']
    assert schema['properties']['Arguments'] == inline_dispatch_schema({
        'properties': {'Arguments': envelope_refs(input_schema)},
    })['properties']['Arguments']
    body = dispatch_body(schema, args)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    assert validator.is_valid(body)
    if 'runId' in args:
        assert not validator.is_valid(dispatch_body(schema, dict(args, runId='invalid')))
    rejected = [*rejected, {}, dict(args, approved=True)]

    bundle = tmp_path / 'release'
    commit, workflow, run_id = '1' * 40, '.github/workflows/ci.yml', '50'
    gateway_release_bundle.generate(bundle, commit, workflow, run_id)
    profile = ci_profile(dict(INSTALL, installationId='fixture', revision=1), 18080)
    released, = (item for item in load_release_routes(bundle, commit, workflow, run_id, profile)
                 if item['id'] in route_ids)
    assert (released['id'], released['uri']) == (route_id, route['uri'])
    assert released['plugins']['request-validation'] == validation
    assert released['plugins']['proxy-rewrite'] == {'uri': owner_path}

    def mediate(delegated_scope, request, uri):
        engine = dispatch_engine(request, delegated_scope, uri)
        ctx = engine.lua.table()
        plugins = route['plugins']
        engine.lua.execute(plugins['serverless-pre-function']['functions'][-1].encode())(None, ctx)
        engine.body = b'{}'  # APISIX may re-encode the live request body after capture.
        engine.lua.execute(plugins['serverless-post-function']['functions'][0].encode())(None, ctx)
        return engine

    for bad_args in rejected:
        bad_body = dispatch_body(schema, bad_args)
        assert not validator.is_valid(bad_body)
        with pytest.raises(Denied) as denied:
            mediate(scope, bad_body, owner_path)
        assert denied.value.args == (400,)
        assert json.loads(denied.value.response_body)['code'] == INVALID_TOOL_ARGUMENTS

    with pytest.raises(Denied) as denied:
        mediate(cap, body, route['uri'])
    assert denied.value.args == (403,)
    owner = mediate(scope, body, owner_path)
    assert owner.body == json.dumps(args, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False).encode('utf-8')
    assert b'authorization' not in owner.headers and b'x-ouf-unlisted' not in owner.headers
    assert b'x-ouf-delegation' not in owner.headers
    receipt = verified_owner_receipt(owner)
    assert receipt['capability'] == cap and receipt['path'] == owner_path
    assert receipt['subject'] == 'human-a' and receipt['tenant'] == 'tenant-a'

    capability_contracts()[cap]['publicationState'] = 'REVOKED'
    with pytest.raises(ConfigError, match='MCP THS link capability missing or inconsistent'):
        compile_config(config)
    with pytest.raises(ValueError, match='active MCP THS link capability required'):
        materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')


def fixture_runtime(config):
    projection = json.loads((ROOT / 'tests/fixtures/installation-projection-lab.json').read_bytes())
    projection['gateway'].update(issuerUrl=INSTALL['issuerUrl'], requiredAudience=INSTALL['gatewayAudience'])
    projection['iam']['workloadClients']['mcpServer'] = INSTALL['mcpServiceIdentity']
    projection['mcp']['environment']['MCP_OIDC_CLIENT_ID'] = INSTALL['mcpServiceIdentity']
    return apply_projection(compile_config(config), projection)


def dispatch_engine(body, scope, uri):
    headers = {'X-OUF-Delegation': proof(dict(human(), scope=scope)),
               'X-Correlation-ID': body['CorrelationID'], 'Idempotency-Key': body['IdempotencyKey'],
               'X-Tool-Attempt-ID': body['AttemptID'], 'X-OUF-Unlisted': 'forged'}
    return Engine(workload(), headers, body, uri=uri)


def verified_owner_receipt(owner):
    encoded, signature = owner.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    assert hmac.compare_digest(base64.urlsafe_b64decode(signature + b'=='),
                               hmac.digest(KEY.encode(), b'ouf-managed-file-owner-v1.' + encoded, 'sha256'))
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
    assert receipt['bodyHash'] == hashlib.sha256(owner.body).hexdigest()
    return receipt


@pytest.mark.parametrize('mode', ['profile', 'preview', 'create', 'handoff', 'review-prepare', 'review-read'])
def test_managed_file_preserves_envelope_and_owner_receipt(mode):
    runtime = fixture_runtime(ROOT / 'ouf-config')
    existing = managed_file(runtime, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY')
    routes = materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')['routes']
    route, = (route for route in routes if route['id'] == 'mcp-managed-file-' + mode)
    schema = route['plugins']['request-validation']['body_schema']
    body = review_request(mode) if mode.startswith('review-') else managed_request(mode)
    Draft7Validator(schema, format_checker=FormatChecker()).validate(body)
    owner_path = '/api/internal/v1/onboarding/managed-file-mcp/' + mode
    owner = dispatch_engine(body, body['CapabilityID'], owner_path)
    original = owner.body
    # The retained owner function supplies the predecessor's envelope and receipt behavior.
    predecessor = dispatch_engine(body, body['CapabilityID'], owner_path)
    retained = function('execute_managed_file_retained', INSTALL, 'DELEGATION_KEY', 'OWNER_KEY')
    predecessor.lua.execute(retained.encode())(None, None)
    owner.lua.execute(route['plugins']['serverless-post-function']['functions'][0].encode())(None, None)
    assert owner.body == predecessor.body == original
    assert verified_owner_receipt(owner) == verified_owner_receipt(predecessor)
