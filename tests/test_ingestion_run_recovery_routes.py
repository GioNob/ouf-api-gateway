import base64
import hashlib
import hmac
import json
import re
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.test_dispatch_schema_contract import dispatch_body
from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.test_file_loop_coherence import retained_installation
from tools.apply_installation_projection import apply_projection
from tools.compile_config import ConfigError, compile_config
from tools.materialize_managed_file_mcp import materialize as managed_file
from tools.materialize_onboarding_review import materialize
from tools.mcp_dispatch_contract import INVALID_TOOL_ARGUMENTS, capability_contracts

ROOT = Path(__file__).resolve().parents[1]
DECLARATION = Path('routes/northbound/mcp-ingestion-run-recovery-link.json')
LINK_ID = 'mcp-ingestion-run-recovery-link'
LINK_PATH = '/api/internal/v1/onboarding/ths-links/ingestion-run-recovery'
RUN_ID = '11111111-1111-4111-8111-111111111111'
RUNS = '/api/trusted-human/v1/ingestion/runs/'


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


# Pending D-085 B.2/B.4: the MCP branch sprint-03/task-50-next-step has not yet
# declared the THS link capabilities. Strict: this turns red as soon as the
# synchronized manifest declares them, so the dispatch routes get completed.
@pytest.mark.xfail(strict=True, reason='MCP manifest does not declare the THS link capability yet (D-085 B.2)')
def test_recovery_link_capability_is_present_in_pinned_manifest():
    declaration = json.loads((ROOT / 'ouf-config' / DECLARATION).read_bytes())
    assert declaration['capabilityId'] in capability_contracts(), (
        'D-085 B.2: the pinned MCP manifest must declare the capability for POST ' + LINK_PATH
        + ' and its ID must be set in ' + DECLARATION.as_posix()
    )


def test_recovery_link_stays_closed_until_manifest_binding(tmp_path, monkeypatch):
    config = tmp_path / 'ouf-config'
    shutil.copytree(ROOT / 'ouf-config', config)
    path = config / DECLARATION
    declaration = json.loads(path.read_bytes())
    declaration['capabilityId'] = None
    path.write_text(json.dumps(declaration), encoding='utf-8')
    assert not any(route['id'] == LINK_ID for route in compile_config(config)['routes'])
    cap, scope = 'fixture.link.capability', 'fixture.link.scope'
    declaration['capabilityId'] = cap
    path.write_text(json.dumps(declaration), encoding='utf-8')
    with pytest.raises(ConfigError, match='MCP recovery-link capability missing'):
        compile_config(config)

    schema = {
        'type': 'object', 'additionalProperties': False,
        'required': ['sourceId', 'runId', 'expectedVersion'],
        'properties': {'sourceId': {'type': 'string'}, 'runId': {'type': 'string', 'format': 'uuid'},
                       'expectedVersion': {'type': 'integer', 'minimum': 0, 'maximum': 2**53 - 1}},
    }
    monkeypatch.setitem(capability_contracts(), cap, {
        'capabilityId': cap, 'gatewayBindingRef': 'capability://fixture.link.binding',
        'owner': 'onboarding', 'operationClass': 'COMMAND', 'toolEligible': False, 'publicationState': 'ACTIVE',
        'requiredAuthorizationCapability': scope, 'inputSchema': schema,
        'baseCostEnvelope': {'hardMaxResultBytes': 4096},
    })
    projection = json.loads((ROOT / 'tests/fixtures/installation-projection-lab.json').read_bytes())
    projection['gateway'].update(issuerUrl=INSTALL['issuerUrl'], requiredAudience=INSTALL['gatewayAudience'])
    projection['iam']['workloadClients']['mcpServer'] = INSTALL['mcpServiceIdentity']
    projection['mcp']['environment']['MCP_OIDC_CLIENT_ID'] = INSTALL['mcpServiceIdentity']
    runtime = apply_projection(compile_config(config), projection)
    existing = managed_file(runtime, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY')
    routes = materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')['routes']
    route = next(route for route in routes if route['id'] == LINK_ID)
    assert route['uri'] == '/internal/capabilities/v1/execute/fixture.link.binding'
    assert route['methods'] == ['POST'] and route['upstream']['retries'] == 0
    assert route['upstream']['nodes'] == {'ouf-onboarding:8080': 1}
    assert route['plugins']['proxy-rewrite']['uri'] == LINK_PATH
    validation = route['plugins']['request-validation']
    assert validation['rejected_msg'] == INVALID_TOOL_ARGUMENTS
    schema = validation['body_schema']
    args = {'sourceId': 'fixture-source', 'runId': RUN_ID, 'expectedVersion': 2**53 - 1}
    body = dispatch_body(schema, args)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    assert validator.is_valid(body)
    assert not validator.is_valid(dispatch_body(schema, dict(args, approved=True)))
    assert not validator.is_valid(dispatch_body(schema, dict(args, runId='invalid')))

    def mediate(delegated_scope):
        headers = {'X-OUF-Delegation': proof(dict(human(), scope=delegated_scope)),
                   'X-Correlation-ID': body['CorrelationID'], 'Idempotency-Key': body['IdempotencyKey'],
                   'X-Tool-Attempt-ID': body['AttemptID'], 'X-OUF-Unlisted': 'forged'}
        engine = Engine(workload(), headers, body, uri=route['uri'])
        ctx = engine.lua.table_from({b'ouf_original_body': engine.body})
        engine.lua.execute(route['plugins']['serverless-post-function']['functions'][0].encode())(None, ctx)
        return engine

    with pytest.raises(Denied):
        mediate(cap)
    owner = mediate(scope)
    assert json.loads(owner.body) == args
    assert b'authorization' not in owner.headers and b'x-ouf-unlisted' not in owner.headers
    assert b'x-ouf-delegation' not in owner.headers
    encoded, signature = owner.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    assert hmac.compare_digest(base64.urlsafe_b64decode(signature + b'=='),
                               hmac.digest(KEY.encode(), b'ouf-managed-file-owner-v1.' + encoded, 'sha256'))
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
    assert receipt['capability'] == cap and receipt['path'] == LINK_PATH
    assert receipt['subject'] == 'human-a' and receipt['tenant'] == 'tenant-a'
    assert receipt['bodyHash'] == hashlib.sha256(owner.body).hexdigest()

    capability_contracts()[cap]['publicationState'] = 'REVOKED'
    with pytest.raises(ConfigError, match='MCP recovery-link capability missing or inconsistent'):
        compile_config(config)
    with pytest.raises(ValueError, match='active MCP recovery-link capability required'):
        materialize(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')
