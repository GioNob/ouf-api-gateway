import copy
import hashlib
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tools.delegation_functions import function
from tools.materialize_operational_execute import CAPABILITIES, dispatch_schema, materialize
from tests.test_execute_delegation import Engine, Denied, INSTALL, envelope, human, workload, proof, runtime

def dispatch(capability, arguments=None, nested=False):
    body = envelope()
    body.update(CapabilityID=capability, GatewayBindingRef='capability://' + capability,
                Owner=CAPABILITIES[capability][0], Arguments=arguments or {},
                AuthorizationDecisionRef='bundle:6:' + capability, MaxResultBytes=524288)
    if nested: body['Identity']['ServicePrincipalID'] = INSTALL['mcpServiceIdentity']
    body['RequestHash'] = hashlib.sha256(json.dumps(body['Arguments'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body

def invoke(capability, body=None, delegated=None, claims=None, **kwargs):
    body = body or dispatch(capability)
    context = human(); context['scope'] = 'mcp.connect operations.status.read operations.incident.read'
    delegated = delegated or proof(context)
    headers = {'X-OUF-Delegation': delegated, 'X-Correlation-ID': body['CorrelationID'],
        'Idempotency-Key': body['IdempotencyKey'], 'X-Tool-Attempt-ID': body['AttemptID'],
        'X-OUF-Delegation-Verified': 'forged', 'X-OUF-External-Role-Refs': 'forged-admin', 'Cookie': 'secret'}
    engine = Engine(claims or workload(), headers, body, **kwargs)
    owner, _, _, _, scope, _ = CAPABILITIES[capability]
    engine.lua.execute(function('execute_operational', INSTALL, 'TEST_KEY',
        operational_binding={'capability': capability, 'owner': owner, 'scope': scope}).encode())(None, None)
    return engine

@pytest.mark.parametrize('capability', CAPABILITIES)
def test_operational_delegation_has_fixed_owner_and_signed_human_context(capability):
    body = dispatch(capability, {'limit': 7}, nested=True)
    context = human(); context['scope'] += ' operations.incident.read'; context['externalRoleRefs'] = ['ouf:viewer']
    engine = invoke(capability, body=body, delegated=proof(context))
    assert json.loads(engine.body) == {'limit': 7}
    assert engine.headers[b'x-ouf-principal-id'] == b'human-a'
    assert engine.headers[b'x-ouf-service-principal'] == b'workload'
    assert engine.headers[b'x-ouf-actor-type'] == b'HUMAN'
    assert engine.headers[b'x-ouf-capability-id'].decode() == capability
    assert engine.headers[b'x-ouf-external-role-refs'] == b'ouf:viewer'
    assert b'authorization' not in engine.headers and b'cookie' not in engine.headers
    if body['Owner'] == 'mcp':
        assert engine.headers[b'x-ouf-delegation-verified'] == b'mcp-operational-aggregate-v1'
        assert engine.headers[b'x-ouf-delegation'].decode() == proof(context)
    else:
        assert b'x-ouf-delegation' not in engine.headers and b'x-ouf-delegation-verified' not in engine.headers

@pytest.mark.parametrize('mode', ['principal', 'tenant', 'service', 'actor', 'acr', 'owner', 'capability', 'operation', 'binding', 'workload', 'scope', 'expired', 'forged', 'missing-key', 'correlation'])
def test_operational_delegation_denies_changed_identity_authority_or_scope(mode):
    cap = 'ouf.ingestion.operations.incidents'
    body = dispatch(cap, nested=True); claims = workload(); context = human(); context['scope'] += ' operations.incident.read'
    kwargs = {}
    if mode in ('principal', 'tenant', 'service', 'actor', 'acr'):
        key = {'principal': 'PrincipalID', 'tenant': 'TenantID', 'service': 'ServicePrincipalID', 'actor': 'ActorType', 'acr': 'AuthenticationContextRef'}[mode]
        body['Identity'][key] = 'forged'
    elif mode == 'owner': body['Owner'] = 'mcp'
    elif mode == 'capability': body['CapabilityID'] = 'ouf.operations.incidents'
    elif mode == 'operation': body['OperationClass'] = 'COMMAND'
    elif mode == 'binding': body['GatewayBindingRef'] = 'capability://arbitrary'
    elif mode == 'workload': claims['azp'] = 'other'
    elif mode == 'scope': context['scope'] = 'mcp.connect operations.status.read'
    elif mode == 'expired': kwargs['now'] = 1061
    elif mode == 'missing-key': kwargs['key'] = None
    elif mode == 'correlation': body['CorrelationID'] = 'different' # override emitted wire header below
    delegated = proof(context)
    if mode == 'forged': delegated = delegated[:-2] + 'zz'
    if mode == 'correlation':
        engine = Engine(claims, {'X-OUF-Delegation': delegated, 'X-Correlation-ID': 'original', 'Idempotency-Key': body['IdempotencyKey'], 'X-Tool-Attempt-ID': body['AttemptID']}, body)
        with pytest.raises(Denied):
            engine.lua.execute(function('execute_operational', INSTALL, 'TEST_KEY', operational_binding={'capability': cap, 'owner': 'ingestion', 'scope': 'operations.incident.read'}).encode())(None, None)
    else:
        with pytest.raises(Denied): invoke(cap, body, delegated, claims, **kwargs)

@pytest.mark.parametrize('capability', CAPABILITIES)
def test_operational_queries_are_closed_and_cursor_is_owner_only(capability):
    validator = Draft7Validator(dispatch_schema(capability), format_checker=FormatChecker())
    valid = [{}, {'limit': 100}, {'since': '2026-10-11T00:00:00Z'}]
    invalid = [None, [], {'future': 'secret'}, {'limit': 0}, {'limit': True}, {'limit': 101}, {'since': '2026-10-11T00:00:00'}]
    producer_incidents = CAPABILITIES[capability][0] != 'mcp' and capability.endswith('.incidents')
    cursor = {'cursor': '11111111-1111-4111-8111-111111111111'}
    (valid if producer_incidents else invalid).append(cursor)
    if producer_incidents: valid.append({'snapshot': True, 'limit': 100})
    else: invalid.append({'snapshot': True})
    invalid += [{'cursor': cursor['cursor'], 'limit': 1}, {'cursor': '00000000-0000-0000-0000-000000000000'}, {'snapshot': False}]
    if CAPABILITIES[capability][0] == 'gateway': invalid.append({'sourceId': 'source'})
    else: valid.append({'sourceId': 'source'})
    if capability.endswith('.incidents'): valid.append({'state': 'OPEN'})
    else: invalid.append({'state': 'OPEN'})
    for args in valid: assert validator.is_valid(dispatch(capability, args)), args
    for args in invalid:
        body = dispatch(capability); body['Arguments'] = args
        assert not validator.is_valid(body), args

def test_operational_materialization_is_closed_and_preserves_existing_status_boundary():
    doc = materialize(runtime(), '$ENV://OIDC', 'DELEGATION_KEY')
    routes = [r for r in doc['routes'] if r.get('labels', {}).get('ouf-mediation') == 'operational-execute-v1']
    assert len(routes) == 6 and len({r['uri'] for r in routes}) == 6
    for route in routes:
        cap = route['plugins']['request-validation']['body_schema']['properties']['CapabilityID']['const']
        _, service, port, path, _, _ = CAPABILITIES[cap]
        assert route['uri'] == '/internal/capabilities/v1/execute/' + cap
        assert route['upstream']['nodes'] == {f'{service}:{port}': 1} and route['upstream']['retries'] == 0
        assert route['plugins']['proxy-rewrite']['uri'] == path
    status = next(r for r in doc['routes'] if r.get('uri') == '/internal/capabilities/v1/execute')
    assert 'mcp-operational-aggregate-v1' not in status['plugins']['serverless-post-function']['functions'][0]

@pytest.mark.parametrize('change', ['destination', 'scope', 'workload', 'actor', 'timeout', 'operation', 'tool-exposure', 'duplicate', 'missing'])
def test_operational_materialization_rejects_binding_drift(change):
    rt = runtime(); target = next(r for r in rt['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == 'ouf.ingestion.operations.incidents')
    if change == 'destination': target['service_id'] = 'evil'
    elif change == 'scope': target['x-ouf-policy']['requiredScope'] = 'operations.status.read'
    elif change == 'workload': target['x-ouf-policy']['allowedServiceIdentities'].append('other')
    elif change == 'actor': target['x-ouf-policy']['allowedActorTypes'] = ['HUMAN']
    elif change == 'timeout': target['x-ouf-policy']['timeoutSeconds'] = 100
    elif change == 'operation': target['x-ouf-capability']['operationType'] = 'COMMAND'
    elif change == 'tool-exposure': target['x-ouf-capability']['toolEligible'] = True
    elif change == 'duplicate': rt['routes'].append(copy.deepcopy(target))
    elif change == 'missing': rt['routes'].remove(target)
    with pytest.raises(ValueError): materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')

def test_operational_renderer_cannot_embed_arbitrary_authority():
    for binding in ({}, {'capability': 'arbitrary', 'owner': 'mcp', 'scope': 'operations.status.read'}, {'capability': 'ouf.gateway.operations.summary', 'owner': 'mcp', 'scope': 'operations.status.read'}):
        with pytest.raises(ValueError): function('execute_operational', INSTALL, 'TEST_KEY', operational_binding=binding)
