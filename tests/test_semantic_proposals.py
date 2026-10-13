import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import pytest
from jsonschema import Draft7Validator, FormatChecker
from tests.test_execute_delegation import Engine, Denied, human, workload, envelope, proof, runtime, INSTALL, KEY
from tools.delegation_functions import function
from tools.materialize_semantic_proposals import materialize, CAPABILITIES

def request(cap='ouf.semantic.propose', actor='HUMAN'):
    mode, operation, _ = CAPABILITIES[cap]
    e = envelope()
    args = {'create': {'semanticId': 'ouf:test:Place', 'artifactType': 'CLASS', 'namespace': 'ouf',
                      'localName': 'Place', 'ownerRef': 'owner', 'authorityRef': 'authority',
                      'semanticVersion': '1.0.0', 'labels': {'it': 'Luogo'}, 'definition': {}, 'commandKey': 'intent-1'},
            'validate': {'revisionId': '22222222-2222-4222-8222-222222222222', 'expectedRowVersion': 0, 'commandKey': 'intent-1'},
            'review': {'revisionId': '22222222-2222-4222-8222-222222222222', 'expectedRowVersion': 0,
                       'validationRunId': '33333333-3333-4333-8333-333333333333', 'commandKey': 'intent-1'},
            'read': {'commandKey': 'intent-1'}}[mode]
    e.update(CapabilityID=cap, GatewayBindingRef='capability://'+cap, Owner='semantic', OperationClass=operation,
             Arguments=args, IdempotencyKey='intent-1' if operation == 'COMMAND' else 'read-1')
    e['Identity']['ActorType'] = actor
    return e

def execute(cap='ouf.semantic.propose', body=None, actor='HUMAN', claims=None, delegation=None, key=KEY):
    e = request(cap, actor) if body is None else body
    if delegation is None:
        delegation = proof(dict(human(), ouf_actor_type=actor, scope='mcp.connect '+CAPABILITIES[cap][2], externalRoleRefs=['ente:staff']))
    h = {'X-OUF-Delegation': delegation, 'X-Correlation-ID': e['CorrelationID'],
         'Idempotency-Key': e['IdempotencyKey'], 'X-Tool-Attempt-ID': e['AttemptID'],
         'X-OUF-Principal-ID': 'forged', 'Cookie': 'forged'}
    engine = Engine(workload() if claims is None else claims, h, e, key=key)
    engine.modules[b'resty.openssl.digest'] = engine.lua.table_from({b'new': lambda _: engine.lua.table_from({b'final': lambda _, data: hashlib.sha256(data).digest()})})
    engine.modules[b'resty.string'] = engine.lua.table_from({b'to_hex': lambda data: data.hex().encode()})
    engine.lua.execute(function('execute_semantic_proposals', INSTALL, 'TEST_KEY', 'OWNER_KEY',
        operational_binding={'capability': cap, 'owner': 'semantic', 'scope': CAPABILITIES[cap][2]}).encode())(None, None)
    return engine

@pytest.mark.parametrize('cap', CAPABILITIES)
@pytest.mark.parametrize('actor', ['HUMAN', 'AI_AGENT', 'SERVICE'])
def test_actual_lua_signs_exact_identity_path_body_and_owner_permission(cap, actor):
    engine = execute(cap, actor=actor)
    encoded, signature = engine.headers[b'x-ouf-semantic-proposal-receipt'].split(b'.')
    pad = lambda x: x+b'='*((4-len(x)%4)%4)
    assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),
        hmac.new(KEY.encode(), b'ouf-semantic-proposal-owner-v1.'+encoded, hashlib.sha256).digest())
    r = json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert r['purpose'] == 'semantic-proposal-owner' and r['path'] == '/api/semantic/v1/proposal-commands/'+CAPABILITIES[cap][0]
    assert r['capability'] == CAPABILITIES[cap][2] and r['actor'] == actor and r['subject'] == 'human-a'
    assert r['bodyHash'] == hashlib.sha256(engine.body).hexdigest() and r['exp']-r['iat'] == 30
    assert json.loads(engine.body) == request(cap, actor)
    assert not {'authorization', 'cookie', 'x-ouf-delegation', 'x-ouf-principal-id'} & {k.decode() for k in engine.headers}

@pytest.mark.parametrize('kind', ['scope', 'workload', 'tenant', 'identity', 'owner', 'operation', 'publish', 'intent', 'expired', 'future', 'signature', 'key'])
def test_actual_lua_blocks_unknown_authority_and_drift(kind):
    cap = 'ouf.semantic.propose'
    body = request(cap); claims = workload(); delegation = None; key = KEY
    if kind == 'scope': delegation = proof(dict(human(), scope='mcp.connect'))
    if kind == 'workload': claims['azp'] = 'attacker'
    if kind == 'tenant': body['Identity']['TenantID'] = 'tenant-b'
    if kind == 'identity': body['Identity']['PrincipalID'] = 'admin'
    if kind == 'owner': body['Owner'] = 'authorization'
    if kind == 'operation': body['OperationClass'] = 'READ'
    if kind == 'publish': body['CapabilityID'] = 'ouf.semantic.publish'
    if kind == 'intent': body['Arguments']['commandKey'] = 'new-intent'
    if kind in ('expired', 'future'):
        parts = proof(dict(human(), scope=cap)).split('.')
        p = json.loads(base64.urlsafe_b64decode(parts[0]+'='*((4-len(parts[0])%4)%4)));p.update(iat=1001, exp=1031) if kind == 'future' else p.update(iat=970, exp=1000)
        encoded = base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b'=')
        delegation = (encoded+b'.'+base64.urlsafe_b64encode(hmac.new(KEY.encode(),encoded,hashlib.sha256).digest()).rstrip(b'=')).decode()
    if kind == 'signature':
        value = proof(dict(human(), scope=cap)); at = value.index('.')+1
        delegation = value[:at]+('A' if value[at] != 'A' else 'B')+value[at+1:]
    if kind == 'key': key = None
    with pytest.raises(Denied): execute(cap, body=body, claims=claims, delegation=delegation, key=key)

def test_materializer_closed_routes_schemas_and_no_automatic_retry():
    doc = materialize(runtime(), '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'SEMANTIC_OWNER_KEY', 'AUTHORIZATION_OWNER_KEY')
    routes = [r for r in doc['routes'] if '/execute/semantic/' in r.get('uri', '')]
    assert len(routes) == 4
    assert len([r for r in doc['routes'] if r['id'].startswith('authorization-ths-')]) == 3
    assert len([r for r in doc['routes'] if '/execute/authorization/' in r.get('uri', '')]) == 3
    with pytest.raises(ValueError, match='preserve THS'):
        materialize(runtime(), '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'SEMANTIC_OWNER_KEY')
    for route in routes:
        assert route['upstream']['nodes'] == {'ouf-semantic-registry:8080': 1} and route['upstream']['retries'] == 0
        schema = route['plugins']['request-validation']['body_schema'];cap = schema['properties']['CapabilityID']['const']
        validator = Draft7Validator(schema, format_checker=FormatChecker());validator.validate(request(cap))
        bad = request(cap);bad['Arguments']['approvedBy'] = 'agent';assert not validator.is_valid(bad)
        bad = request(cap);bad['Arguments']['commandKey'] = '';assert not validator.is_valid(bad)
        assert '/api/trusted-human/' not in route['plugins']['proxy-rewrite']['uri']
    rt = runtime();route = next(r for r in rt['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == 'ouf.semantic.propose')
    route['plugins']['proxy-rewrite']['uri'] = '/api/trusted-human/v1/semantic-approval-challenges'
    with pytest.raises(ValueError): materialize(rt, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'SEMANTIC_OWNER_KEY', 'AUTHORIZATION_OWNER_KEY')

def test_ths_and_owner_signing_keys_are_not_tool_inputs():
    doc = materialize(runtime(), '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'SEMANTIC_OWNER_KEY', 'AUTHORIZATION_OWNER_KEY')
    assert not any('/semantic/' in r.get('uri', '') and ('publish' in r.get('uri', '') or 'decision' in r.get('uri', '')) for r in doc['routes'])
    with pytest.raises(ValueError): function('execute_semantic_proposals', INSTALL, 'TEST_KEY', 'bad-key')

def write_owner_vectors(path):
    vectors=[]
    for cap in CAPABILITIES:
        e=execute(cap,actor='AI_AGENT')
        vectors.append({'path':'/api/semantic/v1/proposal-commands/'+CAPABILITIES[cap][0],
                        'proof':e.headers[b'x-ouf-semantic-proposal-receipt'].decode(), 'body':e.body.decode()})
    Path(path).write_text(json.dumps(vectors)+'\n')
