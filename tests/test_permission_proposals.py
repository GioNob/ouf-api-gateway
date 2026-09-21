import base64
import hashlib
import hmac
import json
import copy
import pytest
from jsonschema import Draft7Validator
from tests.test_execute_delegation import Engine, Denied, human, workload, envelope, proof, runtime, INSTALL, KEY
from tools.delegation_functions import function
from tools.materialize_permission_proposals import materialize

CAP='authorization.permissions.propose'
def request():
    e=envelope();e.update(CapabilityID=CAP,GatewayBindingRef='capability://'+CAP,Owner='authorization',OperationClass='COMMAND',Arguments={'operation':'REVOKE','grantId':'test','reason':'human review'})
    return e

def execute(body=None,claims=None,delegation=None):
    e=request() if body is None else body
    if delegation is None:delegation=proof(dict(human(),scope='mcp.connect '+CAP,externalRoleRefs=['ente:staff']))
    h={'X-OUF-Delegation':delegation,'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID']}
    engine=Engine(workload() if claims is None else claims,h,e)
    engine.modules[b'resty.openssl.digest']=engine.lua.table_from({b'new':lambda algorithm:engine.lua.table_from({b'final':lambda _,data:hashlib.sha256(data).digest()})})
    engine.modules[b'resty.string']=engine.lua.table_from({b'to_hex':lambda data:data.hex().encode()})
    engine.lua.execute(function('execute_permissions',INSTALL,'TEST_KEY','OWNER_KEY').encode())(None,None)
    return engine

def test_lua_receipt_binds_identity_capability_path_body_and_expiry():
    e=execute();encoded,signature=e.headers[b'x-ouf-authorization-receipt'].split(b'.');pad=lambda s:s+b'='*((4-len(s)%4)%4)
    assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),hmac.new(KEY.encode(),b'ouf-authorization-owner-v1.'+encoded,hashlib.sha256).digest())
    r=json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert r['path']=='/api/internal/v1/authorization/permissions/propose'
    assert r['capability']==CAP and r['subject']=='human-a' and r['roles']=='ente:staff'
    assert r['bodyHash']==hashlib.sha256(e.body).hexdigest() and r['exp']-r['iat']==30
    assert b'authorization' not in e.headers and b'x-ouf-delegation' not in e.headers
    assert json.loads(e.body)==request()

@pytest.mark.parametrize('kind',['scope','workload','identity','confirm','owner'])
def test_actual_lua_rejects_escalation(kind):
    e=request();claims=workload();delegation=None
    if kind=='scope':delegation=proof(dict(human(),scope='mcp.connect'))
    if kind=='workload':claims['azp']='attacker'
    if kind=='identity':e['Identity']['PrincipalID']='admin'
    if kind=='confirm':e['CapabilityID']='authorization.policy.publish'
    if kind=='owner':e['Owner']='mcp'
    with pytest.raises(Denied):execute(e,claims,delegation)

def test_materialized_routes_are_closed_and_have_no_confirmation_backend():
    doc=materialize(runtime(),'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY')
    routes=[r for r in doc['routes'] if '/execute/authorization/' in r.get('uri','')]
    assert len(routes)==3
    for r in routes:
        assert r['upstream']['nodes']=={'ouf-onboarding:8080':1}
        assert r['plugins']['proxy-rewrite']['uri'].split('/')[-1] in ('read','propose','status')
        assert r['upstream']['retries']==0
        if r['uri'].endswith('/propose'):
            validator=Draft7Validator(r['plugins']['request-validation']['body_schema']);validator.validate(request())
            bad=request();bad['Arguments']['confirm']=True;assert not validator.is_valid(bad)
    rt=runtime();binding=next(r for r in rt['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId')==CAP);binding['plugins']['proxy-rewrite']['uri']='/api/trusted-human/v1/authorization/policies'
    with pytest.raises(ValueError):materialize(rt,'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY')


def test_ths_routes_only_forward_to_session_owner():
    routes=[r for r in materialize(runtime(),'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY')['routes'] if r['id'].startswith('authorization-ths-')]
    assert len(routes)==3
    assert all(r['upstream']['nodes']=={'ouf-onboarding:8080':1} for r in routes)
    assert all('openid-connect' not in r['plugins'] for r in routes)
    assert all('/api/trusted-human/v1/authorization/*' not in r['uris'] for r in routes)
