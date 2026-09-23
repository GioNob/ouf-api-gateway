import base64
import hashlib
import hmac
import json

import pytest
from jsonschema import Draft7Validator
from tests.test_execute_delegation import Engine, Denied, human, workload, envelope, proof, runtime, INSTALL, KEY
from tools.delegation_functions import function
from tools.materialize_object_search import materialize


def request(args=None):
    e=envelope()
    e.update(CapabilityID='urban.object.search', GatewayBindingRef='capability://urban.object.search',Owner='udp',OperationClass='SEARCH',Arguments=args if args is not None else {'type':'ouf:Asset','pageSize':10})
    return e


def execute(body=None,claims=None,delegation=None):
    e=request() if body is None else body
    if delegation is None:delegation=proof(dict(human(),scope='mcp.connect urban.object.search',externalRoleRefs=['ente:viewer']))
    headers={'X-OUF-Delegation':delegation,'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],'X-OUF-UDP-Search-Receipt':'forged','Cookie':'untrusted'}
    engine=Engine(workload() if claims is None else claims,headers,e)
    engine.lua.execute(function('execute_object_search',INSTALL,'TEST_KEY','OWNER_KEY').encode())(None,None)
    return engine


def test_gateway_signs_exact_owner_body_and_strips_supplied_authority():
    engine=execute();encoded,signature=engine.headers[b'x-ouf-udp-search-receipt'].split(b'.')
    pad=lambda s:s+b'='*((4-len(s)%4)%4)
    assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),hmac.new(KEY.encode(),b'ouf-udp-search-owner-v1.'+encoded,hashlib.sha256).digest())
    receipt=json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert receipt['path']=='/api/udp/v1/objects/search' and receipt['capability']=='urban.object.search'
    assert receipt['tenant']=='tenant-a' and receipt['subject']=='human-a'
    assert receipt['bodyHash']==hashlib.sha256(engine.body).hexdigest()
    assert json.loads(engine.body)=={'type':'ouf:Asset','pageSize':10}
    assert b'authorization' not in engine.headers and b'cookie' not in engine.headers and b'x-ouf-delegation' not in engine.headers


@pytest.mark.parametrize('change', ['scope','tenant','identity','workload','wildcard','extra','pageSize','capability'])
def test_gateway_denies_untrusted_or_invalid_search(change):
    body=request();claims=workload();delegation=None
    if change=='scope':delegation=proof(dict(human(),scope='mcp.connect'))
    if change=='tenant':delegation=proof(dict(human(),tenant_id='another-tenant',scope='urban.object.search'))
    if change=='identity':body['Identity']['PrincipalID']='someone-else'
    if change=='workload':claims['azp']='untrusted'
    if change=='wildcard':body['Arguments']['type']='*'
    if change=='extra':body['Arguments']['sql']='select *'
    if change=='pageSize':body['Arguments']['pageSize']=101
    if change=='capability':body['CapabilityID']='authorization.policy.publish'
    with pytest.raises(Denied):execute(body,claims,delegation)


def test_compiler_binds_only_fixed_udp_service_and_rejects_changed_policy():
    doc=materialize(runtime(),'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','UDP_KEY')
    routes=[r for r in doc['routes'] if r.get('uri')=='/internal/capabilities/v1/execute/urban.object.search']
    assert len(routes)==1
    route=routes[0];assert route['upstream']['nodes']=={'ouf-udp-object-resolution:8080':1}
    assert route['upstream']['retries']==0 and route['plugins']['proxy-rewrite']['uri']=='/api/udp/v1/objects/search'
    schema=Draft7Validator(route['plugins']['request-validation']['body_schema'])
    assert schema.is_valid(request())
    assert not schema.is_valid(request({'type':'*'}))
    assert not schema.is_valid(request({'type':'ouf:Asset','sql':'select *'}))
    changed=runtime();binding=next(r for r in changed['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId')=='urban.object.search' and r.get('labels',{}).get('exposure')=='internal')
    binding['plugins']['proxy-rewrite']['uri']='/api/udp/v1/admin'
    with pytest.raises(ValueError):materialize(changed,'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY','UDP_KEY')
