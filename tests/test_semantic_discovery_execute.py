import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from tests.test_execute_delegation import Engine, Denied, human, workload, envelope, proof, runtime, INSTALL, KEY
from tools.delegation_functions import function
from tools.materialize_apisix_execute_runtime import materialize as established
from tools.materialize_semantic_discovery import materialize

ROOT=Path(__file__).resolve().parents[1]
OPS=('request','status','candidates')

def request(name='request'):
    cap='ouf.semantic.discovery'+('' if name=='request' else '.'+name)
    e=envelope()
    args={'requestedArtifactType':'CLASS','intent':'teatro','preferredLanguages':['it','en'],'idempotencyKey':'discovery-test-0001'} if name=='request' else {'requestId':'11111111-1111-4111-8111-111111111111'}
    e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='semantic',OperationClass='COMMAND' if name=='request' else 'READ',Arguments=args)
    return e

def execute(name='request',e=None,claims=None,delegation=None):
    e=e or request(name)
    delegation=delegation or proof(dict(human(),scope='mcp.connect ouf.semantic.discovery'))
    headers={'X-OUF-Delegation':delegation,'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],'X-OUF-Semantic-Discovery-Receipt':'forged','Cookie':'untrusted'}
    engine=Engine(claims or workload(),headers,e,uri='/internal/capabilities/v1/execute/semantic/discovery/'+name)
    engine.lua.execute(function('execute_semantic_discovery',INSTALL,'DELEGATION_KEY','DISCOVERY_OWNER_KEY').encode())(None,None)
    return engine

@pytest.mark.parametrize('name',OPS)
def test_receipt_binds_exact_envelope_and_fixed_owner_path(name):
    engine=execute(name);encoded,sig=engine.headers[b'x-ouf-semantic-discovery-receipt'].split(b'.')
    dec=lambda x:base64.urlsafe_b64decode(x+b'='*((4-len(x)%4)%4))
    assert hmac.compare_digest(dec(sig),hmac.new(KEY.encode(),b'ouf-semantic-discovery-owner-v1.'+encoded,hashlib.sha256).digest())
    assert not hmac.compare_digest(dec(sig),hmac.new(KEY.encode(),b'ouf-semantic-read-owner-v1.'+encoded,hashlib.sha256).digest())
    r=json.loads(dec(encoded))
    assert r['purpose']=='semantic-discovery-owner' and r['path']=='/api/internal/v1/semantic/discovery/'+name
    assert r['bodyHash']==hashlib.sha256(engine.body).hexdigest()
    assert r['tenant']=='tenant-a' and r['subject']=='human-a'
    assert b'authorization' not in engine.headers and b'cookie' not in engine.headers and b'x-ouf-delegation' not in engine.headers
    Draft202012Validator(json.loads((ROOT/f'schemas/mcp-gateway-semantic-discovery-{name}-dispatch-v1.json').read_text()),format_checker=FormatChecker()).validate(json.loads(engine.body))

@pytest.mark.parametrize('case',['scope','tenant','identity','workload','extra','intent','key','languages','type','authority','operation','requestId'])
def test_denies_bad_identity_arguments_and_authority(case):
    name='status' if case=='requestId' else 'request'
    e=request(name);claims=workload();delegation=None
    if case=='scope':delegation=proof(dict(human(),scope='mcp.connect'))
    if case=='tenant':delegation=proof(dict(human(),tenant_id='other',scope='ouf.semantic.discovery'))
    if case=='identity':e['Identity']['PrincipalID']='other'
    if case=='workload':claims['azp']='other'
    if case=='extra':e['Arguments']['endpoint']='https://example.test'
    if case=='intent':e['Arguments']['intent']='x'*2001
    if case=='key':e['Arguments']['idempotencyKey']='short'
    if case=='languages':e['Arguments']['preferredLanguages']=['it']*6
    if case=='type':e['Arguments']['requestedArtifactType']='ARBITRARY'
    if case=='authority':e['CapabilityID']='ouf.semantic.publish'
    if case=='operation':e['OperationClass']='READ'
    if case=='requestId':e['Arguments']['requestId']='1-1-1-1-1'
    with pytest.raises(Denied):execute(name,e,claims,delegation)

def test_additive_materialization_preserves_all_existing_routes():
    existing=established(runtime(),'$ENV://OIDC','DELEGATION_KEY');before=copy.deepcopy(existing)
    upstream={'scheme':'http','type':'roundrobin','nodes':{'semantic-fixture:8080':1}}
    ids={name:'installation-discovery-'+name for name in OPS}
    result=materialize(existing,INSTALL,'DELEGATION_KEY','DISCOVERY_KEY',upstream,ids)
    assert existing==before and result['routes'][:-3]==before['routes']
    for route,name in zip(result['routes'][-3:],OPS):
        assert route['uri']=='/internal/capabilities/v1/execute/semantic/discovery/'+name
        assert route['plugins']['proxy-rewrite']['uri']=='/api/internal/v1/semantic/discovery/'+name
        assert route['upstream']['nodes']==upstream['nodes'] and route['upstream']['retries']==0
    with pytest.raises(ValueError):materialize(result,INSTALL,'DELEGATION_KEY','DISCOVERY_KEY',upstream,ids)
    with pytest.raises(ValueError):materialize(existing,INSTALL,'KEY','KEY',upstream,ids)
    with pytest.raises(ValueError):materialize(existing,INSTALL,'DELEGATION_KEY','DISCOVERY_KEY',{},ids)
    with pytest.raises(ValueError):materialize(existing,INSTALL,'DELEGATION_KEY','DISCOVERY_KEY',upstream,{name:'same' for name in OPS})

@pytest.mark.parametrize('name',OPS)
def test_schema_rejects_caller_backend_and_unknown_identity(name):
    schema=json.loads((ROOT/f'schemas/mcp-gateway-semantic-discovery-{name}-dispatch-v1.json').read_text())
    validator=Draft202012Validator(schema,format_checker=FormatChecker());e=request(name)
    validator.validate(e)
    for target,key,value in [('Arguments','endpoint','https://example.test'),('Identity','Issuer','forged')]:
        bad=copy.deepcopy(e);bad[target][key]=value
        assert list(validator.iter_errors(bad))
