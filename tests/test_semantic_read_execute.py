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
from tools.materialize_semantic_read import materialize

ROOT=Path(__file__).resolve().parents[1]

def request(name='search'):
    e=envelope();cap='ouf.semantic.search' if name=='search' else 'ouf.semantic.read'
    e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='semantic',OperationClass='READ',Arguments={'q':'teatro','limit':20} if name=='search' else {'semanticId':'test:class','revisionId':'11111111-1111-4111-8111-111111111111','publicationSetId':'22222222-2222-4222-8222-222222222222'})
    return e

def execute(name='search',e=None,claims=None,delegation=None):
    e=e or request(name)
    delegation=delegation or proof(dict(human(),scope='mcp.connect '+e['CapabilityID']))
    headers={'X-OUF-Delegation':delegation,'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],'X-OUF-Semantic-Read-Receipt':'forged','Cookie':'untrusted'}
    engine=Engine(claims or workload(),headers,e,uri='/api/internal/v1/semantic/consultation/'+name)
    engine.lua.execute(function('execute_semantic_read',INSTALL,'DELEGATION_KEY','SEMANTIC_OWNER_KEY').encode())(None,None)
    return engine

@pytest.mark.parametrize('name',['search','get'])
def test_receipt_binds_exact_original_envelope_and_only_fixed_read(name):
    engine=execute(name);encoded,sig=engine.headers[b'x-ouf-semantic-read-receipt'].split(b'.')
    dec=lambda x:base64.urlsafe_b64decode(x+b'='*((4-len(x)%4)%4))
    assert hmac.compare_digest(dec(sig),hmac.new(KEY.encode(),b'ouf-semantic-read-owner-v1.'+encoded,hashlib.sha256).digest())
    r=json.loads(dec(encoded));assert r['purpose']=='semantic-read-owner'
    assert r['path']=='/api/internal/v1/semantic/consultation/'+name
    assert r['bodyHash']==hashlib.sha256(engine.body).hexdigest()
    assert r['tenant']=='tenant-a' and r['subject']=='human-a'
    assert b'authorization' not in engine.headers and b'cookie' not in engine.headers
    assert 'idempotencyKey' not in r
    Draft202012Validator(json.loads((ROOT/f'schemas/mcp-gateway-semantic-{name}-dispatch-v1.json').read_text()),format_checker=FormatChecker()).validate(json.loads(engine.body))

@pytest.mark.parametrize('case',['scope','tenant','identity','workload','extra','limit','pin','authority','query'])
def test_denies_wrong_identity_unbounded_query_and_authoritative_action(case):
    name='get' if case=='pin' else 'search';e=request(name);claims=workload();delegation=None
    if case=='scope':delegation=proof(dict(human(),scope='mcp.connect'))
    if case=='tenant':delegation=proof(dict(human(),tenant_id='other',scope=e['CapabilityID']))
    if case=='identity':e['Identity']['PrincipalID']='other'
    if case=='workload':claims['azp']='other'
    if case=='extra':e['Arguments']['endpoint']='https://example.test'
    if case=='limit':e['Arguments']['limit']=101
    if case=='pin':del e['Arguments']['revisionId']
    if case=='authority':e['CapabilityID']='ouf.semantic.publish'
    if case=='query':e['Arguments']['q']='x'*257
    with pytest.raises(Denied):execute(name,e,claims,delegation)

def test_additive_materialization_preserves_upload_search_and_template():
    existing=established(runtime(),'$ENV://OIDC','DELEGATION_KEY')
    before=copy.deepcopy(existing)
    upstream={'scheme':'http','type':'roundrobin','nodes':{'semantic-fixture:8080':1}}
    ids={'search':'installation-search','get':'installation-get'}
    result=materialize(existing,INSTALL,'DELEGATION_KEY','SEMANTIC_KEY',upstream,ids)
    assert existing==before and result['routes'][:-2]==before['routes']
    assert result['routes'][-1]['upstream']['nodes']==upstream['nodes']
    with pytest.raises(ValueError):materialize(result,INSTALL,'DELEGATION_KEY','SEMANTIC_KEY',upstream,ids)
    with pytest.raises(ValueError):materialize(existing,INSTALL,'KEY','KEY',upstream,ids)
    with pytest.raises(ValueError):materialize(existing,INSTALL,'DELEGATION_KEY','SEMANTIC_KEY',{},ids)
    with pytest.raises(ValueError):materialize(existing,INSTALL,'DELEGATION_KEY','SEMANTIC_KEY',upstream,{'search':'same','get':'same'})
