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
from tools.materialize_semantic_proposal import materialize

ROOT=Path(__file__).resolve().parents[1]
OPS={'create':'ouf.semantic.propose','validate':'ouf.semantic.review.prepare','request':'ouf.semantic.approval.request','read':'ouf.semantic.proposal.read'}
def request(name='create'):
    e=envelope();cap=OPS[name]
    a={'proposalKey':'teatri-fixture'}
    if name=='create':a['commands']=[{'semanticId':'urn:fixture:Teatro','artifactType':'CLASS','namespace':'urn:fixture:','localName':'Teatro','ownerRef':'fixture-owner','authorityRef':'fixture-authority','semanticVersion':'1.0.0','labels':{'it':'Teatro'},'definition':{}}]
    elif name!='read':a['expectedVersion']=0 if name=='validate' else 1
    e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='semantic',OperationClass='READ' if name=='read' else 'COMMAND',Arguments=a)
    return e
def execute(name='create',e=None,claims=None,delegation=None):
    e=e or request(name)
    scope='ouf.semantic.propose' if name=='read' else e['CapabilityID']
    delegation=delegation or proof(dict(human(),scope='mcp.connect '+scope))
    headers={'X-OUF-Delegation':delegation,'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],'X-OUF-Semantic-Proposal-Receipt':'forged','Cookie':'untrusted'}
    engine=Engine(claims or workload(),headers,e,uri='/internal/capabilities/v1/execute/semantic/proposals/'+name)
    engine.lua.execute(function('execute_semantic_proposal',INSTALL,'DELEGATION_KEY','SEMANTIC_OWNER_KEY').encode())(None,None)
    return engine
@pytest.mark.parametrize('name',OPS)
def test_exact_proposal_receipt_and_closed_envelope(name):
    engine=execute(name);encoded,sig=engine.headers[b'x-ouf-semantic-proposal-receipt'].split(b'.')
    dec=lambda x:base64.urlsafe_b64decode(x+b'='*((4-len(x)%4)%4))
    assert hmac.compare_digest(dec(sig),hmac.new(KEY.encode(),b'ouf-semantic-proposal-owner-v1.'+encoded,hashlib.sha256).digest())
    r=json.loads(dec(encoded));assert r['purpose']=='semantic-proposal-owner'
    assert r['path']=='/api/internal/v1/semantic/proposals/'+name
    assert r['bodyHash']==hashlib.sha256(engine.body).hexdigest()
    assert b'authorization' not in engine.headers and b'cookie' not in engine.headers
    Draft202012Validator(json.loads((ROOT/f'schemas/mcp-gateway-semantic-proposal-{name}-dispatch-v1.json').read_text()),format_checker=FormatChecker()).validate(json.loads(engine.body))
@pytest.mark.parametrize('case',['scope','tenant','identity','workload','extra','publish','approval','version','key','batch'])
def test_deny_authority_confusion_and_unbounded_input(case):
    name='validate' if case=='version' else 'create';e=request(name);claims=workload();delegation=None
    if case=='scope':delegation=proof(dict(human(),scope='mcp.connect ouf.semantic.search'))
    if case=='tenant':delegation=proof(dict(human(),tenant_id='other',scope=e['CapabilityID']))
    if case=='identity':e['Identity']['PrincipalID']='other'
    if case=='workload':claims['azp']='other'
    if case=='extra':e['Arguments']['endpoint']='https://example.test'
    if case in ('publish','approval'):e['CapabilityID']='ouf.semantic.'+('publish' if case=='publish' else 'approve')
    if case=='version':e['Arguments']['expectedVersion']=0.5
    if case=='key':e['Arguments']['proposalKey']='../other'
    if case=='batch':e['Arguments']['commands']*=22
    with pytest.raises(Denied):execute(name,e,claims,delegation)
def test_materialization_is_additive_and_never_retries_owner_mutations():
    existing=established(runtime(),'$ENV://OIDC','DELEGATION_KEY');before=copy.deepcopy(existing)
    upstream={'scheme':'http','type':'roundrobin','nodes':{'semantic-fixture:8080':1}}
    ids={n:'fixture-proposal-'+n for n in OPS}
    result=materialize(existing,INSTALL,'DELEGATION_KEY','SEMANTIC_OWNER_KEY',upstream,ids)
    assert existing==before and result['routes'][:len(before['routes'])]==before['routes']
    added=result['routes'][len(before['routes']):]
    assert len(added)==4 and all(r['upstream']['retries']==0 for r in added)
    with pytest.raises(ValueError):materialize(result,INSTALL,'DELEGATION_KEY','SEMANTIC_OWNER_KEY',upstream,ids)
