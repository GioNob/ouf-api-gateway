import base64
import hashlib
import hmac
import json
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Engine, Denied, human, workload, envelope, proof, runtime, INSTALL, KEY
from tools.delegation_functions import function
from tools.materialize_managed_file_mcp import materialize
from ops.apisix.deploy_managed_file_mcp import select

PROFILE='ouf.managed-source.file.profile'
PREVIEW='ouf.managed-source.preview'
CREATE='ouf.managed-source.onboarding.create'
ASSET='00000000-0000-4000-8000-000000000001'
OTHER='00000000-0000-4000-8000-000000000002'

def request(mode='profile'):
    cap={'profile':PROFILE,'preview':PREVIEW,'create':CREATE}.get(mode,PROFILE)
    args={'assetId':ASSET}
    if mode=='preview':args['profileId']=OTHER
    if mode=='create':args.update(profileId=OTHER,sourceId='cinema',name='Cinema',owner='Comune',targetClassIri='https://example.org/Cinema',semanticRefs=['core@1'],sourceObjectKeyFields=[],fields=[{'fieldName':'cinema','extractionDecision':'INCLUDE','dataAccessLabel':'OPEN','targetPropertyIri':'https://example.org/name'}])
    e=envelope()
    e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='onboarding',
             OperationClass='READ' if mode=='preview' else 'COMMAND',Arguments=args)
    return e

def execute(mode='profile',body=None,delegation=None,uri=None):
    e=request(mode) if body is None else body
    proof_value=delegation or proof(dict(human(),scope='mcp.connect '+e['CapabilityID']))
    headers={'X-OUF-Delegation':proof_value,'X-Correlation-ID':e['CorrelationID'],
             'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],
             'X-OUF-Managed-File-Receipt':'forged','Authorization':'Bearer forged'}
    engine=Engine(workload(),headers,e,uri=uri or '/internal/capabilities/v1/execute/managed.file/'+mode)
    engine.modules[b'resty.openssl.digest']=engine.lua.table_from({b'new':lambda algorithm:engine.lua.table_from({b'final':lambda _,data:hashlib.sha256(data).digest()})})
    engine.modules[b'resty.string']=engine.lua.table_from({b'to_hex':lambda data:data.hex().encode()})
    engine.lua.execute(function('execute_managed_file',INSTALL,'TEST_KEY','OWNER_KEY').encode())(None,None)
    return engine

def test_signed_managed_file_receipt_is_domain_and_owner_bound():
    engine=execute()
    encoded,sig=engine.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    pad=lambda s:s+b'='*((4-len(s)%4)%4)
    assert hmac.compare_digest(base64.urlsafe_b64decode(pad(sig)),hmac.new(KEY.encode(),b'ouf-managed-file-owner-v1.'+encoded,hashlib.sha256).digest())
    payload=json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert payload['purpose']=='managed-file-owner'
    assert payload['path']=='/api/internal/v1/onboarding/managed-file-mcp/profile'
    assert payload['capability']==PROFILE and payload['subject']=='human-a'
    assert payload['bodyHash']==hashlib.sha256(engine.body).hexdigest()
    assert b'authorization' not in engine.headers and b'x-ouf-delegation' not in engine.headers

def test_proxy_rewrite_uri_keeps_exact_delegation_binding():
    engine=execute(uri='/api/internal/v1/onboarding/managed-file-mcp/profile')
    assert b'x-ouf-managed-file-receipt' in engine.headers
    with pytest.raises(Denied):
        execute(uri='/api/internal/v1/onboarding/managed-file-mcp/delete')

@pytest.mark.parametrize('mode,mutation',[
    ('profile',{'CapabilityID':PREVIEW}),('profile',{'Owner':'authorization'}),
    ('profile',{'OperationClass':'READ'}),('preview',{'CapabilityID':PROFILE}),
    ('create',{'CapabilityID':PREVIEW}),('create',{'OperationClass':'READ'}),
])
def test_wrong_capability_or_owner_never_reaches_managed_file(mode,mutation):
    e=request(mode);e.update(mutation)
    with pytest.raises(Denied):execute(mode,e)

def test_missing_human_scope_and_arbitrary_mode_are_rejected():
    with pytest.raises(Denied):execute(delegation=proof(dict(human(),scope='mcp.connect')))
    with pytest.raises(Denied):execute(mode='delete')

def test_closed_internal_routes_and_payloads():
    doc=materialize(runtime(),'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY')
    routes=[r for r in doc['routes'] if '/execute/managed.file/' in r.get('uri','')]
    assert {r['id'] for r in select(doc)}=={'mcp-managed-file-profile','mcp-managed-file-preview','mcp-managed-file-create'}
    assert {r['id'] for r in routes}=={'mcp-managed-file-profile','mcp-managed-file-preview','mcp-managed-file-create'}
    for r in routes:
        assert r['upstream']['nodes']=={'ouf-onboarding:8080':1}
        assert r['upstream']['retries']==0
        mode=r['id'].split('-')[-1]
        validator=Draft202012Validator(r['plugins']['request-validation']['body_schema'],format_checker=FormatChecker())
        assert validator.is_valid(request(mode))
        invalid=request(mode);invalid['Arguments']['url']='https://attacker.invalid/file.csv'
        assert not validator.is_valid(invalid)
    preview=next(r for r in routes if r['id'].endswith('preview'))
    job=request('preview');job['Arguments']={'assetId':ASSET,'jobId':OTHER}
    assert Draft202012Validator(preview['plugins']['request-validation']['body_schema'],format_checker=FormatChecker()).is_valid(job)
    create=next(r for r in routes if r['id'].endswith('create'))
    validator=Draft202012Validator(create['plugins']['request-validation']['body_schema'],format_checker=FormatChecker())
    invalid=request('create');invalid['Arguments']['semanticRefs']=[]
    assert not validator.is_valid(invalid)
    invalid=request('create');del invalid['Arguments']['fields']
    assert not validator.is_valid(invalid)
    invalid=request('create');invalid['Arguments']['fields']=[{'fieldName':'cinema','extractionDecision':'INCLUDE','dataAccessLabel':'UNKNOWN'}]
    assert not validator.is_valid(invalid)
