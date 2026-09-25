import base64
import hashlib
import hmac
import json
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Engine, Denied, human, workload, envelope, proof, runtime, INSTALL, KEY
from tools.delegation_functions import function
from tools.materialize_managed_file_mcp import materialize

PROFILE='ouf.managed-source.file.profile'
PREVIEW='ouf.managed-source.preview'
ASSET='00000000-0000-4000-8000-000000000001'
OTHER='00000000-0000-4000-8000-000000000002'

def request(mode='profile'):
    cap=PROFILE if mode=='profile' else PREVIEW
    args={'assetId':ASSET}
    if mode=='preview':args['profileId']=OTHER
    e=envelope()
    e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='onboarding',
             OperationClass='COMMAND' if mode=='profile' else 'READ',Arguments=args)
    return e

def execute(mode='profile',body=None,delegation=None):
    e=request(mode) if body is None else body
    proof_value=delegation or proof(dict(human(),scope='mcp.connect '+e['CapabilityID']))
    headers={'X-OUF-Delegation':proof_value,'X-Correlation-ID':e['CorrelationID'],
             'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],
             'X-OUF-Managed-File-Receipt':'forged','Authorization':'Bearer forged'}
    engine=Engine(workload(),headers,e,uri='/internal/capabilities/v1/execute/managed.file/'+mode)
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

@pytest.mark.parametrize('mode,mutation',[
    ('profile',{'CapabilityID':PREVIEW}),('profile',{'Owner':'authorization'}),
    ('profile',{'OperationClass':'READ'}),('preview',{'CapabilityID':PROFILE}),
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
    assert {r['id'] for r in routes}=={'mcp-managed-file-profile','mcp-managed-file-preview'}
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
