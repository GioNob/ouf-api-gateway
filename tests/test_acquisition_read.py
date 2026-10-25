import base64
import copy
import hashlib
import hmac
import json

import pytest
from jsonschema import Draft7Validator,FormatChecker
from tests.test_execute_delegation import Engine,Denied,INSTALL,envelope,human,workload,proof,runtime
from tools.delegation_functions import function
from tools.materialize_acquisition_read import CAPABILITIES,dispatch_schema,materialize
from tools.materialize_apisix_execute_runtime import materialize as base_materialize

RUN='11111111-1111-4111-8111-111111111111'

def body(cap,args=None):
    e=envelope();e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner=CAPABILITIES[cap][0],Arguments=args if args is not None else{'sourceId':'source-a','runId':RUN,'limit':10},MaxResultBytes=1048576)
    return e

def invoke(cap,mode=None):
    spec=CAPABILITIES[cap];p=human();p['scope']='mcp.connect '+' '.join(sorted(spec[3]));claims=workload();e=body(cap)
    if mode in spec[3]:p['scope']='mcp.connect '+' '.join(s for s in spec[3]if s!=mode)
    if mode=='operational-authority-only':p['scope']='mcp.connect ingestion.operations.read urban.object.search'
    if mode=='workload':claims['azp']='other'
    if mode=='tenant':p['tenant_id']='other'
    if mode=='principal':e['Identity']['PrincipalID']='other'
    if mode=='operation':e['OperationClass']='COMMAND'
    if mode=='capability':e['CapabilityID']='authorization.policy.publish'
    if mode=='owner':e['Owner']='wrong'
    if mode=='binding':e['GatewayBindingRef']='capability://wrong'
    if mode=='extra':e['Arguments']['url']='https://attacker.invalid'
    if mode=='run':e['Arguments']['runId']='00000000-0000-0000-0000-000000000000'
    if mode=='limit':e['Arguments']['limit']=101
    if mode=='source':e['Arguments']['sourceId']=''
    if mode=='wrong-cursor':e['Arguments']['afterHandoffId'if spec[0]=='ingestion'else'afterLineageId']=RUN
    delegated=proof(p);headers={'X-OUF-Delegation':delegated,'X-Correlation-ID':e['CorrelationID'],'X-Tool-Attempt-ID':e['AttemptID'],'Idempotency-Key':e['IdempotencyKey'],'X-OUF-UDP-Acquisition-Receipt':'forged','X-Principal-Type':'forged','Cookie':'private-cookie'}
    if mode=='correlation':headers['X-Correlation-ID']='wrong'
    engine=Engine(claims,headers,e,now=1061 if mode=='expired' else 1000)
    key=('cd'if spec[0]=='ingestion'else'ef')*32
    engine.lua.globals()[b'OWNER_TEST_KEY']=key.encode()
    engine.lua.execute(b'os.getenv=function(name) if name == "OWNER_KEY" then return OWNER_TEST_KEY end return TEST_KEY end')
    engine.lua.execute(function('execute_acquisition_read',INSTALL,'TEST_KEY',owner_key_env='OWNER_KEY',operational_binding={'capability':cap,'owner':spec[0],'scope':spec[4]}).encode())(None,None)
    return engine

@pytest.mark.parametrize('cap',CAPABILITIES)
def test_actual_lua_receipt_binds_minimized_owner_body_without_forwarded_authority(cap):
    engine=invoke(cap);ingestion=CAPABILITIES[cap][0]=='ingestion'
    header=b'x-ouf-ingestion-read-receipt'if ingestion else b'x-ouf-udp-acquisition-receipt'
    encoded,signature=engine.headers[header].split(b'.');pad=lambda b:b+b'='*(-len(b)%4)
    domain=b'ouf-ingestion-read-owner-v1.'if ingestion else b'ouf-udp-acquisition-owner-v1.'
    key=(('cd'if ingestion else'ef')*32).encode()
    assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),hmac.new(key,domain+encoded,hashlib.sha256).digest())
    receipt=json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert receipt['path']==CAPABILITIES[cap][2]and receipt['capability']==cap and receipt['bodyHash']==hashlib.sha256(engine.body).hexdigest()
    assert receipt['tenant']=='tenant-a'and receipt['subject']=='human-a'and receipt['exp']-receipt['iat']==30
    assert json.loads(engine.body)==body(cap)['Arguments']
    for forbidden in (b'authorization',b'cookie',b'x-ouf-delegation',b'x-principal-type'):assert forbidden not in engine.headers
    assert all(scope in receipt['scope'].split()for scope in CAPABILITIES[cap][3])

@pytest.mark.parametrize('cap',CAPABILITIES)
@pytest.mark.parametrize('mode',['operational-authority-only','workload','tenant','principal','operation','capability','owner','binding','extra','run','limit','source','wrong-cursor','expired','correlation'])
def test_unrelated_scope_mutation_drift_or_input_cannot_be_signed(cap,mode):
    with pytest.raises(Denied):invoke(cap,mode)

@pytest.mark.parametrize('cap',CAPABILITIES)
def test_every_read_permission_is_required_and_dispatch_schema_is_closed(cap):
    for scope in CAPABILITIES[cap][3]:
        with pytest.raises(Denied):invoke(cap,scope)
    validator=Draft7Validator(dispatch_schema(cap),format_checker=FormatChecker())
    assert validator.is_valid(body(cap))
    for args in ({'sourceId':'source-a'},{'sourceId':'source-a','runId':RUN,'sql':'select 1'},{'sourceId':'source-a','runId':RUN,'limit':True},{'sourceId':'source-a','runId':RUN,'limit':0},{'sourceId':'source-a','runId':RUN,'limit':101}):assert not validator.is_valid(body(cap,args))

def test_additive_compiler_preserves_retained_routes_and_rejects_auth_backend_drift():
    rt=runtime();before=base_materialize(rt,'$ENV://OIDC','DELEGATION_KEY');result=materialize(before,rt,'DELEGATION_KEY','INGESTION_KEY','UDP_KEY')
    assert result['routes'][:-2]==before['routes']and len(result['routes'])==len(before['routes'])+2
    for route in result['routes'][-2:]:assert route['upstream']['retries']==0 and route['upstream']['timeout']['read']==12
    for change in ['backend','scope','timeout','ssl','duplicate','collision']:
        changed=copy.deepcopy(rt);retained=copy.deepcopy(before)
        b=next(r for r in changed['routes']if r.get('uri')=='/internal/capabilities/v1/execute/ouf.ingestion.acquisition.read')
        if change=='backend':b['x-ouf-backend-binding']['service']='attacker.invalid'
        if change=='scope':b['x-ouf-policy']['requiredScope']='operations.status.read'
        if change=='timeout':b['x-ouf-policy']['timeoutSeconds']=300
        if change=='ssl':next(r for r in retained['routes']if r['uri'].endswith('/execute'))['plugins']['openid-connect']['ssl_verify']=False
        if change=='duplicate':changed['routes'].append(copy.deepcopy(b))
        if change=='collision':retained['routes'].append({'id':'existing','uris':[b['uri']]})
        with pytest.raises(ValueError):materialize(retained,changed,'DELEGATION_KEY','INGESTION_KEY','UDP_KEY')

def export_vectors(path):
    vectors=[]
    for cap,spec in CAPABILITIES.items():
        engine=invoke(cap);header=b'x-ouf-ingestion-read-receipt'if spec[0]=='ingestion'else b'x-ouf-udp-acquisition-receipt'
        vectors.append({'capability':cap,'body':engine.body.decode(),'receipt':engine.headers[header].decode(),'path':spec[2]})
    from pathlib import Path
    Path(path).write_text(json.dumps({'vectors':vectors}))

if __name__=='__main__':
    import sys
    export_vectors(sys.argv[1])
