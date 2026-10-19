import copy,hashlib,json
import pytest
from jsonschema import Draft7Validator,FormatChecker
from tools.materialize_ingestion_read import CAPABILITIES,SCOPE,dispatch_schema,materialize
from tools.delegation_functions import function
from tools.materialize_apisix_execute_runtime import materialize as base_materialize
from tests.test_execute_delegation import Engine,Denied,INSTALL,envelope,human,workload,proof,runtime

def existing():return base_materialize(runtime(),'$ENV://OIDC','DELEGATION_KEY')
def body(cap,args=None):
 value=envelope();value.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='ingestion',Arguments=args or{'sourceId':'source-a','limit':10},MaxResultBytes=524288)
 value['RequestHash']=hashlib.sha256(json.dumps(value['Arguments'],sort_keys=True,separators=(',',':')).encode()).hexdigest();return value

def invoke(cap,mode=None):
 ctx=human();ctx['scope']+=' '+SCOPE;claims=workload();value=body(cap);kw={}
 if mode in('principal','tenant','actor','acr','client'):
  key={'principal':'PrincipalID','tenant':'TenantID','actor':'ActorType','acr':'AuthenticationContextRef','client':'ServicePrincipalID'}[mode];value['Identity'][key]='forged'
 if mode=='scope':ctx['scope']='mcp.connect operations.status.read'
 if mode=='workload':claims['azp']='other'
 if mode=='issuer':claims['iss']='https://other.invalid'
 if mode=='audience':claims['aud']='other'
 if mode=='workload-expired':claims['exp']=999
 if mode=='owner':value['Owner']='udp'
 if mode=='binding':value['GatewayBindingRef']='capability://ouf.ingestion.run'
 if mode=='operation':value['OperationClass']='COMMAND'
 if mode=='capability':value['CapabilityID']='ouf.ingestion.run'
 if mode=='expired':kw['now']=1061
 if mode=='key':kw['key']=None
 delegated=proof(ctx)
 if mode=='signature':delegated=delegated[:-2]+'zz'
 headers={'X-OUF-Delegation':delegated,'X-Correlation-ID':value['CorrelationID'],'Idempotency-Key':value['IdempotencyKey'],'X-Tool-Attempt-ID':value['AttemptID'],'Cookie':'secret','X-OUF-External-Role-Refs':'forged'}
 if mode=='correlation':headers['X-Correlation-ID']='other'
 e=Engine(claims,headers,value,**kw)
 e.lua.execute(function('execute_ingestion_read',INSTALL,'TEST_KEY',operational_binding={'capability':cap,'owner':'ingestion','scope':SCOPE}).encode())(None,None)
 return e

@pytest.mark.parametrize('cap',CAPABILITIES)
def test_real_lua_preserves_source_arguments_and_verified_human_owner_context(cap):
 e=invoke(cap);assert json.loads(e.body)=={'sourceId':'source-a','limit':10}
 assert e.headers[b'x-ouf-capability-id'].decode()==cap
 assert e.headers[b'x-ouf-principal-id']==b'human-a' and e.headers[b'x-ouf-service-principal']==b'workload'
 assert e.headers[b'x-ouf-granted-scopes'].decode().endswith(SCOPE)
 assert all(k not in e.headers for k in (b'authorization',b'cookie',b'x-ouf-delegation',b'x-ouf-delegation-verified',b'x-ouf-external-role-refs'))

@pytest.mark.parametrize('cap',CAPABILITIES)
@pytest.mark.parametrize('mode',['principal','tenant','actor','acr','client','scope','workload','issuer','audience','workload-expired','owner','binding','operation','capability','expired','key','signature','correlation'])
def test_real_lua_denies_forgery_expiry_scope_or_identity_changes(cap,mode):
 with pytest.raises(Denied):invoke(cap,mode)

@pytest.mark.parametrize('cap',CAPABILITIES)
def test_closed_schema_bounds_source_query_and_rejects_mutation_or_url(cap):
 v=Draft7Validator(dispatch_schema(cap),format_checker=FormatChecker())
 assert v.is_valid(body(cap));assert v.is_valid(body(cap,{'since':'2026-10-19T10:00:00Z'}))
 for args in ({'url':'https://attacker'},{'sourceId':''},{'limit':True},{'limit':101},{'limit':0},{'cursor':'arbitrary'},{'since':'2026-10-19T10:00:00'},{'activate':True}):
  assert not v.is_valid(body(cap,args))
 value=body(cap);value['OperationClass']='COMMAND';assert not v.is_valid(value)
 value=body(cap);value['Identity']['ActorType']='SERVICE';assert not v.is_valid(value)


def test_adds_only_two_declared_routes_and_preserves_every_existing_byte():
 before=existing();rt=runtime();result=materialize(before,rt,'DELEGATION_KEY')
 assert result['routes'][:-2]==before['routes'];assert len(result['routes'])==len(before['routes'])+2
 for row in result['routes'][-2:]:
  cap=row['plugins']['request-validation']['body_schema']['properties']['CapabilityID']['const'];mode=CAPABILITIES[cap]
  assert row['uri']=='/internal/capabilities/v1/execute/'+cap and row['methods']==['POST']
  assert row['upstream']['retries']==0 and row['plugins']['proxy-rewrite']['uri']=='/api/internal/v1/ingestion/operations/'+mode
  assert row['plugins']['openid-connect']==next(x for x in before['routes']if x['uri'].endswith('/execute'))['plugins']['openid-connect']
 assert 'ab'*32 not in json.dumps(result)

@pytest.mark.parametrize('change',['scope','actor','workload','operation','tool','human','backend','timeout','path','duplicate','missing','ssl','jwks','generic-method','collision'])
def test_binding_or_auth_template_drift_fails_closed(change):
 rt=runtime();before=existing();target=next(x for x in rt['routes']if x['id']=='mcp-ingestion-status');template=next(x for x in before['routes']if x['uri'].endswith('/execute'))
 if change=='scope':target['x-ouf-policy']['requiredScope']='operations.status.read'
 elif change=='actor':target['x-ouf-policy']['allowedActorTypes']=['SERVICE']
 elif change=='workload':target['x-ouf-policy']['allowedServiceIdentities']=['other']
 elif change=='operation':target['x-ouf-capability']['operationType']='COMMAND'
 elif change=='tool':target['x-ouf-capability']['toolEligible']=False
 elif change=='human':target['x-ouf-capability']['humanRequired']=True
 elif change=='backend':target['x-ouf-backend-binding']['service']='evil'
 elif change=='timeout':target['x-ouf-policy']['timeoutSeconds']=100
 elif change=='path':target['uri']='/evil'
 elif change=='duplicate':rt['routes'].append(copy.deepcopy(target))
 elif change=='missing':rt['routes'].remove(target)
 elif change=='ssl':template['plugins']['openid-connect']['ssl_verify']=False
 elif change=='jwks':template['plugins']['openid-connect']['use_jwks']=False
 elif change=='generic-method':template['methods']=['GET']
 elif change=='collision':before['routes'].append({'id':'collision','uris':['/internal/capabilities/v1/execute/ouf.ingestion.status']})
 with pytest.raises(ValueError):materialize(before,rt,'DELEGATION_KEY')

def test_distributed_service_binding_uses_projected_backend_and_port():
 rt=runtime();rt['x-ouf-installation']['serviceBindings']={'ouf-ingestion-runtime':'ingestion.remote.internal'}
 for row in rt['routes']:
  if row['id']in('mcp-ingestion-status','mcp-ingestion-history'):
   row['x-ouf-backend-binding'].update(service='ingestion.remote.internal',port=8443)
 result=materialize(existing(),rt,'DELEGATION_KEY')
 assert all(row['upstream']['nodes']=={'ingestion.remote.internal:8443':1}for row in result['routes'][-2:])

def test_renderer_cannot_select_a_write_other_owner_scope_or_arbitrary_capability():
 for binding in ({},{'capability':'ouf.ingestion.run','owner':'ingestion','scope':SCOPE},{'capability':'ouf.ingestion.status','owner':'udp','scope':SCOPE},{'capability':'ouf.ingestion.status','owner':'ingestion','scope':'operations.status.read'}):
  with pytest.raises(ValueError):function('execute_ingestion_read',INSTALL,'TEST_KEY',operational_binding=binding)

def test_retained_compiled_subset_is_exact_output_of_production_compiler():
 from pathlib import Path
 from tools.compile_config import compile_config
 root=Path(__file__).resolve().parents[1]
 expected=json.loads((root/'catalogue/ingestion-read-compiled-bindings.json').read_text())
 actual=compile_config(root/'ouf-config')
 selected=[row for row in actual['routes']if row['id']in('mcp-ingestion-history','mcp-ingestion-status')]
 assert expected=={'routes':selected}
