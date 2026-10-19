"""Two additive Ingestion READ routes from approved, projected capability bindings."""
import copy,json,re
from pathlib import Path
from tools.delegation_functions import function
ROOT=Path(__file__).resolve().parents[1]
CAPABILITIES={'ouf.ingestion.status':'status','ouf.ingestion.history':'history'}
SCOPE='ingestion.operations.read'
def dispatch_schema(capability):
 if capability not in CAPABILITIES:raise ValueError('closed ingestion READ capability required')
 schema=json.loads((ROOT/'schemas/mcp-gateway-status-dispatch-v1.json').read_text())
 fields=schema['properties'];fields['CapabilityID']={'const':capability}
 fields['GatewayBindingRef']={'const':'capability://'+capability};fields['Owner']={'const':'ingestion'}
 fields['MaxResultBytes']['maximum']=524288
 fields['Arguments']={'type':'object','additionalProperties':False,'properties':{
  'sourceId':{'type':'string','minLength':1,'maxLength':200},
  'limit':{'type':'integer','minimum':1,'maximum':100},
  'since':{'type':'string','format':'date-time','maxLength':100,'pattern':r'^.+T.+(Z|[+-][0-9]{2}:[0-9]{2})$'}}}
 return schema

def materialize(existing,runtime,delegation_key_env,owner_key_env=None):
 if (not isinstance(owner_key_env,str)or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}",owner_key_env)or owner_key_env==delegation_key_env):
  raise ValueError("distinct ingestion owner receipt key environment required")
 result=copy.deepcopy(existing);installation=runtime['x-ouf-installation']
 templates=[r for r in result['routes']if r.get('uri')=='/internal/capabilities/v1/execute']
 if len(templates)!=1:raise ValueError('one retained execute template required')
 template=templates[0];plugins=template.get('plugins',{});oidc=plugins.get('openid-connect',{})
 if(template.get('methods')!=['POST']or any(k not in plugins for k in('openid-connect','limit-count','request-validation','serverless-pre-function','serverless-post-function'))
  or oidc.get('bearer_only')is not True or oidc.get('ssl_verify')is not True or oidc.get('use_jwks')is not True
  or oidc.get('unauth_action')!='deny' or 'required_scopes'in oidc):
  raise ValueError('retained authenticated execute template required')
 for capability,mode in CAPABILITIES.items():
  uri='/internal/capabilities/v1/execute/'+capability;path='/api/internal/v1/ingestion/operations/'+mode;rid='mcp-ingestion-'+mode
  bindings=[r for r in runtime['routes']if r.get('id')==rid]
  if len(bindings)!=1:raise ValueError('one compiled ingestion READ binding required')
  binding=bindings[0];cap=binding['x-ouf-capability'];policy=binding['x-ouf-policy'];backend=binding['x-ouf-backend-binding']
  # Backend service/port are projected installation inputs, never caller URLs.
  service=backend.get('service');port=backend.get('port')
  logical=installation.get('serviceBindings',{}).get('ouf-ingestion-runtime','ouf-ingestion-runtime')
  if(binding.get('uri')!=uri or binding.get('methods')!=['POST']or cap.get('capabilityId')!=capability
   or cap.get('owner')!='ingestion' or cap.get('operationType')!='READ' or cap.get('humanRequired')is not False
   or cap.get('toolEligible')is not True or policy.get('identity')!='M2M' or policy.get('requiredScope')!=SCOPE
   or policy.get('allowedServiceIdentities')!=[installation['mcpServiceIdentity']]
   or policy.get('allowedActorTypes')!=['HUMAN_USER','MCP_SERVER']or policy.get('maxRequestBytes')!=65536 or policy.get('timeoutSeconds')!=3
   or type(service)is not str or service!=logical or not re.fullmatch('[A-Za-z0-9._-]{1,253}',service)
   or type(port)is not int or not 1<=port<=65535 or backend.get('path')!=path
   or binding.get('plugins',{}).get('proxy-rewrite',{}).get('uri')!=path):
   raise ValueError('compiled ingestion READ binding drift')
  for old in result['routes']:
   paths=[old.get('uri')]+list(old.get('uris')or[])
   if old.get('id')==rid or uri in paths:
    raise ValueError('ingestion READ route already selected; reconcile')
  route=copy.deepcopy(template);route.update(id=rid,uri=uri,methods=['POST'],status=1,priority=0)
  route.setdefault('labels',{})['ouf-mediation']='ingestion-read-owner-receipt-v1'
  route['plugins']['request-validation']={'max_req_body_size':65536,'body_schema':dispatch_schema(capability)}
  route['plugins']['serverless-post-function']={'phase':'access','functions':[function('execute_ingestion_read',installation,delegation_key_env,owner_key_env=owner_key_env,
   operational_binding={'capability':capability,'owner':'ingestion','scope':SCOPE})]}
  route['plugins']['proxy-rewrite']={'uri':path}
  route['upstream']={'type':'roundrobin','scheme':'http','nodes':{f'{service}:{port}':1},'retries':0,
   'timeout':{'connect':3,'send':3,'read':3}}
  result['routes'].append(route)
 return result

