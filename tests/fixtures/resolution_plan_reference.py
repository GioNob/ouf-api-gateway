"""Offline copy of ouf-deploy resolution_ths_update/plan.py (route definitions only)."""
import copy


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


PAGE='/trusted-human/resolution/*'
PACKAGE='/api/udp/v1/governance/resolution/issues/package'
ROUTES=('ths-resolution-package-read','ths-resolution-package-confirm','trusted-human-resolution-review')

def compile_routes(before):
 require(type(before)is dict and 0<len(before)<=256 and not set(ROUTES)&set(before),'RESOLUTION_ROUTES_ALREADY_EXIST_RECONCILE')
 templates=('trusted-human-onboarding-review','ths-identity-preflight-read','ths-identity-preflight-create')
 require(all(k in before for k in templates),'EXISTING_APPROVED_OWNER_ROUTE_TEMPLATES_REQUIRED')
 page=copy.deepcopy(before[templates[0]]);read=copy.deepcopy(before[templates[1]]);confirm=copy.deepcopy(before[templates[2]])
 require(page.get('uri')=='/trusted-human/onboarding/*'and page.get('methods')==['GET','POST']and 'openid-connect'not in page['plugins']and page['plugins'].get('serverless-pre-function'),'EXISTING_AUTHENTICATED_BROWSER_SESSION_BOUNDARY_REQUIRED')
 for row,method in((read,'GET'),(confirm,'POST')):
  require(row.get('uri')=='/api/udp/v1/governance/identity/preflight'and row.get('methods')==[method]
   and row['plugins']['openid-connect'].get('bearer_only')is True
   and row['plugins']['openid-connect'].get('ssl_verify')is True
   and row['plugins']['openid-connect'].get('required_scopes')==['urban.identity.preflight']
   and row['plugins'].get('serverless-pre-function')and row['plugins'].get('serverless-post-function')
   and row['upstream'].get('retries')==0,'EXACT_EXISTING_UDP_HUMAN_OIDC_BOUNDARY_REQUIRED')
 for row,rid,path,cap in((read,ROUTES[0],PACKAGE,'resolution.issue.read'),(confirm,ROUTES[1],PACKAGE+'/confirm','resolution.match.approve')):
  row.update(id=rid,uri=path);row.pop('uris',None)
  row.setdefault('labels',{}).update({'ouf-capability':cap,'ouf-surface':'TRUSTED_HUMAN_RESOLUTION'})
  row['plugins']['openid-connect']['required_scopes']=[cap]
  require(set(row['plugins'].get('proxy-rewrite',{}))<= {'uri'},'UNREVIEWED_UDP_REWRITE_CHANNEL')
  if 'proxy-rewrite'in row['plugins']:row['plugins']['proxy-rewrite']['uri']=path
  require('vars'not in row and 'filter_func'not in row,'UNREVIEWED_TEMPLATE_PATH_CONDITION')
  if row.get('methods')==['POST']:row['plugins'].setdefault('request-validation',{})['body_schema']=copy.deepcopy(CONFIRM_SCHEMA)
  row['plugins']['client-control']={'max_body_size':1048576}
  row['upstream']['timeout']={'connect':3,'send':3,'read':20}
 page.update(id=ROUTES[2],uri=PAGE);page.pop('uris',None)
 require('proxy-rewrite'not in page['plugins']and 'vars'not in page,'BROWSER_PATH_PRESERVATION_REQUIRED')
 page.setdefault('labels',{}).update({'ouf-capability':'resolution.issue.read','ouf-surface':'TRUSTED_HUMAN_RESOLUTION'})
 page['plugins']['client-control']={'max_body_size':1048576};page['upstream']['timeout']={'connect':3,'send':3,'read':30}
 for row in(read,confirm,page):
  for existing in before.values():
   paths=[existing['uri']]if'uri'in existing else existing.get('uris',[])
   require(row['uri']not in paths,'RESOLUTION_PATH_ALREADY_BOUND_RECONCILE')
 return {row['id']:row for row in(read,confirm,page)}


UUID_PATTERN='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
CONFIRM_SCHEMA={'type':'object','additionalProperties':False,'required':['snapshotHash','choices'],
 'properties':{'snapshotHash':{'type':'string','pattern':'^sha256:[0-9a-f]{64}$'},'choices':{'type':'array','items':{
  'type':'object','additionalProperties':False,'required':['issueId','expectedVersion','action'],'properties':{
   'issueId':{'type':'string','pattern':UUID_PATTERN},'expectedVersion':{'type':'integer','minimum':0},
   'action':{'type':'string','enum':['APPROVE','CREATE_NEW','DISMISS']},
   'reason':{'type':['string','null'],'maxLength':1000},
   'targetUrbanObjectId':{'type':['string','null'],'pattern':UUID_PATTERN},
   'expectedReviewHash':{'type':['string','null'],'pattern':'^sha256:[0-9a-f]{64}$'}}}}}}
