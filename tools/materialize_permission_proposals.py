"""Add closed permission read/proposal/status mediation; no confirm or admin proxy."""
import argparse
import copy
import json
from pathlib import Path
from tools.materialize_apisix_execute_runtime import materialize as status_runtime
from tools.delegation_functions import function
ROOT=Path(__file__).resolve().parents[1]
CAPS={'authorization.permissions.read':('read','READ'),'authorization.permissions.propose':('propose','COMMAND'),'authorization.proposal.read':('status','READ')}
def materialize(runtime,oidc_secret_ref,delegation_key_env,owner_key_env):
    result=status_runtime(runtime,oidc_secret_ref,delegation_key_env)
    template=next(r for r in result['routes'] if r['uri']=='/internal/capabilities/v1/execute')
    schemas=json.loads((ROOT/'schemas/mcp-gateway-permissions-dispatch-v1.json').read_text())['oneOf']
    for cap,(mode,operation) in CAPS.items():
        candidates=[r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId')==cap and r.get('labels',{}).get('exposure')=='internal']
        if len(candidates)!=1:raise ValueError('exact permission binding required: '+cap)
        binding=candidates[0];p=binding['x-ouf-policy'];c=binding['x-ouf-capability']
        path='/api/internal/v1/authorization/permissions/'+mode
        if binding['service_id']!='ouf-onboarding' or binding['plugins']['proxy-rewrite']['uri']!=path or c['owner']!='authorization' or c['operationType']!=operation or c.get('humanRequired') or not c.get('toolEligible') or p['identity']!='M2M' or p['requiredScope']!=cap or p['allowedActorTypes']!=['HUMAN'] or runtime['x-ouf-installation']['mcpServiceIdentity'] not in p['allowedServiceIdentities'] or p['maxRequestBytes']!=65536 or p['timeoutSeconds']!=3:
            raise ValueError('permission binding mismatch: '+cap)
        route=copy.deepcopy(template);route['id']='mcp-permissions-'+mode;route['uri']='/internal/capabilities/v1/execute/authorization/'+mode
        route['labels']['ouf-mediation']='permission-proposals-v1'
        route['plugins']['request-validation']['body_schema']=next(s for s in schemas if s['properties']['CapabilityID']['const']==cap)
        route['plugins']['serverless-post-function']['functions']=[function('execute_permissions',runtime['x-ouf-installation'],delegation_key_env,owner_key_env)]
        route['plugins']['proxy-rewrite']['uri']=path
        route['upstream']['nodes']={'ouf-onboarding:8080':1}
        result['routes'].append(route)
    # Human surface uses the owner's OIDC session and CSRF, never MCP receipts.
    for suffix,uris,methods in [('page',['/trusted-human/authorization/','/trusted-human/authorization/permissions.js','/trusted-human/authorization/permissions.css'],['GET']),('api',['/trusted-human/authorization/api/proposals/*'],['GET','POST']),('login',['/oauth2/authorization/ouf-ths','/login/oauth2/code/ouf-ths'],['GET'])]:
        result['routes'].append({'id':'authorization-ths-'+suffix,'uris':uris,'methods':methods,'plugins':{'client-control':{'max_body_size':65536},'serverless-pre-function':{'phase':'rewrite','functions':["return function() local h=ngx.req.get_headers(0); for k,_ in pairs(h) do if k:lower():sub(1,6)=='x-ouf-' or k:lower()=='authorization' then ngx.req.clear_header(k) end end end"]}},'upstream':{'type':'roundrobin','nodes':{'ouf-onboarding:8080':1},'retries':0,'timeout':{'connect':3,'send':3,'read':10}}})
    result['authorizationOwnerKeyEnv']=owner_key_env
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,required=True);p.add_argument('--oidc-client-secret-ref',required=True);p.add_argument('--delegation-key-env',required=True);p.add_argument('--owner-key-env',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text()),a.oidc_client_secret_ref,a.delegation_key_env,a.owner_key_env),indent=2)+'\n')
