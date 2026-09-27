"""Bind delegated HUMAN profile and redacted preview to the Onboarding owner."""
import argparse
import copy
import json
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_permission_proposals import materialize as permission_runtime

ROOT=Path(__file__).resolve().parents[1]
MODES={
    'profile':('ouf.managed-source.file.profile','COMMAND'),
    'preview':('ouf.managed-source.preview','READ'),
    'create':('ouf.managed-source.onboarding.create','COMMAND'),
}

def materialize(runtime,oidc_secret_ref,delegation_key_env,owner_key_env):
    result=permission_runtime(runtime,oidc_secret_ref,delegation_key_env,owner_key_env)
    template=next(r for r in result['routes'] if r['uri']=='/internal/capabilities/v1/execute')
    schemas=json.loads((ROOT/'schemas/mcp-gateway-managed-file-dispatch-v1.json').read_text())['oneOf']
    for mode,(cap,operation) in MODES.items():
        route_id='mcp-managed-file-'+mode
        candidates=[r for r in runtime['routes'] if r.get('id')==route_id]
        if len(candidates)!=1:raise ValueError('exact managed-file binding required: '+mode)
        binding=candidates[0];p=binding['x-ouf-policy'];c=binding['x-ouf-capability']
        path='/api/internal/v1/onboarding/managed-file-mcp/'+mode
        if (binding['service_id']!='ouf-onboarding' or binding['x-ouf-backend-binding']['service']!='ouf-onboarding'
            or binding['x-ouf-backend-binding']['port']!=8080
            or binding['plugins']['proxy-rewrite']['uri']!=path or binding['methods']!=['POST']
            or c['capabilityId']!=cap or c['owner']!='onboarding' or c['operationType']!=operation
            or c.get('humanRequired') or not c.get('toolEligible') or p['identity']!='M2M'
            or p['requiredScope']!=cap or p['allowedActorTypes']!=['HUMAN']
            or runtime['x-ouf-installation']['mcpServiceIdentity'] not in p['allowedServiceIdentities']
            or p['maxRequestBytes']!=65536 or p['timeoutSeconds']!=3):
            raise ValueError('managed-file binding mismatch: '+mode)
        route=copy.deepcopy(template)
        route['id']=route_id
        route['uri']='/internal/capabilities/v1/execute/managed.file/'+mode
        route['labels']['ouf-mediation']='managed-file-delegation-v1'
        route['labels']['ouf-managed']='true'
        route['labels']['ouf-exposure']='internal'
        matching=[s for s in schemas if s['properties']['CapabilityID']['const']==cap]
        route['plugins']['request-validation']['body_schema']=matching[0] if len(matching)==1 else {'oneOf':matching}
        route['plugins']['request-id']={'header_name':'X-Correlation-ID','include_in_response':True,'algorithm':'uuid'}
        route['plugins']['serverless-post-function']['functions']=[function('execute_managed_file',runtime['x-ouf-installation'],delegation_key_env,owner_key_env)]
        route['plugins']['proxy-rewrite']['uri']=path
        route['upstream']['nodes']={'ouf-onboarding:8080':1}
        result['routes'].append(route)
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--oidc-client-secret-ref',required=True)
    p.add_argument('--delegation-key-env',required=True)
    p.add_argument('--owner-key-env',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text()),a.oidc_client_secret_ref,a.delegation_key_env,a.owner_key_env),indent=2)+'\n')
