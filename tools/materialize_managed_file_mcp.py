"""Bind delegated HUMAN profile and redacted preview to the Onboarding owner."""
import argparse
import copy
import json
from pathlib import Path

from tools.apisix_request_schema import dispatch_validation
from tools.delegation_functions import function
from tools.mcp_dispatch_contract import PICKER_CAPABILITY, PICKER_ISSUE
from tools.materialize_permission_proposals import materialize as permission_runtime

ROOT=Path(__file__).resolve().parents[1]
MODES={
    'profile':('ouf.managed-source.file.profile','COMMAND'),
    'preview':('ouf.managed-source.preview','READ'),
    'create':('ouf.managed-source.onboarding.create','COMMAND'),
    'handoff':(PICKER_CAPABILITY,'COMMAND'),
    'handoff-issue':(PICKER_ISSUE,'COMMAND'),
}

def materialize(runtime,oidc_secret_ref,delegation_key_env,owner_key_env, *, use_route_labels=False):
    result=permission_runtime(runtime,oidc_secret_ref,delegation_key_env,owner_key_env)
    template=next(r for r in result['routes'] if r['uri']=='/internal/capabilities/v1/execute')
    schemas=json.loads((ROOT/'schemas/mcp-gateway-managed-file-dispatch-v1.json').read_text())['oneOf']
    for mode,(cap,operation) in MODES.items():
        route_id='mcp-managed-file-'+mode
        request_limit = 3145728 if mode == 'create' else 65536
        timeout = 10 if mode in ('create', 'preview') else 3
        candidates=[r for r in runtime['routes'] if r.get('id')==route_id]
        if len(candidates)!=1:raise ValueError('exact managed-file binding required: '+mode)
        binding=candidates[0];p=binding['x-ouf-policy'];c=binding['x-ouf-capability']
        path='/api/internal/v1/onboarding/managed-file-mcp/'+mode
        if (binding.get('uri')!='/internal/capabilities/v1/execute/managed.file/'+mode
            or binding['labels'].get('exposure') != 'internal' or binding.get('vars')
            or binding['service_id']!='ouf-onboarding' or binding['x-ouf-backend-binding']['service']!='ouf-onboarding'
            or binding['x-ouf-backend-binding']['port']!=8080
            or binding['plugins']['proxy-rewrite']['uri']!=path or binding['methods']!=['POST']
            or c['capabilityId']!=cap or c['owner']!='onboarding' or c['operationType']!=operation
            or c.get('humanRequired') or c.get('toolEligible') != (mode != 'handoff-issue') or p['identity']!='M2M'
            or p['requiredScope'] != (PICKER_CAPABILITY if mode == 'handoff-issue' else cap) or p['allowedActorTypes']!=['HUMAN']
            or p['allowedServiceIdentities'] != [runtime['x-ouf-installation']['mcpServiceIdentity']]
            or p['maxRequestBytes']!=request_limit
            or p['timeoutSeconds']!=timeout):
            raise ValueError('managed-file binding mismatch: '+mode)
        route=copy.deepcopy(template)
        route['id']=route_id
        route['uri']='/internal/capabilities/v1/execute/managed.file/'+mode
        if mode == 'handoff':
            # Preserve the explicit APISIX routing priority and enabled state on adoption.
            route.update(priority=0, status=1)
        route['labels']['ouf-mediation']='managed-file-delegation-v1'
        route['labels']['ouf-managed']='true'
        route['labels']['ouf-exposure']='internal'
        if mode in ('handoff', 'handoff-issue'):
            route['plugins']['request-validation'] = binding['plugins']['request-validation']
        else:
            schema, = (s for s in schemas if s['properties']['CapabilityID']['const'] == cap)
            route['plugins']['request-validation'] = dispatch_validation(schema, request_limit)
        route['plugins']['request-id']={'header_name':'X-Correlation-ID','include_in_response':True,'algorithm':'uuid'}
        # Retain the installed reader and receipt checks during adoption.
        source = 'execute_managed_file_retained' if mode == 'handoff' else 'execute_managed_file'
        post = function(source, runtime['x-ouf-installation'], delegation_key_env, owner_key_env,
                        use_route_labels=use_route_labels, issue_handoff=mode == 'handoff-issue')
        route['plugins']['serverless-post-function']['functions']=[post]
        route['plugins']['proxy-rewrite']['uri']=path
        route['upstream']['nodes']={'ouf-onboarding:8080':1}
        route['plugins']['client-control']={'max_body_size':request_limit}
        route['upstream']['timeout']={'connect':3,'send':timeout,'read':timeout}
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
