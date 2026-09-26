"""Candidate streaming upload binding; deployment needs verified APISIX-Runtime."""
import argparse
import copy
import json
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_permission_proposals import materialize as permission_runtime

CAP='ouf.managed-source.file.upload'
PATH='/api/internal/v1/onboarding/managed-file-mcp/upload'
URI='/internal/capabilities/v1/execute/managed.file/upload'

def materialize(runtime,oidc_secret_ref,delegation_key_env,owner_key_env):
    result=permission_runtime(runtime,oidc_secret_ref,delegation_key_env,owner_key_env)
    template=next(r for r in result['routes'] if r['uri']=='/internal/capabilities/v1/execute')
    matches=[r for r in runtime['routes'] if r.get('id')=='mcp-managed-file-upload']
    if len(matches)!=1:raise ValueError('exact delegated upload binding required')
    binding=matches[0];policy=binding['x-ouf-policy'];cap=binding['x-ouf-capability']
    if (binding['uri']!=URI or binding['methods']!=['POST'] or binding['service_id']!='ouf-onboarding'
        or binding['x-ouf-backend-binding']['service']!='ouf-onboarding'
        or binding['x-ouf-backend-binding']['port']!=8080
        or binding['plugins']['proxy-rewrite']['uri']!=PATH
        or cap['capabilityId']!=CAP or cap['owner']!='onboarding' or cap['operationType']!='COMMAND'
        or cap.get('humanRequired') or not cap.get('toolEligible') or policy['identity']!='M2M'
        or policy['requiredScope']!=CAP or policy['allowedActorTypes']!=['HUMAN']
        or runtime['x-ouf-installation']['mcpServiceIdentity'] not in policy['allowedServiceIdentities']
        or policy['maxRequestBytes']!=10485760 or policy['timeoutSeconds']!=30):
        raise ValueError('delegated upload binding mismatch')
    route=copy.deepcopy(template)
    route['id']='mcp-managed-file-upload';route['uri']=URI
    route['labels']['ouf-mediation']='managed-file-streaming-upload-v1'
    route['labels']['ouf-managed']='true';route['labels']['ouf-exposure']='internal'
    route['plugins'].pop('request-validation',None)  # JSON validation would buffer CSV.
    route['plugins']['request-id']={'header_name':'X-Correlation-ID','include_in_response':True,'algorithm':'uuid'}
    # Preserve only the two metadata headers validated in the access phase.
    # The execute template strips every other caller-supplied X-OUF-* header.
    route['plugins']['serverless-pre-function']['functions']=[
        "return function(conf, ctx) for name,_ in pairs(ngx.req.get_headers(0)) do "
        "local n=name:lower(); if n:sub(1,6)=='x-ouf-' "
        "and n~='x-ouf-delegation' and n~='x-ouf-file-id' "
        "then ngx.req.clear_header(name) end end end"
    ]
    route['plugins']['client-control']={'max_body_size':10485760}
    route['plugins']['proxy-control']={'request_buffering':False}
    route['plugins']['serverless-post-function']['functions']=[function('execute_managed_upload',runtime['x-ouf-installation'],delegation_key_env,owner_key_env)]
    route['plugins']['proxy-rewrite']['uri']=PATH
    route['upstream']['nodes']={'ouf-onboarding:8080':1}
    route['upstream']['timeout']={'connect':10,'send':30,'read':30}
    return route

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--oidc-client-secret-ref',required=True)
    p.add_argument('--delegation-key-env',required=True)
    p.add_argument('--owner-key-env',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text()),a.oidc_client_secret_ref,a.delegation_key_env,a.owner_key_env),indent=2)+'\n')
