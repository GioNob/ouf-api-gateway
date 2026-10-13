"""Add only four purpose-bound semantic preparation routes to an existing materialized installation.

No upstream/issuer/secret/domain/tenant default; existing routes remain byte-equivalent.
"""
import copy
import json
from pathlib import Path
from tools.delegation_functions import function

ROOT=Path(__file__).resolve().parents[1]

def materialize(existing,installation,delegation_key_env,semantic_key_env,semantic_upstream,route_ids):
    if delegation_key_env==semantic_key_env:
        raise ValueError('distinct delegation and semantic owner signing keys required')
    if set(route_ids)!={'create','validate','request','read'} or len(set(route_ids.values()))!=4 or any(not isinstance(x,str) or not x for x in route_ids.values()):
        raise ValueError('four distinct installation-owned route IDs required')
    # Reuse the proven authentication/limits template; never rebuild /mcp or upload routes.
    templates=[r for r in existing['routes'] if r.get('uri')=='/internal/capabilities/v1/execute']
    if len(templates)!=1:raise ValueError('one established execute template required')
    template=templates[0]
    for name in ('openid-connect','limit-count','request-validation','serverless-pre-function'):
        if name not in template.get('plugins',{}):raise ValueError('authenticated bounded execute template required')
    if not isinstance(semantic_upstream,dict) or semantic_upstream.get('scheme') not in ('http','https') or not semantic_upstream.get('nodes'):
        raise ValueError('resolved semantic upstream binding required')
    result=copy.deepcopy(existing)
    for name in ('create','validate','request','read'):
        uri='/internal/capabilities/v1/execute/semantic/proposals/'+name
        if any(r.get('id')==route_ids[name] or r.get('uri')==uri for r in existing['routes']):
            raise ValueError('semantic route already exists; reconcile before materialization')
        r=copy.deepcopy(template)
        r.update(id=route_ids[name],uri=uri,methods=['POST'])
        r['labels']['ouf-mediation']='semantic-proposal-v1'
        r['plugins']['request-validation']={'max_req_body_size':65536,'body_schema':json.loads((ROOT/f'schemas/mcp-gateway-semantic-proposal-{name}-dispatch-v1.json').read_text())}
        r['plugins']['serverless-post-function']={'phase':'access','functions':[function('execute_semantic_proposal',installation,delegation_key_env,semantic_key_env)]}
        r['plugins']['proxy-rewrite']={'uri':'/api/internal/v1/semantic/proposals/'+name}
        r['upstream']=copy.deepcopy(semantic_upstream)
        r.pop('service_id',None)
        r['upstream']['retries']=0
        r['upstream']['timeout']={'connect':3,'send':10,'read':10}
        result['routes'].append(r)
    return result
