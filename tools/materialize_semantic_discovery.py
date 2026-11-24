"""Add only three purpose-bound discovery routes to an existing materialized installation.

No upstream/issuer/secret/domain/tenant default; existing routes remain byte-equivalent.
"""
import copy
import json
from pathlib import Path
from tools.apisix_request_schema import dispatch_validation
from tools.managed_discovery_functions import owner_function

ROOT=Path(__file__).resolve().parents[1]


def materialize(existing,installation,delegation_key_env,discovery_key_env,semantic_upstream,route_ids):
    if set(route_ids)!={'request','status','candidates'} or len(set(route_ids.values()))!=3 or any(not isinstance(x,str) or not x for x in route_ids.values()):
        raise ValueError('three distinct installation-owned route IDs required')
    # Reuse the proven authentication/limits template; never rebuild /mcp or upload routes.
    templates=[r for r in existing['routes'] if r.get('uri')=='/internal/capabilities/v1/execute']
    if len(templates)!=1:raise ValueError('one established execute template required')
    template=templates[0]
    for name in ('openid-connect','limit-count','request-validation','serverless-pre-function'):
        if name not in template.get('plugins',{}):raise ValueError('authenticated bounded execute template required')
    if not isinstance(semantic_upstream,dict) or semantic_upstream.get('scheme') not in ('http','https') or not semantic_upstream.get('nodes'):
        raise ValueError('resolved semantic upstream binding required')
    if delegation_key_env == discovery_key_env:
        raise ValueError('distinct delegation and semantic owner signing keys required')
    post = owner_function('execute_semantic_discovery', installation, delegation_key_env, discovery_key_env)
    result=copy.deepcopy(existing)
    for name in ('request','status','candidates'):
        uri='/internal/capabilities/v1/execute/semantic/discovery/'+name
        if any(str(r['id']) == route_ids[name] or any(
                path == uri or (isinstance(path, str) and path.endswith('*') and uri.startswith(path[:-1]))
                for path in ([r['uri']] if 'uri' in r else r.get('uris', []))) for r in existing['routes']):
            raise ValueError('semantic route already exists; reconcile before materialization')
        r=copy.deepcopy(template)
        r.update(id=route_ids[name],uri=uri,methods=['POST'])
        r['labels']['ouf-mediation']='semantic-discovery-v1'
        schema = json.loads((ROOT / f'schemas/mcp-gateway-semantic-discovery-{name}-dispatch-v1.json').read_bytes())
        r['plugins']['request-validation'] = dispatch_validation(schema, 65536)
        r['plugins']['serverless-post-function']={'phase':'access','functions':[post]}
        r['plugins']['proxy-rewrite']={'uri':'/api/internal/v1/semantic/discovery/'+name}
        r['upstream']=copy.deepcopy(semantic_upstream)
        for inherited in ('create_time', 'update_time', 'service_id', 'upstream_id', 'uris'):
            r.pop(inherited, None)
        r['plugins']['client-control'] = {'max_body_size': 65536}
        r['upstream']['retries']=0
        r['upstream']['timeout']={'connect':3,'send':3,'read':3}
        result['routes'].append(r)
    return result
