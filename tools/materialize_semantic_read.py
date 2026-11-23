"""Materialize Semantic consultation routes for the release and the retained read profile."""
import copy
import json
from pathlib import Path
from tools.apisix_request_schema import dispatch_validation
from tools.delegation_functions import capture_original_body, function
from tools.mcp_dispatch_contract import (
    EXECUTE_PATH, SEARCH_SCOPE, SEARCH_BINDINGS, capability_contracts, dispatch_input_schema, envelope_refs,
)
from tools.r2b_limits import rate_limit_profile

ROOT=Path(__file__).resolve().parents[1]

def materialize_governed(existing, runtime, delegation_key_env, semantic_key_env):
    installation = runtime['x-ouf-installation']
    template, = (r for r in existing['routes'] if r.get('uri') == EXECUTE_PATH)
    if not {'openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function'} <= template['plugins'].keys():
        raise ValueError('authenticated bounded execute template required')
    for route_id, (capability, suffix, mode) in SEARCH_BINDINGS.items():
        binding, = (r for r in runtime['routes'] if r['id'] == route_id)
        contract = capability_contracts()[capability]
        policy = binding['x-ouf-policy']
        backend = binding['x-ouf-backend-binding']
        cap = binding['x-ouf-capability']
        path = '/api/internal/v1/semantic/consultation/' + mode
        if (binding['uri'] != EXECUTE_PATH + suffix or binding['methods'] != ['POST'] or binding.get('vars')
                or binding['labels']['exposure'] != 'internal' or backend['service'] != 'ouf-semantic-registry'
                or backend['path'] != path or cap['capabilityId'] != capability
                or cap['owner'] != 'semantic' or contract['owner'] != cap['owner']
                or cap['operationType'] != 'READ' or contract['operationClass'] != cap['operationType']
                or contract['gatewayBindingRef'] != 'capability://' + capability
                or contract['toolEligible'] != (mode == 'search') or (mode == 'search-batch' and cap['toolEligible'])
                or (contract.get('publicationState') != 'ACTIVE'
                    and not (mode == 'search-batch' and 'publicationState' not in contract
                             and contract.get('provenance', {}).get('kind') == 'contract-derived'))
                or contract['requiredAuthorizationCapability'] != SEARCH_SCOPE
                or policy['identity'] != 'M2M' or policy['requiredScope'] != SEARCH_SCOPE
                or policy['allowedActorTypes'] != ['HUMAN'] or not cap['humanRequired']
                or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
                or not 0 < policy['maxRequestBytes'] <= 65536 or delegation_key_env == semantic_key_env):
            raise ValueError(f'{route_id}: semantic search binding mismatch')
        route = copy.deepcopy(template)
        route.update(id=route_id, uri=binding['uri'], methods=['POST'], priority=0, status=1)
        route['labels'].update({'ouf-mediation': 'semantic-read-v1', 'ouf-exposure': 'internal'})
        plugins = route['plugins']
        plugins.update(copy.deepcopy(binding['plugins']))
        plugins['limit-count'] = rate_limit_profile('semanticSearch' if mode == 'search' else 'semanticSearchBatch')
        limit = policy['maxRequestBytes']
        plugins['client-control'] = {'max_body_size': limit}
        if mode == 'search-batch':
            plugins['request-validation']['rejected_msg'] = 'SEM_BATCH_ARGUMENTS_INVALID'
            plugins['response-rewrite'] = {
                'vars': [['status', '==', 413]], 'headers': {'set': {'Content-Type': 'application/json'}},
                'body': '{"code":"SEM_BATCH_REQUEST_TOO_LARGE"}',
            }
        plugins['serverless-pre-function']['functions'].append(capture_original_body(limit))
        post = function('execute_semantic_read', installation, delegation_key_env, semantic_key_env,
                        use_route_labels=True, read_mode=mode)
        plugins['serverless-post-function'] = {'phase': 'access', 'functions': [post]}
        timeout = policy['timeoutSeconds']
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'retries': 0,
                             'nodes': {f"{backend['service']}:{backend['port']}": 1},
                             'timeout': dict(connect=timeout, send=timeout, read=timeout)}
        yield route


def materialize(existing,installation,delegation_key_env,semantic_key_env,semantic_upstream,route_ids):
    if delegation_key_env==semantic_key_env:
        raise ValueError('distinct delegation and semantic owner signing keys required')
    if set(route_ids)!={'search','get'} or len(set(route_ids.values()))!=2 or any(not isinstance(x,str) or not x for x in route_ids.values()):
        raise ValueError('two distinct installation-owned route IDs required')
    # Reuse the proven authentication/limits template; never rebuild /mcp or upload routes.
    templates=[r for r in existing['routes'] if r.get('uri')=='/internal/capabilities/v1/execute']
    if len(templates)!=1:raise ValueError('one established execute template required')
    template=templates[0]
    for name in ('openid-connect','limit-count','request-validation','serverless-pre-function'):
        if name not in template.get('plugins',{}):raise ValueError('authenticated bounded execute template required')
    if not isinstance(semantic_upstream,dict) or semantic_upstream.get('scheme') not in ('http','https') or not semantic_upstream.get('nodes'):
        raise ValueError('resolved semantic upstream binding required')
    result=copy.deepcopy(existing)
    for name in ('search','get'):
        uri='/internal/capabilities/v1/execute/semantic/'+name
        if any(r.get('id')==route_ids[name] or r.get('uri')==uri for r in existing['routes']):
            raise ValueError('semantic route already exists; reconcile before materialization')
        r=copy.deepcopy(template)
        r.update(id=route_ids[name],uri=uri,methods=['POST'])
        r['labels']['ouf-mediation']='semantic-read-v1'
        schema = json.loads((ROOT / f'schemas/mcp-gateway-semantic-{name}-dispatch-v1.json').read_bytes())
        if name == 'search':
            source = capability_contracts()[SEARCH_SCOPE]['inputSchema']
            schema['properties']['Arguments'] = envelope_refs(dispatch_input_schema(SEARCH_SCOPE, source))
        r['plugins']['request-validation'] = dispatch_validation(schema, 65536)
        r['plugins']['serverless-post-function']={'phase':'access','functions':[function('execute_semantic_read',installation,delegation_key_env,semantic_key_env)]}
        r['plugins']['proxy-rewrite']={'uri':'/api/internal/v1/semantic/consultation/'+name}
        r['upstream']=copy.deepcopy(semantic_upstream)
        r.pop('service_id',None)
        r['upstream']['retries']=0
        r['upstream']['timeout']={'connect':3,'send':3,'read':3}
        result['routes'].append(r)
    return result
