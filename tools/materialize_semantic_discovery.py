"""Materialize exact discovery routes on the authenticated MCP execute boundary."""
import copy
import json
from pathlib import Path

from tools.apisix_request_schema import dispatch_validation
from tools.delegation_functions import capture_original_body, function
from tools.mcp_dispatch_contract import DISCOVERY_MODES, DISCOVERY_SCOPE, capability_contracts

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 65536


def materialize_governed(existing, runtime, delegation_key_env, discovery_key_env, proposal_key_env):
    installation = runtime['x-ouf-installation']
    bindings = {route['id']: route for route in runtime['routes']}
    ids = {mode: 'mcp-semantic-discovery-' + mode for mode in DISCOVERY_MODES}
    template = _template(existing)
    for mode, route_id in ids.items():
        binding = bindings[route_id]
        cap = DISCOVERY_SCOPE if mode == 'request' else DISCOVERY_SCOPE + '.' + mode
        contract = capability_contracts()[cap]
        operation = 'COMMAND' if mode in ('request', 'adopt') else 'READ'
        backend = binding['x-ouf-backend-binding']
        if (binding['uri'] != _uri(mode) or binding['methods'] != ['POST']
                or binding['labels']['exposure'] != 'internal'
                or backend != {'service': 'ouf-semantic-registry', 'port': 8080, 'path': _path(mode)}
                or binding['x-ouf-capability']['capabilityId'] != cap or contract['publicationState'] != 'ACTIVE'
                or not (contract['toolEligible'] and binding['x-ouf-capability']['toolEligible'])
                or binding['x-ouf-capability']['humanRequired']
                or binding['x-ouf-capability']['owner'] != contract['owner'] or contract['owner'] != 'semantic'
                or binding['x-ouf-capability']['operationType'] != contract['operationClass']
                or contract['operationClass'] != operation or contract['gatewayBindingRef'] != 'capability://' + cap
                or binding['x-ouf-policy'] != {
                    'identity': 'M2M', 'requiredScope': DISCOVERY_SCOPE, 'allowedActorTypes': ['HUMAN'],
                    'allowedServiceIdentities': [installation['mcpServiceIdentity']],
                    'maxRequestBytes': LIMIT, 'timeoutSeconds': 3}):
            raise ValueError(f'{route_id}: discovery binding mismatch')
        upstream = {'scheme': 'http', 'nodes': {f"{backend['service']}:{backend['port']}": 1}}
        owner_key = proposal_key_env if mode == 'adopt' else discovery_key_env
        route = _route(existing, template, mode, route_id, installation, delegation_key_env, owner_key,
                       upstream, binding['plugins']['request-validation'], use_route_labels=True)
        route.update(priority=0, status=1)
        route['labels']['ouf-exposure'] = binding['labels']['exposure']
        route['plugins']['request-id'] = binding['plugins']['request-id']
        if mode == 'adopt':
            route['upstream']['type'] = 'roundrobin'
        yield route


def _uri(mode):
    return '/internal/capabilities/v1/execute/semantic/discovery/' + mode


def _path(mode):
    if mode == 'adopt':
        return '/api/semantic/v1/proposal-commands/adopt'
    return '/api/internal/v1/semantic/discovery/' + mode


def _template(existing):
    templates = [r for r in existing['routes'] if r.get('uri') == '/internal/capabilities/v1/execute']
    if len(templates) != 1:
        raise ValueError('one established execute template required')
    template, = templates
    if not {'openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function'} <= template['plugins'].keys():
        raise ValueError('authenticated bounded execute template required')
    return template


def _route(existing, template, mode, route_id, installation, delegation_key, owner_key, upstream,
           validation, *, use_route_labels=False):
    if delegation_key == owner_key:
        raise ValueError('distinct delegation and semantic owner signing keys required')
    uri = _uri(mode)
    if any(str(r['id']) == route_id or any(
            path == uri or (isinstance(path, str) and path.endswith('*') and uri.startswith(path[:-1]))
            for path in ([r['uri']] if 'uri' in r else r.get('uris', []))) for r in existing['routes']):
        raise ValueError('semantic route already exists; reconcile before materialization')
    route = copy.deepcopy(template)
    for inherited in ('create_time', 'update_time', 'service_id', 'upstream_id', 'uris'):
        route.pop(inherited, None)
    route.update(id=route_id, uri=uri, methods=['POST'])
    adopt = mode == 'adopt'
    route['labels']['ouf-mediation'] = 'semantic-proposal-v1' if adopt else 'semantic-discovery-v1'
    plugins = route['plugins']
    plugins['client-control'] = {'max_body_size': LIMIT}
    plugins['request-validation'] = validation
    plugins['proxy-rewrite'] = {'uri': _path(mode)}
    if adopt or (mode == 'candidates' and use_route_labels):
        plugins['serverless-pre-function']['functions'].append(capture_original_body(LIMIT))
    kind = 'execute_discovery_adopt' if adopt else 'execute_semantic_discovery'
    post = function(kind, installation, delegation_key, owner_key, use_route_labels=use_route_labels,
                    discovery_mode=mode if use_route_labels else None)
    plugins['serverless-post-function'] = {'phase': 'access', 'functions': [post]}
    route['upstream'] = {**copy.deepcopy(upstream), 'retries': 0, 'timeout': dict(connect=3, send=3, read=3)}
    return route


def materialize(existing, installation, delegation_key_env, discovery_key_env, semantic_upstream, route_ids):
    if (set(route_ids) != {'request', 'status', 'candidates'} or len(set(route_ids.values())) != 3
            or any(not isinstance(x, str) or not x for x in route_ids.values())):
        raise ValueError('three distinct installation-owned route IDs required')
    if (not isinstance(semantic_upstream, dict) or semantic_upstream.get('scheme') not in ('http', 'https')
            or not semantic_upstream.get('nodes')):
        raise ValueError('resolved semantic upstream binding required')
    template = _template(existing)
    result = copy.deepcopy(existing)
    for mode in ('request', 'status', 'candidates'):
        schema = json.loads((ROOT / f'schemas/mcp-gateway-semantic-discovery-{mode}-dispatch-v1.json').read_bytes())
        result['routes'].append(_route(existing, template, mode, route_ids[mode], installation, delegation_key_env,
                                       discovery_key_env, semantic_upstream, dispatch_validation(schema, LIMIT)))
    return result
