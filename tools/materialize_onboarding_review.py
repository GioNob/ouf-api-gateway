"""Add two bounded draft-review commands and the existing owner's HUMAN UI.

No approval/activation capability is delegated to the chatbot. The owner serves
its existing OAuth session and CSRF boundary through the fixed review namespace.
"""
import copy
import json
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_managed_file_ths import materialize as human_picker
from tools.materialize_trusted_human_onboarding_runtime import materialize_route as human_route
from tools.materialize_apisix_internal_m2m_routes import materialize as service_routes

ROOT = Path(__file__).resolve().parents[1]
MODES = {
    'review-prepare': ('ouf.managed-source.onboarding.review.prepare', 'COMMAND'),
    'review-read': ('ouf.managed-source.onboarding.read', 'READ'),
}



def apisix_review_schema(schema):
    """Project one reference-free schema for APISIX's Lua JSON Schema store.

    The canonical contract keeps its URN. This metadata-only projection may
    remove that exact nested resource identifier only while no references
    depend on it; all validation keywords remain byte-for-byte equivalent.
    """
    def has_reference(value):
        if isinstance(value, dict):
            return any(k in ('$ref', '$dynamicRef', '$recursiveRef') or has_reference(v)
                       for k, v in value.items())
        return isinstance(value, list) and any(has_reference(v) for v in value)
    result = copy.deepcopy(schema)
    proposal = result['properties']['Arguments']['properties']['executionProposal']
    if (proposal.get('$id') != 'urn:ouf:managed-file-execution-proposal:lexical-csv:v1'
            or has_reference(result)):
        raise ValueError('exact reference-free execution proposal schema required')
    del proposal['$id']
    return result


def materialize(existing, runtime, delegation_key_env, owner_key_env):
    if delegation_key_env == owner_key_env:
        raise ValueError('distinct delegation and owner signing keys required')
    result = copy.deepcopy(existing)
    templates = [r for r in result['routes'] if r.get('uri') == '/internal/capabilities/v1/execute']
    if len(templates) != 1 or any(name not in templates[0].get('plugins', {}) for name in
           ('openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function')):
        raise ValueError('one authenticated bounded execute template required')
    installation = runtime['x-ouf-installation']
    for mode, (cap, operation) in MODES.items():
        timeout = 10 if mode == 'review-prepare' else 3
        route_id = 'mcp-managed-file-'+mode
        matches = [r for r in runtime['routes'] if r.get('id') == route_id]
        if len(matches) != 1:
            raise ValueError('exact onboarding review binding required')
        binding = matches[0]
        policy, capability = binding['x-ouf-policy'], binding['x-ouf-capability']
        uri = '/internal/capabilities/v1/execute/managed.file/'+mode
        path = '/api/internal/v1/onboarding/managed-file-mcp/'+mode
        if (binding.get('uri') != uri or binding.get('methods') != ['POST']
            or binding.get('service_id') != 'ouf-onboarding'
            or binding['x-ouf-backend-binding'] != {'service': 'ouf-onboarding', 'port': 8080, 'path': path}
            or binding['plugins']['proxy-rewrite']['uri'] != path
            or capability['capabilityId'] != cap or capability['owner'] != 'onboarding'
            or capability['operationType'] != operation or capability.get('humanRequired') or not capability.get('toolEligible')
            or policy['identity'] != 'M2M' or policy['requiredScope'] != cap
            or policy['allowedActorTypes'] != ['HUMAN']
            or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
            or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != timeout):
            raise ValueError('onboarding review binding mismatch')
        route = copy.deepcopy(templates[0])
        route.update(id=route_id, uri=uri, methods=['POST'])
        route['labels']['ouf-mediation'] = 'onboarding-review-v1'
        schema = json.loads((ROOT/f'schemas/mcp-gateway-onboarding-{mode}-dispatch-v1.json').read_text())
        if mode == 'review-prepare':
            schema = apisix_review_schema(schema)
        route['plugins']['request-validation'] = {'max_req_body_size': 65536, 'body_schema': schema}
        route['plugins']['serverless-post-function'] = {'phase': 'access', 'functions': [
            function('execute_managed_file', installation, delegation_key_env, owner_key_env)]}
        route['plugins']['proxy-rewrite'] = {'uri': path}
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {'ouf-onboarding:8080': 1},
                             'retries': 0, 'timeout': {'connect': 3, 'send': timeout, 'read': timeout}}
        _append(result, route)
    # Reuse the existing owner-session boundary; no browser tokens enter MCP.
    human_routes = human_picker(runtime)['routes']
    login = human_routes[1]
    current = [r for r in result['routes'] if r.get('id') == login['id']]
    permission_login = copy.deepcopy(login)
    permission_login['plugins']['serverless-pre-function']['functions'] = [
        "return function() local h=ngx.req.get_headers(0); for k,_ in pairs(h) do if k:lower():sub(1,6)=='x-ouf-' or k:lower()=='authorization' then ngx.req.clear_header(k) end end end"]
    if len(current) != 1 or current[0] not in (login, permission_login):
        raise ValueError('existing owner OAuth login route must match; reconcile before materialization')
    for flow, capability in [('onboarding', 'ouf.onboarding.configuration.write'), ('semantic', 'ouf.semantic.review')]:
        page = copy.deepcopy(human_routes[0])
        page.update(id='trusted-human-'+flow+'-review', uri='/trusted-human/'+flow+'/*')
        page['labels'].update({'ouf-capability': capability, 'ouf-surface': 'TRUSTED_HUMAN_WORKFLOW'})
        page['plugins']['client-control'] = {'max_body_size': 65536}
        page['plugins'].pop('proxy-control', None)
        # The source action includes a bounded 35s readiness probe plus activation.
        page['upstream']['timeout'] = {'connect': 3, 'send': 3, 'read': 60 if flow == 'onboarding' else 10}
        _append(result, page)
    secret_ref = templates[0]['plugins']['openid-connect']['client_secret']
    indexed = {r['id']: r for r in runtime['routes']}
    readiness_id = 'trusted-human-ingestion-onboarding-readiness'
    readiness = indexed[readiness_id]
    path = '/api/trusted-human/v1/ingestion/onboarding-readiness'
    if (readiness['uri'] != path or readiness['methods'] != ['POST']
            or readiness['x-ouf-backend-binding'] != {'service': 'ouf-ingestion-runtime', 'port': 8080, 'path': path}
            or readiness['x-ouf-policy']['requiredScope'] != 'ouf.onboarding.configuration.write'
            or readiness['x-ouf-policy']['timeoutSeconds'] != 35):
        raise ValueError('readiness owner binding mismatch')
    _append(result, human_route(readiness, installation, secret_ref))
    compatibility_id = 'r4a-onboarding-ingestion-compatibility-read'
    compatibility = indexed[compatibility_id]
    path = '/api/internal/v1/onboarding/compatibility/ingestion-runtime'
    if (compatibility['uri'] != path or compatibility['methods'] != ['GET']
            or compatibility['x-ouf-backend-binding'] != {'service': 'ouf-onboarding', 'port': 8080, 'path': path}
            or compatibility['x-ouf-policy']['requiredScope'] != 'ouf.onboarding.configuration.read'
            or compatibility['x-ouf-policy']['timeoutSeconds'] != 10):
        raise ValueError('compatibility owner binding mismatch')
    route = service_routes(runtime, [compatibility_id], secret_ref)['routes'][0]
    # Preserve query parameters for the owner's exact source/version/hash check.
    route['upstream'].update(retries=0, timeout={'connect': 3, 'send': 3, 'read': 10})
    _append(result, route)
    return result


def _append(result, route):
    if any(r.get('id') == route['id'] or (r.get('uri') == route['uri']
           and set(r.get('methods', [])) & set(route['methods'])) for r in result['routes']):
        raise ValueError('review route already exists; reconcile before materialization')
    result['routes'].append(route)
