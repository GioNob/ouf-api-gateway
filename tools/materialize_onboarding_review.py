"""Add two bounded draft-review commands and the existing owner's HUMAN UI.

No approval/activation capability is delegated to the chatbot. The owner serves
its existing OAuth session and CSRF boundary through the fixed review namespace.
"""
import copy
import json
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_managed_file_ths import materialize as human_picker

ROOT = Path(__file__).resolve().parents[1]
MODES = {
    'review-prepare': ('ouf.managed-source.onboarding.review.prepare', 'COMMAND'),
    'review-read': ('ouf.managed-source.onboarding.read', 'READ'),
}


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
        route['plugins']['request-validation'] = {'max_req_body_size': 65536,
            'body_schema': json.loads((ROOT/f'schemas/mcp-gateway-onboarding-{mode}-dispatch-v1.json').read_text())}
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
        page['upstream']['timeout'] = {'connect': 3, 'send': 3, 'read': 10}
        _append(result, page)
    return result


def _append(result, route):
    if any(r.get('id') == route['id'] or r.get('uri') == route['uri'] for r in result['routes']):
        raise ValueError('review route already exists; reconcile before materialization')
    result['routes'].append(route)
