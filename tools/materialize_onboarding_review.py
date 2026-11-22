"""Add two bounded draft-review commands and the existing owner's HUMAN UI.

No approval/activation capability is delegated to the chatbot. The owner serves
its existing OAuth session and CSRF boundary through the fixed review namespace.
"""
import copy
import json
from pathlib import Path

from tools.apisix_request_schema import dispatch_validation
from tools.delegation_functions import capture_original_body, function
from tools.materialize_managed_file_ths import materialize as human_picker
from tools.materialize_trusted_human_onboarding_runtime import materialize_route as human_route
from tools.materialize_apisix_internal_m2m_routes import materialize as service_routes
from tools.mcp_dispatch_contract import (
    RECOVERY_LINK_ID, RECOVERY_LINK_PATH, capability_contracts, manifest_execute_uri,
)

ROOT = Path(__file__).resolve().parents[1]
MODES = {
    'review-prepare': ('ouf.managed-source.onboarding.review.prepare', 'COMMAND'),
    'review-read': ('ouf.managed-source.onboarding.read', 'READ'),
}
INGESTION_RUNS = '/api/trusted-human/v1/ingestion/runs/'
RECOVERY_PAGE_ID = 'trusted-human-ingestion-run-recovery'
RUN_ROUTES = {
    'trusted-human-ingestion-run-read': ('GET', '', 'ingestion.run.read'),
    'trusted-human-ingestion-run-resume': ('POST', '/resume', 'ingestion.run.resume'),
    'trusted-human-ingestion-run-abort': ('POST', '/abort', 'ingestion.run.abort'),
}
UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'


def review_schema(mode):
    return json.loads((ROOT / f'schemas/mcp-gateway-onboarding-{mode}-dispatch-v1.json').read_bytes())


def review_page(picker, flow):
    capability, read_timeout = {
        'onboarding': ('ouf.onboarding.configuration.write', 60),
        'semantic': ('ouf.semantic.review', 10),
        # An owner THS decision can perform two sequential 15s Ingestion calls.
        'ingestion-run-recovery': ('ingestion.run.read', 35),
    }[flow]
    page = copy.deepcopy(picker)
    route_id = RECOVERY_PAGE_ID if flow == 'ingestion-run-recovery' else 'trusted-human-'+flow+'-review'
    page.update(id=route_id, uri='/trusted-human/'+flow+'/*')
    page['labels'].update({'ouf-capability': capability, 'ouf-surface': 'TRUSTED_HUMAN_WORKFLOW'})
    page['plugins']['client-control'] = {'max_body_size': 65536}
    page['plugins'].pop('proxy-control', None)
    # The source action includes a bounded 35s readiness probe plus activation.
    page['upstream']['timeout'] = {'connect': 3, 'send': 3, 'read': read_timeout}
    return page


def recovery_run_route(binding, installation, secret_ref):
    method, suffix, scope = RUN_ROUTES[binding['id']]
    uri = INGESTION_RUNS + '*'
    selector = [['uri', '~~', '^' + INGESTION_RUNS + UUID + suffix + '$']]
    policy, capability = binding['x-ouf-policy'], binding['x-ouf-capability']
    if (binding['uri'] != uri or binding['methods'] != [method] or binding.get('vars') != selector
            or binding['x-ouf-backend-binding'] != {'service': 'ouf-ingestion-runtime', 'port': 8080, 'path': uri}
            or capability['capabilityId'] != scope or capability['owner'] != 'ingestion'
            or not capability['humanRequired'] or capability['toolEligible']
            or policy['requiredScope'] != scope or policy['maxRequestBytes'] != 65536
            or policy['timeoutSeconds'] != 15):
        raise ValueError('ingestion run HUMAN binding mismatch: ' + binding['id'])
    route = human_route(binding, installation, secret_ref, strip_all_ouf_headers=True)
    route['vars'] = selector
    return route


def recovery_link_route(template, binding, installation, delegation_key_env, owner_key_env, *, use_route_labels):
    policy, capability = binding['x-ouf-policy'], binding['x-ouf-capability']
    contract = capability_contracts().get(capability['capabilityId'])
    if not contract or contract.get('publicationState') != 'ACTIVE':
        raise ValueError('active MCP recovery-link capability required in pinned manifest')
    uri = manifest_execute_uri(contract['gatewayBindingRef'])
    if (binding['uri'] != uri or binding['methods'] != ['POST']
            or binding['labels']['exposure'] != 'internal'
            or binding['x-ouf-backend-binding'] != {'service': 'ouf-onboarding', 'port': 8080, 'path': RECOVERY_LINK_PATH}
            or capability['owner'] != contract['owner'] or contract['owner'] != 'onboarding'
            or capability['operationType'] != contract['operationClass']
            or policy['requiredScope'] != contract['requiredAuthorizationCapability']
            or policy['identity'] != 'M2M' or policy['allowedActorTypes'] != ['HUMAN']
            or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
            or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != 3):
        raise ValueError('ingestion recovery-link binding mismatch')
    route = copy.deepcopy(template)
    route.update(id=RECOVERY_LINK_ID, uri=uri, methods=['POST'])
    route['labels']['ouf-mediation'] = 'onboarding-review-v1'
    plugins = route['plugins']
    plugins['request-validation'] = binding['plugins']['request-validation']
    plugins['client-control'] = {'max_body_size': policy['maxRequestBytes']}
    plugins['serverless-pre-function']['functions'].append(capture_original_body(policy['maxRequestBytes']))
    plugins['serverless-post-function'] = {'phase': 'access', 'functions': [
        function('execute_managed_file', installation, delegation_key_env, owner_key_env,
                 use_route_labels=use_route_labels, recovery_link=contract),
    ]}
    plugins['proxy-rewrite'] = {'uri': RECOVERY_LINK_PATH}
    route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {'ouf-onboarding:8080': 1},
                         'retries': 0, 'timeout': {'connect': 3, 'send': 3, 'read': 3}}
    return route


def materialize(existing, runtime, delegation_key_env, owner_key_env, *, use_route_labels=False):
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
        request_limit = 3145728 if mode == 'review-prepare' else 65536
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
            or policy['maxRequestBytes'] != request_limit or policy['timeoutSeconds'] != timeout):
            raise ValueError('onboarding review binding mismatch')
        route = copy.deepcopy(templates[0])
        route.update(id=route_id, uri=uri, methods=['POST'])
        route['labels']['ouf-mediation'] = 'onboarding-review-v1'
        route['plugins']['request-validation'] = dispatch_validation(review_schema(mode), request_limit)
        # The November 8 apply left this route's installed function intact.
        source = 'execute_managed_file_retained' if mode == 'review-read' else 'execute_managed_file'
        post = function(source, installation, delegation_key_env, owner_key_env,
                        use_route_labels=use_route_labels and mode == 'review-read')
        route['plugins']['serverless-post-function'] = {'phase': 'access', 'functions': [post]}
        route['plugins']['proxy-rewrite'] = {'uri': path}
        if mode == 'review-prepare':
            route['plugins']['client-control'] = {'max_body_size': request_limit}
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
    for flow in ('onboarding', 'semantic', 'ingestion-run-recovery'):
        _append(result, review_page(human_routes[0], flow))
    secret_ref = templates[0]['plugins']['openid-connect']['client_secret']
    indexed = {r['id']: r for r in runtime['routes']}
    if RECOVERY_LINK_ID in indexed:
        _append(result, recovery_link_route(templates[0], indexed[RECOVERY_LINK_ID], installation,
                                           delegation_key_env, owner_key_env, use_route_labels=use_route_labels))
    for route_id in RUN_ROUTES:
        _append(result, recovery_run_route(indexed[route_id], installation, secret_ref))
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
           and set(r.get('methods', [])) & set(route['methods'])
           # The run bindings above validate disjoint selectors for the same path prefix.
           and not (r.get('id') in RUN_ROUTES and route['id'] in RUN_ROUTES))
           for r in result['routes']):
        raise ValueError('review route already exists; reconcile before materialization')
    result['routes'].append(route)
