"""Release materialization for the Onboarding MCP and M2M policy-read routes."""
import copy

from tools.apisix_request_schema import dispatch_validation
from tools.delegation_functions import INSTALLATION_LABELS, function
from tools.materialize_apisix_authorization_runtime import materialize_bundle_route, workload_guard
from tools.materialize_managed_upload import materialize as streaming_upload
from tools.plan_semantic_search import Change, changed_paths, inventory_routes
from tools.mcp_dispatch_contract import (
    EXECUTE_PATH, ONBOARDING_DISPATCH, POLICY_BUNDLE_ID, UPLOAD_ID, capability_contracts,
    dispatch_input_schema, envelope_refs,
)


def policy_bundle(policy, metadata, secret_ref, installation):
    policy_route = materialize_bundle_route(policy, metadata, secret_ref)
    roles = {'mcp': 'mcpServer', 'ingestion': 'ingestion', 'udp': 'udp', 'semantic': 'semantic'}
    labels = {f'ouf-{role}-workload': installation('iam.workloadClients.' + client)
              for role, client in roles.items()}
    if (policy['x-ouf-policy']['allowedServiceIdentities'] != [metadata[r + 'ServiceIdentity'] for r in roles]
            or policy['labels']['exposure'] != 'internal' or policy.get('vars')
            or policy['service_id'] != 'ouf-onboarding'
            or policy['x-ouf-backend-binding'] != {'service': 'ouf-onboarding', 'port': 8080,
                                                  'path': policy_route['plugins']['proxy-rewrite']['uri']}):
        raise ValueError('unexpected policy bundle service binding')
    policy_route['labels'].update(labels)
    policy_route['plugins']['serverless-post-function']['functions'] = [
        workload_guard(labels, ['SERVICE'], service_labels=True)]
    return policy_route


def check_binding(route, binding, contract, metadata):
    route_id = route['id']
    capability = binding['x-ouf-capability']
    cap = capability['capabilityId']
    rule = binding['x-ouf-policy']
    owner_path = binding['plugins']['proxy-rewrite']['uri']
    if (binding['uri'] != route['uri'] or binding['methods'] != ['POST'] or binding.get('vars')
            or binding['labels']['exposure'] != 'internal' or binding['service_id'] != 'ouf-onboarding'
            or owner_path != route['plugins']['proxy-rewrite']['uri']
            or binding['x-ouf-backend-binding'] != {'service': 'ouf-onboarding', 'port': 8080, 'path': owner_path}
            or cap != ONBOARDING_DISPATCH.get(route_id, 'ouf.managed-source.file.upload')
            or capability['owner'] != contract['owner'] or capability['operationType'] != contract['operationClass']
            or capability['humanRequired'] or not capability['toolEligible']
            or rule['identity'] != 'M2M' or rule['requiredScope'] != cap or rule['allowedActorTypes'] != ['HUMAN']
            or rule['allowedServiceIdentities'] != [metadata['mcpServiceIdentity']]
            or rule['maxRequestBytes'] != (10485760 if route_id == UPLOAD_ID else 65536)
            or rule['timeoutSeconds'] != route['upstream']['timeout']['read']):
        raise ValueError(f'{route_id}: unexpected Onboarding route binding')


def family_routes(runtime, managed, secret_ref, delegation, owner, installation):
    bindings = {r['id']: r for r in runtime['routes']}
    metadata = runtime['x-ouf-installation']
    existing = {r['id']: r for r in managed['routes']}
    existing[UPLOAD_ID] = streaming_upload(runtime, secret_ref, delegation, owner)
    routes = [policy_bundle(bindings[POLICY_BUNDLE_ID], metadata, secret_ref, installation)]
    settings = {'AUDIENCE': 'gateway.requiredAudience', 'MCP_WORKLOAD': 'iam.workloadClients.mcpServer',
                'DELEGATION_KEY_ENV': 'gateway.delegationKeyEnv', 'OWNER_KEY_ENV': 'gateway.sourceRevisionOwnerKeyEnv'}
    for route_id in (*ONBOARDING_DISPATCH, UPLOAD_ID):
        binding = bindings[route_id]
        # Revision read shares profile's non-Arguments envelope and 3-second upstream.
        template_id = 'mcp-managed-file-profile' if route_id == 'mcp-source-revision-read' else route_id
        route = copy.deepcopy(existing[template_id])
        cap = binding['x-ouf-capability']['capabilityId']
        contract = capability_contracts()[cap]
        if route_id == 'mcp-source-revision-read':
            route.update(id=route_id, uri=EXECUTE_PATH + '/source.revision/read')
            route['plugins']['proxy-rewrite']['uri'] = '/api/internal/v1/onboarding/source-revision-mcp/read'
            route['plugins'].pop('client-control')
            route['labels']['ouf-mediation'] = 'source-revision-v1'
        check_binding(route, binding, contract, metadata)
        if route_id in ONBOARDING_DISPATCH:
            schema = route['plugins']['request-validation']['body_schema']
            fields = schema['properties']
            for key, value in [('CapabilityID', cap), ('GatewayBindingRef', contract['gatewayBindingRef']),
                               ('OperationClass', contract['operationClass']), ('Owner', contract['owner'])]:
                fields[key] = {'const': value}
            fields['Arguments'] = envelope_refs(dispatch_input_schema(cap, contract['inputSchema']))
            # Retain the installed envelope ceiling, including on the three permission routes.
            fields['MaxResultBytes']['maximum'] = 1048576
            route['plugins']['request-validation'] = dispatch_validation(schema, binding['x-ouf-policy']['maxRequestBytes'])
        source = {UPLOAD_ID: 'execute_managed_upload', 'mcp-managed-file-profile': 'execute_managed_profile',
                  'mcp-source-revision-read': 'execute_revision_read'}.get(route_id, 'execute_permissions')
        route['plugins']['serverless-post-function']['functions'] = [
            function(source, metadata, delegation, owner, use_route_labels=True)]
        route['plugins']['request-id'] = binding['plugins']['request-id']
        route['labels'].update({label: installation(settings[key]) for key, label in INSTALLATION_LABELS.items()})
        route.update(priority=0, status=1)
        routes.append(route)

    for route in routes:
        route['labels']['ouf-exposure'] = 'internal'
        route['plugins']['openid-connect']['claim_validator']['issuer'] = {
            'valid_issuers': [installation('gateway.issuerUrl')]}
        group = 'authorizationPolicyRead' if route['id'] == POLICY_BUNDLE_ID else 'onboardingMcp'
        prefix = 'gateway.rateLimits.' + group + '.'
        route['plugins']['limit-count'].update(count=installation(prefix + 'count'),
                                              time_window=installation(prefix + 'timeWindowSeconds'))
    return routes


def check_selectors(desired, live):
    """Task 51h: literal URI, overlapping methods and host scope, foreign ID."""
    owned = {r['id'] for r in desired}
    for other in live:
        if other['id'] in owned:
            continue
        for route in desired:
            if not set(route.get('uris', [route.get('uri')])) & set(other.get('uris', [other.get('uri')])):
                continue
            methods, theirs = route.get('methods'), other.get('methods')
            if methods and theirs and set(methods).isdisjoint(theirs):
                continue
            hosts = route.get('hosts', [route['host']] if route.get('host') else [])
            other_hosts = other.get('hosts', [other['host']] if other.get('host') else [])
            if hosts and other_hosts and not any(hosts_overlap(a, b) for a in hosts for b in other_hosts):
                continue
            raise ValueError(f"{route['id']}: selector conflict with {other['id']}")


def hosts_overlap(first, second):
    first, second = first.lower(), second.lower()
    return (first == second or first.startswith('*') and second.endswith(first[1:])
            or second.startswith('*') and first.endswith(second[1:]))


def adoption_plan(desired, inventory):
    """Read-only preflight of resolved routes. Refuse a create or an occupied ID."""
    live = inventory_routes(inventory)
    check_selectors(desired, live.values())
    target_ids = set(ONBOARDING_DISPATCH) | {POLICY_BUNDLE_ID, UPLOAD_ID}
    changes = []
    for route in desired:
        key = route['id']
        if key not in target_ids:
            continue
        old = live.get(key)
        if (not old or any(old.get(k) != route.get(k) for k in
                           ('uri', 'uris', 'methods', 'host', 'hosts', 'vars', 'remote_addr', 'remote_addrs', 'filter_func'))
                or old['labels']['ouf-installation'] != route['labels']['ouf-installation']
                or old['plugins']['proxy-rewrite']['uri'] != route['plugins']['proxy-rewrite']['uri']):
            raise ValueError(f'{key}: missing or mismatched installed route')
        changes.append(Change(key, key, old, route))
    if len(changes) != len(target_ids) or {c.target_id for c in changes} != target_ids:
        raise ValueError('expected exactly one desired route for each adopted ID')
    return changes


def restore_adoption(plan, desired, readback):
    """Return before-images only after checking the full post-apply readback."""
    live = inventory_routes(readback)
    check_selectors(desired, live.values())
    for change in plan:
        if next(changed_paths(change.after, live.get(change.target_id)), None) is not None:
            raise ValueError(f'{change.target_id}: restore readback drift')
    return [Change(c.logical_id, c.target_id, c.after, c.before) for c in reversed(plan)]
