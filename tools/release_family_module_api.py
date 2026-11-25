"""Materializza le API REST Semantic e le rotte interne fra moduli della famiglia F7."""
import copy

from tools.materialize_apisix_authorization_runtime import workload_guard
from tools.materialize_apisix_internal_m2m_routes import materialize_route
from tools.materialize_r4a_identity_preflight import materialize as preflight

SEMANTIC = (
    'semantic-approval-request', 'semantic-artifact-propose', 'semantic-artifact-search',
    'semantic-rdf-import', 'semantic-revision-validate',
)
ONBOARDING = {
    'onboarding-managed-file-read': ('onboarding', 'ingestion'),
    'r4a-onboarding-ingestion-compatibility': ('ingestion',),
    'r4a-onboarding-ingestion-compatibility-read': ('ingestion',),
    'r4a-onboarding-ingestion-configuration-read': ('ingestion',),
}
PREFLIGHT = {
    'onboarding-identity-preflight-read': (
        'GET', '/api/udp/v1/governance/internal/identity/preflight', 'ouf.udp.identity.attestation.read',
        'SERVICE', 'M2M', 65536, 10),
}


def bind_quota(route, group, installation):
    limit = route['plugins']['limit-count']
    prefix = 'gateway.rateLimits.' + group + '.'
    limit.update(count=installation(prefix + 'count'), time_window=installation(prefix + 'timeWindowSeconds'))


def module_api_routes(runtime, bindings, semantic_routes, reviewed_routes, clients, secret_ref, installation):
    indexed = {route['id']: route for route in semantic_routes}
    for key in SEMANTIC:
        route = copy.deepcopy(indexed[key])
        route.update(priority=0, status=1)
        # Own quota classes: today's installed values, independent of the THS and MCP families.
        bind_quota(route, 'semanticRestApi', installation)
        yield route, 'ouf-semantic-registry'

    for key, roles in ONBOARDING.items():
        binding = bindings[key]
        allowed = binding['x-ouf-policy']['allowedServiceIdentities']
        if allowed != [clients[role] for role in roles]:
            raise ValueError('unexpected module API workload policy: ' + key)
        if key == 'r4a-onboarding-ingestion-compatibility-read':
            original, = (r for r in reviewed_routes if r['id'] == key)
            route = copy.deepcopy(original)
            route.update(priority=0, status=1)
        else:
            route = materialize_route(binding, runtime['x-ouf-installation'], secret_ref)
        # APISIX risolve i segnaposto JSON. La guardia legge i client dalle label di rotta.
        labels = {'ouf-' + role + '-workload': installation('iam.workloadClients.' + role) for role in roles}
        route['labels'].update(labels)
        route['plugins']['serverless-post-function']['functions'] = [
            workload_guard(labels, ['SERVICE'], service_labels=True)]
        bind_quota(route, 'moduleApiOnboarding', installation)
        yield route, 'ouf-onboarding'

    udp = 'ouf-udp-object-resolution'
    route, = preflight(runtime, secret_ref, udp, specs=PREFLIGHT, service_identity=clients['sourceOnboarding'])['routes']
    route['labels']['ouf-source-onboarding-workload'] = installation('iam.workloadClients.sourceOnboarding')
    bind_quota(route, 'moduleApiPreflight', installation)
    yield route, udp
