"""Release the owner-facing HUMAN APIs from their validated RouteBindings."""
from tools.materialize_r4a_identity_preflight import materialize as preflight


SEMANTIC_IDS = {'semantic-human-card', 'semantic-human-decision', 'semantic-human-publish'}
READINESS_ID = 'trusted-human-ingestion-onboarding-readiness'
PREFLIGHT_IDS = {'ths-identity-preflight-read', 'ths-identity-preflight-create'}


def owner_routes(runtime, secret_ref, semantic_routes, review_routes):
    """Keep each installed plugin shape, including the implicit limit-count key."""
    udp_service = 'ouf-udp-object-resolution'
    udp = preflight(runtime, secret_ref, udp_service)['routes']
    for routes, ids, service, quota in (
        (semantic_routes, SEMANTIC_IDS, 'ouf-semantic-registry', 'thsSemantic'),
        (review_routes, {READINESS_ID}, 'ouf-ingestion-runtime', 'thsIngestionReadiness'),
        (udp, PREFLIGHT_IDS, udp_service, 'thsIdentityPreflight'),
    ):
        for route_id in sorted(ids):
            route, = (r for r in routes if r['id'] == route_id)
            prefix = 'gateway.rateLimits.' + quota
            limit = dict(route['plugins']['limit-count'],
                         count={'$installation': prefix + '.count'},
                         time_window={'$installation': prefix + '.timeWindowSeconds'})
            body = dict(route, plugins={**route['plugins'], 'limit-count': limit})
            if route_id not in PREFLIGHT_IDS:
                body.update(priority=0, status=1)
            yield body, service
