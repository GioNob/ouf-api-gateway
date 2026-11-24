"""Release the owner-facing HUMAN APIs from RouteBindings and installed recovery contracts."""
from tools.materialize_r4a_identity_preflight import materialize as preflight


SEMANTIC_IDS = {'semantic-human-card', 'semantic-human-decision', 'semantic-human-publish'}
READINESS_ID = 'trusted-human-ingestion-onboarding-readiness'
PREFLIGHT_IDS = {'ths-identity-preflight-read', 'ths-identity-preflight-create'}

QUARANTINE = '/api/trusted-human/v1/ingestion/quarantine/'
JOBS = '/api/udp/v1/governance/materialization/jobs/'
UUID = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
RECOVERY = (
    ('r4a-ingestion-human-quarantine-read', QUARANTINE, 'GET', '', 'ingestion.quarantine.read'),
    ('r4a-ingestion-human-quarantine-retry', QUARANTINE, 'POST', '/retry', 'ouf.ingestion.quarantine.retry'),
    ('r4a-udp-human-materialization-review', JOBS, 'GET', '', 'udp.materialization.retry'),
    ('r4a-udp-human-materialization-retry', JOBS, 'POST', '/retry', 'udp.materialization.retry'),
)

# APISIX compares the complete plugin bodies, including Lua source.
STRIP_HEADERS = (
    "return function(conf, ctx) local headers=ngx.req.get_headers(0,true); for name,_ in pairs(headers) do "
    "if string.lower(name):sub(1,6)=='x-ouf-' then ngx.req.clear_header(name) end end end"
)
REQUIRE_HUMAN = (
    "return function(conf, ctx) local cjson=require('cjson.safe'); local auth=ngx.var.http_authorization; "
    "local token=auth and auth:match('^[Bb]earer%s+(.+)$'); local part=token and token:match('^[^.]+%.([^.]+)%.[^.]+$'); "
    "if not part then return ngx.exit(401) end; part=part:gsub('-','+'):gsub('_','/'); local rem=#part%4; "
    "if rem>0 then part=part..string.rep('=',4-rem) end; local raw=ngx.decode_base64(part); "
    "local claims=raw and cjson.decode(raw); if type(claims)~='table' then return ngx.exit(401) end; "
    "local actor=claims['ouf_actor_type']; if actor~='HUMAN' and actor~='HUMAN_USER' then return ngx.exit(403) end; end"
)


def recovery_resources(installation):
    """Materialize the four recovery routes directly from their installed specification."""
    for route_id, path, method, suffix, scope in RECOVERY:
        if path == JOBS:
            service = 'ouf-udp-object-resolution'
            selectors = {'host': installation('gateway.publicApiHost')}
            description = 'Governed HUMAN recovery; owner authorization retained'
        else:
            service = 'ouf-ingestion-runtime'
            selectors = {}
            description = 'Governed HUMAN recovery; exact UUID action; owner authorization retained'
        quota = 'gateway.rateLimits.thsIngestionReadiness.'
        body = {
            'name': route_id, 'desc': description, 'status': 1, **selectors,
            'methods': [method], 'uri': path + '*', 'vars': [['uri', '~~', '^' + path + UUID + suffix + '$']],
            'plugins': {
                'request-id': {'algorithm': 'uuid', 'header_name': 'X-Correlation-ID', 'include_in_response': True},
                'limit-count': {'count': installation(quota + 'count'), 'rejected_code': 429,
                                'time_window': installation(quota + 'timeWindowSeconds')},
                'openid-connect': {
                    'bearer_only': True, 'unauth_action': 'deny', 'use_jwks': True, 'ssl_verify': True,
                    'claim_validator': {'audience': {'required': True, 'match_with_client_id': True}},
                    'client_id': installation('gateway.requiredAudience'),
                    'client_secret': installation('gateway.oidcClientSecretRef'),
                    'discovery': installation('caddy.oidcDiscoveryUrl'), 'required_scopes': [scope],
                },
                'serverless-pre-function': {'phase': 'rewrite', 'functions': [STRIP_HEADERS]},
                'serverless-post-function': {'phase': 'access', 'functions': [REQUIRE_HUMAN]},
            },
            'upstream': {'type': 'roundrobin', 'scheme': 'http',
                         'nodes': [{'host': installation('services.bindings.' + service),
                                    'port': installation('services.ports.' + service), 'weight': 1}]},
        }
        yield {'kind': 'routes', 'id': route_id, 'body': body}


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
