"""Materialize the Resolution browser boundary and its two HUMAN UDP routes."""
import json
from pathlib import Path

from tools.materialize_managed_file_ths import materialize as picker
from tools.materialize_onboarding_review import review_page
from tools.materialize_r4a_identity_preflight import materialize as preflight

UDP = 'ouf-udp-object-resolution'
PACKAGE = '/api/udp/v1/governance/resolution/issues/package'
CONFIRM_SCHEMA = Path(__file__).resolve().parents[1] / 'schemas/ths-resolution-package-confirm-v1.json'
PACKAGE_ROUTES = (
    ('ths-identity-preflight-read', 'ths-resolution-package-read', PACKAGE, 'resolution.issue.read', 'GET'),
    ('ths-identity-preflight-create', 'ths-resolution-package-confirm', PACKAGE + '/confirm', 'resolution.match.approve', 'POST'),
)


def retarget(route, route_id, uri, capability, read_timeout):
    route.update(id=route_id, uri=uri)
    route.pop('uris', None)
    route['labels'].update({'ouf-capability': capability, 'ouf-surface': 'TRUSTED_HUMAN_RESOLUTION'})
    route['plugins']['client-control'] = {'max_body_size': 1048576}
    route['upstream']['timeout'] = {'connect': 3, 'send': 3, 'read': read_timeout}


def materialize(runtime, secret_ref):
    """Work on fresh template documents. Only the three derived routes are released."""
    page = review_page(picker(runtime)['routes'][0], 'onboarding')
    if (page['uri'] != '/trusted-human/onboarding/*' or page['methods'] != ['GET', 'POST']
            or 'vars' in page or 'proxy-rewrite' in page['plugins'] or 'openid-connect' in page['plugins']
            or not page['plugins'].get('serverless-pre-function')):
        raise ValueError('expected path-preserving Onboarding session boundary')
    retarget(page, 'trusted-human-resolution-review', '/trusted-human/resolution/*', 'resolution.issue.read', 30)

    host = runtime['x-ouf-installation']['serviceBindings'].get(UDP, UDP)
    templates = {r['id']: r for r in preflight(runtime, secret_ref, host)['routes']}
    routes = []
    for template_id, route_id, path, capability, method in PACKAGE_ROUTES:
        route = templates[template_id]
        plugins = route['plugins']
        oidc = plugins['openid-connect']
        if (route['uri'] != '/api/udp/v1/governance/identity/preflight' or route['methods'] != [method]
                or oidc.get('required_scopes') != ['urban.identity.preflight'] or oidc.get('bearer_only') is not True
                or oidc.get('ssl_verify') is not True or route['upstream']['retries'] != 0
                or not plugins.get('serverless-pre-function') or not plugins.get('serverless-post-function')
                or 'vars' in route or 'filter_func' in route or set(plugins.get('proxy-rewrite', {})) - {'uri'}):
            raise ValueError('unexpected UDP HUMAN preflight boundary: ' + template_id)
        retarget(route, route_id, path, capability, 20)
        oidc['required_scopes'] = [capability]
        if 'proxy-rewrite' in plugins:
            plugins['proxy-rewrite']['uri'] = path
        if method == 'POST':
            plugins.setdefault('request-validation', {})['body_schema'] = json.loads(CONFIRM_SCHEMA.read_bytes())
        routes.append(route)
    routes.append(page)
    for route in routes:
        if any(r['id'] == route['id'] or route['uri'] in r.get('uris', [r.get('uri')]) for r in runtime['routes']):
            raise ValueError('resolution route already bound: ' + route['id'])
    return routes
