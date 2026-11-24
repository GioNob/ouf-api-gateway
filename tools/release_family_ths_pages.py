"""F5a browser/session routes and HUMAN bearer APIs owned by Onboarding."""
from tools.materialize_managed_file_ths import materialize as picker
from tools.materialize_trusted_human_authorization_runtime import materialize as authorization
from tools.materialize_trusted_human_onboarding_runtime import materialize_route as approval


PAGE_IDS = (
    'trusted-human-onboarding-review', 'trusted-human-semantic-review',
    'authorization-ths-login', 'authorization-ths-page', 'authorization-ths-api',
)
APPROVAL_IDS = ('trusted-human-onboarding-approvals-get', 'trusted-human-onboarding-approvals-post')
ADMIN_IDS = ('trusted-human-authorization-get', 'trusted-human-authorization-post')


def materialize(reviewed, runtime, bindings, secret_ref):
    # The permission materializer supplies the login variant actually installed.
    for route_id in PAGE_IDS:
        route, = (row for row in reviewed['routes'] if row['id'] == route_id)
        yield dict(route, priority=0, status=1)
    managed_picker, _ = picker(runtime)['routes']
    yield managed_picker

    for route_id in APPROVAL_IDS:
        route = approval(bindings[route_id], runtime['x-ouf-installation'], secret_ref)
        route.update(priority=0, status=1)
        yield with_installation_limits(route, 'thsApprovals')
    admin_routes = {route['id']: route for route in authorization(runtime, secret_ref)['routes']}
    for route_id in ADMIN_IDS:
        yield with_installation_limits(admin_routes[route_id], 'thsAuthorization')


def with_installation_limits(route, rate_class):
    # Keep the plugin's existing key and quota-header defaults.
    limits = route['plugins']['limit-count']
    for field, setting in [('count', 'count'), ('time_window', 'timeWindowSeconds')]:
        limits[field] = {'$installation': f'gateway.rateLimits.{rate_class}.{setting}'}
    return route
