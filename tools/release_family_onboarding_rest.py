"""Materialize the HUMAN REST routes owned by Source Onboarding (F5b)."""
from tools.materialize_trusted_human_installation_runtime import materialize as installation_routes
from tools.materialize_trusted_human_onboarding_runtime import materialize_route
from tools.release_family_ths_pages import with_installation_limits


BINDING_IDS = (
    'trusted-human-managed-file-actions-post',
    'trusted-human-managed-file-preview-get',
    'trusted-human-managed-file-upload',
    'trusted-human-onboarding-lifecycle-get',
    'trusted-human-onboarding-lifecycle-post',
    'trusted-human-onboarding-lifecycle-put',
    'trusted-human-onboarding-sources-get',
    'trusted-human-onboarding-sources-post',
)


def materialize(bindings, installation, secret_ref):
    for route_id in BINDING_IDS:
        route = materialize_route(bindings[route_id], installation, secret_ref, streaming_runtime=True)
        # The materializer borrows this plugin from the shared compiled RouteBinding.
        route['plugins']['limit-count'] = route['plugins']['limit-count'].copy()
        if route_id in ('trusted-human-managed-file-actions-post', 'trusted-human-managed-file-upload'):
            # The installed routes use a shorter read timeout than the source bindings.
            route['upstream']['timeout']['read'] = 10
        # Own quota class: same installed value as the approvals today, independent tomorrow.
        yield with_installation_limits(route, 'thsOnboardingRest')

    # The installation namespace has its own HUMAN guard and per-path owner authorization.
    for route in installation_routes(installation, secret_ref)['routes']:
        yield with_installation_limits(route, 'thsInstallation')
