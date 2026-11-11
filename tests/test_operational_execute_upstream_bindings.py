"""Installation projection and unchanged operational route contract."""
import copy
import json
from functools import lru_cache

import pytest

from tools.apply_installation_projection import apply_projection
from tools.compile_config import ROOT, compile_config
from tools.delegation_functions import function
from tools.materialize_apisix_execute_runtime import materialize as status_runtime
from tools.materialize_operational_execute import CAPABILITIES, dispatch_schema, materialize


SERVICES = ('ouf-mcp-server', 'ouf-ingestion-runtime', 'ouf-gateway-control-plane')
IDENTITY = {service: service for service in SERVICES}
INSTALLATIONS = [
    dict(zip(SERVICES, ('mcp-alpha', 'ouf-ingestion', 'control-alpha'))),
    dict(zip(SERVICES, ('mcp.beta.internal', 'ingestion.beta.internal', 'control.beta.internal'))),
]


@lru_cache(maxsize=1)
def compiled_config():
    return compile_config(ROOT / 'ouf-config')


def runtime(bindings):
    projection = json.loads((ROOT / 'tests/fixtures/installation-projection-lab.json').read_text())
    projection['services']['bindings'].update(bindings)
    return apply_projection(compiled_config(), projection)


def operational_routes(document):
    return {route['uri']: route for route in document['routes']
            if route.get('labels', {}).get('ouf-mediation') == 'operational-execute-v1'}


def before_change_identity_output(rt):
    """Reference construction from bf179e9, before installation host resolution.

    Keep the original route construction here to compare complete output,
    including inherited plugins, schemas, functions and upstream settings.
    """
    result = status_runtime(rt, '$ENV://OIDC', 'DELEGATION_KEY')
    template = next(r for r in result['routes'] if r.get('uri') == '/internal/capabilities/v1/execute')
    for capability, (owner, service, port, path, scope, timeout) in CAPABILITIES.items():
        route = copy.deepcopy(template)
        route['id'] = 'operational-execute-' + capability.replace('.', '-')
        route['uri'] = '/internal/capabilities/v1/execute/' + capability
        route['labels']['ouf-mediation'] = 'operational-execute-v1'
        route['plugins']['request-validation']['body_schema'] = dispatch_schema(capability)
        route['plugins']['serverless-post-function']['functions'] = [function(
            'execute_operational', rt['x-ouf-installation'], 'DELEGATION_KEY',
            operational_binding={'capability': capability, 'owner': owner, 'scope': scope})]
        route['plugins']['proxy-rewrite']['uri'] = path
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {f'{service}:{port}': 1},
                             'retries': 0, 'timeout': {'connect': timeout, 'send': timeout, 'read': timeout}}
        result['routes'].append(route)
    result['operationalExecuteProfile'] = 'ouf.operational-execute.v1'
    return result


def test_identity_bindings_preserve_complete_pre_change_output():
    rt = runtime(IDENTITY)
    original = copy.deepcopy(rt)
    assert materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY') == before_change_identity_output(rt)
    assert rt == original


@pytest.mark.parametrize('bindings', INSTALLATIONS)
def test_two_installations_change_only_operational_upstream_nodes(bindings):
    identity = operational_routes(materialize(runtime(IDENTITY), '$ENV://OIDC', 'DELEGATION_KEY'))
    rt = runtime(bindings)
    original = copy.deepcopy(rt)
    routes = operational_routes(materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY'))
    assert len(routes) == 6
    assert routes.keys() == identity.keys()
    for capability, (_, service, port, _, _, _) in CAPABILITIES.items():
        uri = '/internal/capabilities/v1/execute/' + capability
        source = next(r for r in rt['routes']
                      if (r.get('x-ouf-capability') or {}).get('capabilityId') == capability
                      and r.get('labels', {}).get('exposure') == 'internal')
        assert source['service_id'] == service
        assert source['x-ouf-backend-binding']['service'] == bindings[service]
        assert routes[uri]['upstream']['nodes'] == {f'{bindings[service]}:{port}': 1}
        normalized = copy.deepcopy(routes[uri])
        normalized['upstream']['nodes'] = identity[uri]['upstream']['nodes']
        assert normalized == identity[uri]
    assert rt == original


def test_projection_identity_default_is_preserved_for_omitted_bindings():
    # apply_projection only rewrites services explicitly present in its map.
    assert materialize(runtime({}), '$ENV://OIDC', 'DELEGATION_KEY') == materialize(
        runtime(IDENTITY), '$ENV://OIDC', 'DELEGATION_KEY')


@pytest.mark.parametrize('service', SERVICES)
def test_missing_binding_for_projected_backend_fails_explicitly(service):
    rt = runtime(INSTALLATIONS[0])
    del rt['x-ouf-installation']['serviceBindings'][service]
    with pytest.raises(ValueError, match='missing installation service binding: ' + service):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')


@pytest.mark.parametrize('bindings', [None, '', [], 42])
def test_invalid_installation_bindings_map_fails_explicitly(bindings):
    rt = runtime(IDENTITY)
    rt['x-ouf-installation']['serviceBindings'] = bindings
    with pytest.raises(ValueError, match='missing or invalid installation serviceBindings'):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')


def test_missing_installation_bindings_map_fails_explicitly():
    rt = runtime(IDENTITY)
    del rt['x-ouf-installation']['serviceBindings']
    with pytest.raises(ValueError, match='missing or invalid installation serviceBindings'):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')


@pytest.mark.parametrize('service', SERVICES)
@pytest.mark.parametrize('host', ['', '  ', None, False, 8080, {}, [],
                                 'http://backend', 'backend:8080', 'backend/path', 'bad host'])
def test_invalid_service_binding_fails_explicitly(service, host):
    rt = runtime(IDENTITY)
    rt['x-ouf-installation']['serviceBindings'][service] = host
    with pytest.raises(ValueError, match='invalid installation service binding: ' + service):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')


def test_service_binding_whitespace_matches_projection_normalization():
    bindings = {service: '  ' + host + '  ' for service, host in INSTALLATIONS[0].items()}
    assert materialize(runtime(bindings), '$ENV://OIDC', 'DELEGATION_KEY') == materialize(
        runtime(INSTALLATIONS[0]), '$ENV://OIDC', 'DELEGATION_KEY')


@pytest.mark.parametrize('capability', CAPABILITIES)
@pytest.mark.parametrize('change', ['service-id', 'backend-service', 'missing-backend',
                                  'owner', 'operation', 'path', 'identity', 'scope',
                                  'timeout', 'workload', 'actor', 'request-size',
                                  'human-required', 'tool-eligible'])
def test_projected_routes_still_reject_contract_drift(capability, change):
    rt = runtime(INSTALLATIONS[0])
    target = next(r for r in rt['routes']
                  if (r.get('x-ouf-capability') or {}).get('capabilityId') == capability
                  and r.get('labels', {}).get('exposure') == 'internal')
    cap, policy = target['x-ouf-capability'], target['x-ouf-policy']
    if change == 'service-id':
        # A projected host must not replace the logical contract identifier.
        target['service_id'] = target['x-ouf-backend-binding']['service']
    elif change == 'backend-service': target['x-ouf-backend-binding']['service'] = 'other-backend'
    elif change == 'missing-backend': del target['x-ouf-backend-binding']
    elif change == 'owner': cap['owner'] = 'other'
    elif change == 'operation': cap['operationType'] = 'COMMAND'
    elif change == 'path': target['plugins']['proxy-rewrite']['uri'] = '/other'
    elif change == 'identity': policy['identity'] = 'OIDC'
    elif change == 'scope': policy['requiredScope'] = 'other'
    elif change == 'timeout': policy['timeoutSeconds'] = 100
    elif change == 'workload': policy['allowedServiceIdentities'] = ['other-workload']
    elif change == 'actor': policy['allowedActorTypes'] = ['HUMAN']
    elif change == 'request-size': policy['maxRequestBytes'] = 1
    elif change == 'human-required': cap['humanRequired'] = True
    elif change == 'tool-eligible': cap['toolEligible'] = not cap['toolEligible']
    with pytest.raises(ValueError):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')
