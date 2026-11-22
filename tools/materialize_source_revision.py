"""Materialize the governed source revision prepare route against the native HUMAN backend."""
import copy
import json
from pathlib import Path

from tools.apisix_request_schema import inline_dispatch_schema
from tools.delegation_functions import function
from tools.materialize_operational_execute import operational_host

ROOT = Path(__file__).resolve().parents[1]


def materialize(existing, runtime, delegation_key_env, owner_key_env, *, use_route_labels=False):
    if delegation_key_env == owner_key_env:
        raise ValueError('distinct delegation and owner signing keys required')
    result = copy.deepcopy(existing)
    templates = [r for r in result['routes'] if r.get('uri') == '/internal/capabilities/v1/execute']
    required_plugins = {'openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function'}
    if (len(templates) != 1 or templates[0].get('methods') != ['POST']
            or not required_plugins.issubset(templates[0].get('plugins', {}))):
        raise ValueError('one authenticated bounded execute template required')
    human = [r for r in result['routes'] if r.get('id') == 'trusted-human-onboarding-review']
    if len(human) != 1 or human[0].get('uri') != '/trusted-human/onboarding/*':
        raise ValueError('existing native HUMAN review required')
    installation = runtime['x-ouf-installation']
    cap = 'ouf.onboarding.revision.prepare'
    route_id = 'mcp-source-revision-prepare'
    matches = [r for r in runtime['routes'] if r.get('id') == route_id]
    if len(matches) != 1:
        raise ValueError('exact source revision binding required')
    binding = matches[0]
    policy, capability = binding['x-ouf-policy'], binding['x-ouf-capability']
    # service_id is the logical owner. Projection resolves the physical host.
    host = operational_host(installation, binding, 'ouf-onboarding')
    backend = binding['x-ouf-backend-binding']
    port = backend.get('port')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid source revision backend port')
    nodes = {f'{host}:{port}': 1}
    if nodes != human[0].get('upstream', {}).get('nodes'):
        raise ValueError('native HUMAN review backend mismatch')
    uri = '/internal/capabilities/v1/execute/source.revision/prepare'
    path = '/api/internal/v1/onboarding/source-revision-mcp/prepare'
    if (binding.get('uri') != uri or binding.get('methods') != ['POST']
            or binding.get('service_id') != 'ouf-onboarding'
            or backend != {'service': host, 'port': port, 'path': path}
            or binding['plugins']['proxy-rewrite']['uri'] != path
            or capability['capabilityId'] != cap or capability['owner'] != 'onboarding'
            or capability['operationType'] != 'COMMAND' or capability.get('humanRequired') is not False
            or capability.get('toolEligible') is not True
            or policy['identity'] != 'M2M' or policy['requiredScope'] != cap
            or policy['allowedActorTypes'] != ['HUMAN']
            or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
            or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != 10):
        raise ValueError('source revision binding mismatch')
    route = copy.deepcopy(templates[0])
    route.update(id=route_id, uri=uri, methods=['POST'])
    route['labels']['ouf-mediation'] = 'source-revision-v1'
    schema = ROOT / 'schemas/mcp-gateway-source-revision-prepare-dispatch-v1.json'
    route['plugins']['request-validation'] = {
        'max_req_body_size': 65536,
        'body_schema': inline_dispatch_schema(json.loads(schema.read_bytes())),
        'rejected_msg': 'INVALID_TOOL_ARGUMENTS',
    }
    route['plugins']['client-control'] = {'max_body_size': 65536}
    route['plugins']['serverless-post-function'] = {'phase': 'access', 'functions': [
        function('execute_source_revision', installation, delegation_key_env, owner_key_env,
                 use_route_labels=use_route_labels)]}
    route['plugins']['proxy-rewrite'] = {'uri': path}
    route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': nodes,
        'retries': 0, 'timeout': {'connect': 3, 'send': 10, 'read': 10}}
    if any(r.get('id') == route_id or ((r.get('uri') == uri or uri in r.get('uris', []))
           and (not r.get('methods') or 'POST' in r['methods'])) for r in result['routes']):
        raise ValueError('revision route already exists; reconcile before materialization')
    result['routes'].append(route)
    return result
