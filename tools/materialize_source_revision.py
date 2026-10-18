"""Add exact generic revision routes; retain every existing route and native HUMAN boundary."""
import copy
import json
from pathlib import Path
from tools.delegation_functions import function

ROOT = Path(__file__).resolve().parents[1]
MODES = {'prepare': ('ouf.onboarding.revision.prepare', 'COMMAND', 10),
         'read': ('ouf.onboarding.revision.read', 'READ', 3)}


def materialize(existing, runtime, delegation_key_env, owner_key_env):
    if delegation_key_env == owner_key_env:
        raise ValueError('distinct delegation and owner signing keys required')
    result = copy.deepcopy(existing)
    templates = [r for r in result['routes'] if r.get('uri') == '/internal/capabilities/v1/execute']
    if len(templates) != 1 or any(name not in templates[0].get('plugins', {}) for name in
            ('openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function')):
        raise ValueError('one authenticated bounded execute template required')
    human = [r for r in result['routes'] if r.get('id') == 'trusted-human-onboarding-review']
    if (len(human) != 1 or human[0].get('uri') != '/trusted-human/onboarding/*'
            or human[0].get('upstream', {}).get('nodes') != {'ouf-onboarding:8080': 1}):
        raise ValueError('existing native HUMAN review required')
    installation = runtime['x-ouf-installation']
    for mode, (cap, operation, timeout) in MODES.items():
        route_id = 'mcp-source-revision-'+mode
        matches = [r for r in runtime['routes'] if r.get('id') == route_id]
        if len(matches) != 1:
            raise ValueError('exact source revision binding required')
        binding = matches[0]
        policy, capability = binding['x-ouf-policy'], binding['x-ouf-capability']
        uri = '/internal/capabilities/v1/execute/source.revision/'+mode
        path = '/api/internal/v1/onboarding/source-revision-mcp/'+mode
        if (binding.get('uri') != uri or binding.get('methods') != ['POST']
                or binding.get('service_id') != 'ouf-onboarding'
                or binding['x-ouf-backend-binding'] != {'service': 'ouf-onboarding', 'port': 8080, 'path': path}
                or binding['plugins']['proxy-rewrite']['uri'] != path
                or capability['capabilityId'] != cap or capability['owner'] != 'onboarding'
                or capability['operationType'] != operation or capability.get('humanRequired') or not capability.get('toolEligible')
                or policy['identity'] != 'M2M' or policy['requiredScope'] != cap
                or policy['allowedActorTypes'] != ['HUMAN']
                or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
                or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != timeout):
            raise ValueError('source revision binding mismatch')
        route = copy.deepcopy(templates[0]);route.update(id=route_id, uri=uri, methods=['POST'])
        route['labels']['ouf-mediation'] = 'source-revision-v1'
        route['plugins']['request-validation'] = {'max_req_body_size': 65536,
            'body_schema': json.loads((ROOT/f'schemas/mcp-gateway-source-revision-{mode}-dispatch-v1.json').read_text())}
        route['plugins']['serverless-post-function'] = {'phase': 'access', 'functions': [
            function('execute_source_revision', installation, delegation_key_env, owner_key_env)]}
        route['plugins']['proxy-rewrite'] = {'uri': path}
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {'ouf-onboarding:8080': 1},
            'retries': 0, 'timeout': {'connect': 3, 'send': timeout, 'read': timeout}}
        if any(r.get('id') == route_id or (r.get('uri') == uri and 'POST' in r.get('methods', [])) for r in result['routes']):
            raise ValueError('revision route already exists; reconcile before materialization')
        result['routes'].append(route)
    return result
