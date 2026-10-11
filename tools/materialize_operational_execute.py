"""Closed operational mediation: fixed reviewed owners, no arbitrary proxy."""
import argparse
import copy
import json
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_apisix_execute_runtime import materialize as status_runtime

ROOT = Path(__file__).resolve().parents[1]
CAPABILITIES = {
    'ouf.operations.summary': ('mcp', 'ouf-mcp-server', 8080, '/api/internal/v1/mcp/operations/summary', 'operations.status.read', 5),
    'ouf.operations.incidents': ('mcp', 'ouf-mcp-server', 8080, '/api/internal/v1/mcp/operations/incidents', 'operations.incident.read', 5),
    'ouf.ingestion.operations.summary': ('ingestion', 'ouf-ingestion-runtime', 8080, '/api/internal/v1/ingestion/operations/summary', 'operations.status.read', 3),
    'ouf.ingestion.operations.incidents': ('ingestion', 'ouf-ingestion-runtime', 8080, '/api/internal/v1/ingestion/operations/incidents', 'operations.incident.read', 3),
    'ouf.gateway.operations.summary': ('gateway', 'ouf-gateway-control-plane', 8081, '/api/internal/v1/gateway/operations/summary', 'operations.status.read', 3),
    'ouf.gateway.operations.incidents': ('gateway', 'ouf-gateway-control-plane', 8081, '/api/internal/v1/gateway/operations/incidents', 'operations.incident.read', 3),
}

def dispatch_schema(capability):
    owner, _, _, _, _, _ = CAPABILITIES[capability]
    schema = json.loads((ROOT / 'schemas/mcp-gateway-status-dispatch-v1.json').read_text())
    fields = schema['properties']
    fields['CapabilityID'] = {'const': capability}
    fields['GatewayBindingRef'] = {'const': 'capability://' + capability}
    fields['Owner'] = {'const': owner}
    fields['MaxResultBytes']['maximum'] = 512 * 1024
    query = {'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
             'since': {'type': 'string', 'format': 'date-time', 'maxLength': 100,
                       'pattern': r'^.+T.+(Z|[+-][0-9]{2}:[0-9]{2})$'}}
    if owner != 'gateway': query['sourceId'] = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    incidents = capability.endswith('.incidents')
    if incidents: query['state'] = {'enum': ['OPEN', 'RECOVERING', 'RESOLVED']}
    regular = {'type': 'object', 'additionalProperties': False, 'properties': query}
    if owner != 'mcp' and incidents:
        query['snapshot'] = {'enum': [True]}
        fields['Arguments'] = {'oneOf': [regular, {'type': 'object', 'additionalProperties': False,
            'required': ['cursor'], 'properties': {'cursor': {'type': 'string', 'format': 'uuid',
            'pattern': r'^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'}}}]}
    else: fields['Arguments'] = regular
    return schema

def materialize(runtime, oidc_secret_ref, delegation_key_env, owner_key_env=None):
    if owner_key_env is None:
        result = status_runtime(runtime, oidc_secret_ref, delegation_key_env)
    else:
        from tools.materialize_permission_proposals import materialize as permission_runtime
        result = permission_runtime(runtime, oidc_secret_ref, delegation_key_env, owner_key_env)
    installation = runtime['x-ouf-installation']
    workload = installation['mcpServiceIdentity']
    template = next(r for r in result['routes'] if r.get('uri') == '/internal/capabilities/v1/execute')
    for capability, (owner, service, port, path, scope, timeout) in CAPABILITIES.items():
        candidates = [r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == capability and r.get('labels', {}).get('exposure') == 'internal']
        if len(candidates) != 1: raise ValueError('exact operational binding required: ' + capability)
        binding = candidates[0]
        cap, policy = binding['x-ouf-capability'], binding['x-ouf-policy']
        actors = ['HUMAN_USER', 'MCP_SERVER'] if owner == 'mcp' else ['MCP_SERVER']
        if (cap['owner'] != owner or cap['operationType'] != 'READ' or cap.get('humanRequired') or cap.get('toolEligible') != (owner == 'mcp')
            or binding['service_id'] != service or binding['plugins']['proxy-rewrite']['uri'] != path
            or policy['identity'] != 'M2M' or policy['allowedServiceIdentities'] != [workload]
            or policy['allowedActorTypes'] != actors or policy['requiredScope'] != scope
            or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != timeout):
            raise ValueError('operational binding drift: ' + capability)
        route = copy.deepcopy(template)
        route['id'] = 'operational-execute-' + capability.replace('.', '-')
        route['uri'] = '/internal/capabilities/v1/execute/' + capability
        route['labels']['ouf-mediation'] = 'operational-execute-v1'
        route['plugins']['request-validation']['body_schema'] = dispatch_schema(capability)
        route['plugins']['serverless-post-function']['functions'] = [function('execute_operational', installation, delegation_key_env,
            operational_binding={'capability': capability, 'owner': owner, 'scope': scope})]
        route['plugins']['proxy-rewrite']['uri'] = path
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {f'{service}:{port}': 1},
            'retries': 0, 'timeout': {'connect': timeout, 'send': timeout, 'read': timeout}}
        result['routes'].append(route)
    result['operationalExecuteProfile'] = 'ouf.operational-execute.v1'
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--oidc-client-secret-ref', required=True)
    parser.add_argument('--delegation-key-env', required=True)
    parser.add_argument('--owner-key-env')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = materialize(json.loads(args.runtime.read_text()), args.oidc_client_secret_ref, args.delegation_key_env, args.owner_key_env)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
