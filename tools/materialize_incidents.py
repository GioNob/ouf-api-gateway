"""Closed incident routes layered over status and permission mediation.

Producer adapters must enforce local policy before this profile is activated.
No generic dispatch and no user-supplied upstream are introduced.
"""
import copy
import json
from pathlib import Path
from tools.delegation_functions import function
from tools.materialize_summary import materialize as permission_runtime
ROOT = Path(__file__).resolve().parents[1]
BINDINGS = {
    'ouf.operations.incidents': ('mcp', 'ouf-mcp-server', 8080, 5),
    'ouf.ingestion.operations.incidents': ('ingestion', 'ouf-ingestion-runtime', 8080, 3),
    'ouf.gateway.operations.incidents': ('gateway', 'ouf-gateway-control-plane', 8081, 3),
}

def materialize(runtime, oidc_secret_ref, delegation_key_env, owner_key_env):
    result = permission_runtime(runtime, oidc_secret_ref, delegation_key_env, owner_key_env)
    template = next(r for r in result['routes'] if r['uri'] == '/internal/capabilities/v1/execute')
    schemas = json.loads((ROOT/'schemas/mcp-gateway-incidents-dispatch-v1.json').read_text())['oneOf']
    for cap, (owner, service, port, timeout) in BINDINGS.items():
        matches = [r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == cap and r.get('labels', {}).get('exposure') == 'internal']
        if len(matches) != 1:
            raise ValueError('exact incident binding required: '+cap)
        binding = matches[0]; policy = binding['x-ouf-policy']; descriptor = binding['x-ouf-capability']
        path = '/api/internal/v1/'+owner+'/operations/incidents'
        if (binding['service_id'] != service or binding['plugins']['proxy-rewrite']['uri'] != path
            or descriptor['owner'] != owner or descriptor['operationType'] != 'READ'
            or descriptor.get('humanRequired') or policy['identity'] != 'M2M'
            or policy['requiredScope'] != 'operations.incident.read'
            or runtime['x-ouf-installation']['mcpServiceIdentity'] not in policy['allowedServiceIdentities']
            or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != timeout
            or policy['allowedActorTypes'] != ['HUMAN']):
            raise ValueError('incident binding mismatch: '+cap)
        route = copy.deepcopy(template)
        route.update(id='execute-'+cap, uri='/internal/capabilities/v1/execute/'+cap)
        route['labels']['ouf-mediation'] = 'incidents-execute-v1'
        route['plugins']['request-validation']['body_schema'] = next(s for s in schemas if s['properties']['CapabilityID']['const'] == cap)
        route['plugins']['serverless-post-function']['functions'] = [function('execute_incidents', runtime['x-ouf-installation'], delegation_key_env)]
        route['plugins']['proxy-rewrite']['uri'] = path
        route['upstream']['nodes'] = {service+':'+str(port): 1}
        route['upstream']['timeout'] = dict(connect=timeout, send=timeout, read=timeout)
        result['routes'].append(route)
    return result

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--oidc-client-secret-ref', required=True)
    p.add_argument('--delegation-key-env', required=True)
    p.add_argument('--owner-key-env', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text()), a.oidc_client_secret_ref, a.delegation_key_env, a.owner_key_env), indent=2)+'\n')
