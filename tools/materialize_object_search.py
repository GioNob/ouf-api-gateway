"""Layer one closed UDP search route over the established MCP mediation profile."""
import argparse
import copy
import json
import re
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_incidents import materialize as existing_runtime

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY = 'urban.object.search'
PATH = '/api/udp/v1/objects/search'


def materialize(runtime, oidc_secret_ref, delegation_key_env, owner_key_env, udp_key_env):
    if len({delegation_key_env, owner_key_env, udp_key_env}) != 3 or not isinstance(udp_key_env,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',udp_key_env):
        raise ValueError('three distinct named signing keys required')
    result = existing_runtime(runtime, oidc_secret_ref, delegation_key_env, owner_key_env)
    matches = [r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == CAPABILITY and r.get('labels', {}).get('exposure') == 'internal']
    if len(matches) != 1:
        raise ValueError('exact UDP search binding required')
    binding = matches[0]
    p, cap = binding['x-ouf-policy'], binding['x-ouf-capability']
    if (binding['service_id'] != 'ouf-udp-object-resolution'
        or binding['plugins']['proxy-rewrite']['uri'] != PATH
        or binding['methods'] != ['POST']
        or cap['owner'] != 'udp' or cap['operationType'] != 'SEARCH'
        or not cap.get('toolEligible') or cap.get('humanRequired')
        or p['identity'] != 'M2M' or p['requiredScope'] != CAPABILITY
        or p['allowedActorTypes'] != ['HUMAN']
        or runtime['x-ouf-installation']['mcpServiceIdentity'] not in p['allowedServiceIdentities']
        or p['maxRequestBytes'] != 65536 or p['timeoutSeconds'] != 3):
        raise ValueError('UDP search binding mismatch')
    template = next(r for r in result['routes'] if r['uri'] == '/internal/capabilities/v1/execute')
    route = copy.deepcopy(template)
    route.update(id='execute-urban-object-search', uri='/internal/capabilities/v1/execute/urban.object.search')
    route['labels']['ouf-mediation'] = 'udp-search-execute-v1'
    route['plugins']['request-validation']['body_schema'] = json.loads((ROOT/'schemas/mcp-gateway-object-search-dispatch-v1.json').read_text())
    route['plugins']['serverless-post-function']['functions'] = [function('execute_object_search', runtime['x-ouf-installation'], delegation_key_env, udp_key_env)]
    route['plugins']['proxy-rewrite']['uri'] = PATH
    route['upstream']['nodes'] = {'ouf-udp-object-resolution:8080': 1}
    result['routes'].append(route)
    result['udpOwnerKeyEnv'] = udp_key_env
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--oidc-client-secret-ref', required=True)
    parser.add_argument('--delegation-key-env', required=True)
    parser.add_argument('--owner-key-env', required=True)
    parser.add_argument('--udp-key-env', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(materialize(json.loads(args.runtime.read_text()), args.oidc_client_secret_ref, args.delegation_key_env, args.owner_key_env, args.udp_key_env), indent=2)+'\n')
