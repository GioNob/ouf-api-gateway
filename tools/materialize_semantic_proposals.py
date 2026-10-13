"""Closed native semantic proposal mediation. No approval/publication proxy."""
import argparse
import copy
import json
from pathlib import Path
from tools.materialize_operational_execute import materialize as operational_runtime
from tools.delegation_functions import function

ROOT = Path(__file__).resolve().parents[1]
CAPABILITIES = {
    'ouf.semantic.propose': ('create', 'COMMAND', 'ouf.semantic.propose'),
    'ouf.semantic.review.prepare': ('validate', 'COMMAND', 'ouf.semantic.review.prepare'),
    'ouf.semantic.approval.request': ('review', 'COMMAND', 'ouf.semantic.approval.request'),
    'ouf.semantic.proposal.read': ('read', 'READ', 'ouf.semantic.propose'),
}

def materialize(runtime, oidc_secret_ref, delegation_key_env, semantic_owner_key_env, authorization_owner_key_env=None):
    result = operational_runtime(runtime, oidc_secret_ref, delegation_key_env, authorization_owner_key_env)
    template = next(r for r in result['routes'] if r['uri'] == '/internal/capabilities/v1/execute')
    schemas = json.loads((ROOT/'schemas/mcp-gateway-semantic-proposals-v1.json').read_text())['oneOf']
    installation = runtime['x-ouf-installation']
    for cap, (mode, operation, scope) in CAPABILITIES.items():
        candidates = [r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == cap
                      and r.get('labels', {}).get('exposure') == 'internal']
        if len(candidates) != 1:
            raise ValueError('exact semantic proposal binding required: '+cap)
        binding = candidates[0]
        p, c = binding['x-ouf-policy'], binding['x-ouf-capability']
        path = '/api/semantic/v1/proposal-commands/'+mode
        if (binding['service_id'] != 'ouf-semantic-registry' or binding['plugins']['proxy-rewrite']['uri'] != path
            or c['owner'] != 'semantic' or c['operationType'] != operation or c.get('humanRequired') or not c.get('toolEligible')
            or p['identity'] != 'M2M' or p['requiredScope'] != scope
            or p['allowedActorTypes'] != ['HUMAN', 'AI_AGENT', 'SERVICE']
            or p['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
            or p['maxRequestBytes'] != 65536 or p['timeoutSeconds'] != 3):
            raise ValueError('semantic proposal binding mismatch: '+cap)
        route = copy.deepcopy(template)
        route['id'] = 'semantic-proposal-'+mode
        route['uri'] = '/internal/capabilities/v1/execute/semantic/'+mode
        route['labels']['ouf-mediation'] = 'semantic-proposal-v1'
        route['plugins']['request-validation']['body_schema'] = next(s for s in schemas if s['properties']['CapabilityID']['const'] == cap)
        route['plugins']['serverless-post-function']['functions'] = [function('execute_semantic_proposals', installation,
            delegation_key_env, semantic_owner_key_env, operational_binding={'capability': cap, 'owner': 'semantic', 'scope': scope})]
        route['plugins']['proxy-rewrite']['uri'] = path
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {'ouf-semantic-registry:8080': 1},
                             'retries': 0, 'timeout': {'connect': 3, 'send': 3, 'read': 3}}
        result['routes'].append(route)
    result['semanticProposalProfile'] = 'ouf.semantic-proposal-channel.v1'
    result['semanticProposalOwnerKeyEnv'] = semantic_owner_key_env
    return result

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--oidc-client-secret-ref', required=True)
    p.add_argument('--delegation-key-env', required=True)
    p.add_argument('--semantic-owner-key-env', required=True)
    p.add_argument('--authorization-owner-key-env')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text()), a.oidc_client_secret_ref,
        a.delegation_key_env, a.semantic_owner_key_env, a.authorization_owner_key_env), indent=2)+'\n')
