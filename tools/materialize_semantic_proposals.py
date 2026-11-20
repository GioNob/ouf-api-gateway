"""Closed native semantic proposal mediation. No approval/publication proxy."""
import argparse
import copy
import json
from pathlib import Path
from tools.materialize_operational_execute import materialize as operational_runtime, operational_host
from tools.delegation_functions import function

ROOT = Path(__file__).resolve().parents[1]
# request-validation can rewrite the JSON body between rewrite and access.
CAPTURE_ENVELOPE = """return function(conf, ctx)
    local body = require('apisix.core').request.get_body(65536)
    if not body or #body > 65536 then return ngx.exit(413) end
    ctx.ouf_semantic_envelope = body
end"""
CAPABILITIES = {
    'ouf.semantic.propose': ('create', 'COMMAND', 'ouf.semantic.propose'),
    'ouf.semantic.review.prepare': ('validate', 'COMMAND', 'ouf.semantic.review.prepare'),
    'ouf.semantic.approval.request': ('review', 'COMMAND', 'ouf.semantic.approval.request'),
    'ouf.semantic.proposal.read': ('read', 'READ', 'ouf.semantic.proposal.read'),
    'ouf.semantic.discovery.adopt': ('adopt', 'COMMAND', 'ouf.semantic.discovery'),
}

def materialize(runtime, oidc_secret_ref, delegation_key_env, semantic_owner_key_env, authorization_owner_key_env=None):
    if authorization_owner_key_env is None:
        raise ValueError('existing authorization owner key environment required to preserve THS routes')
    result = operational_runtime(runtime, oidc_secret_ref, delegation_key_env, authorization_owner_key_env)
    return add_to_existing(result, runtime, delegation_key_env, semantic_owner_key_env)


def add_to_existing(existing, runtime, delegation_key_env, semantic_owner_key_env, *, adoption_only=False,
                    use_route_labels=False):
    """Append the reviewed proposal routes without replacing live routes.

    The caller supplies the retained materialized installation and its current
    projected route declarations. Deployment still owns publication and authority.
    A collision requires reconciliation; it never silently replaces a route.
    """
    if delegation_key_env == semantic_owner_key_env:
        raise ValueError('distinct delegation and semantic owner signing keys required')
    if adoption_only and (existing.get('semanticProposalOwnerKeyEnv', semantic_owner_key_env) != semantic_owner_key_env
                          or existing.get('delegationKeyEnv', delegation_key_env) != delegation_key_env):
        raise ValueError('retained proposal key binding mismatch')
    result = copy.deepcopy(existing)
    templates = [r for r in result['routes'] if r.get('uri') == '/internal/capabilities/v1/execute']
    if len(templates) != 1:
        raise ValueError('one established execute template required')
    template = templates[0]
    if any(name not in template.get('plugins', {}) for name in
           ('openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function', 'serverless-post-function')):
        raise ValueError('authenticated bounded execute template required')
    if (template['plugins']['serverless-pre-function']['phase'] != 'rewrite'
        or template['plugins']['serverless-post-function']['phase'] != 'access'):
        raise ValueError('semantic envelope capture requires rewrite before access')
    ids = [r.get('id') for r in result['routes']]
    if len(ids) != len(set(ids)):
        raise ValueError('existing route IDs must be unique')
    schemas = json.loads((ROOT/'schemas/mcp-gateway-semantic-proposals-v1.json').read_text())['oneOf']
    installation = runtime['x-ouf-installation']
    for cap, (mode, operation, scope) in CAPABILITIES.items():
        if adoption_only and mode != 'adopt':
            continue
        candidates = [r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == cap
                      and r.get('labels', {}).get('exposure') == 'internal']
        if len(candidates) != 1:
            raise ValueError('exact semantic proposal binding required: '+cap)
        binding = candidates[0]
        p, c = binding['x-ouf-policy'], binding['x-ouf-capability']
        path = '/api/semantic/v1/proposal-commands/'+mode
        backend = binding['x-ouf-backend-binding']
        host = operational_host(installation, binding, 'ouf-semantic-registry')
        port = backend.get('port')
        if (binding['service_id'] != 'ouf-semantic-registry' or binding['plugins']['proxy-rewrite']['uri'] != path
            or backend.get('path') != path or type(port) is not int or not 1 <= port <= 65535
            or binding['methods'] != ['POST']
            or c['owner'] != 'semantic' or c['operationType'] != operation
            or c.get('humanRequired') is not False or c.get('toolEligible') is not True
            or p['identity'] != 'M2M' or p['requiredScope'] != scope
            or p['allowedActorTypes'] != (['HUMAN'] if mode in ('read', 'adopt') else ['HUMAN', 'AI_AGENT', 'SERVICE'])
            or p['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
            or p['maxRequestBytes'] != 65536 or p['timeoutSeconds'] != 3):
            raise ValueError('semantic proposal binding mismatch: '+cap)
        route = copy.deepcopy(template)
        route['id'] = 'semantic-proposal-'+mode
        route['uri'] = '/internal/capabilities/v1/execute/semantic/'+mode
        if mode == 'adopt':
            if template.get('methods') != ['POST']:
                raise ValueError('authenticated POST execute template required')
            route['id'] = binding['id']
            route['uri'] = binding['uri']
            if route['uri'] != '/internal/capabilities/v1/execute/semantic/discovery/adopt':
                raise ValueError('semantic adoption execute path mismatch')
            route['plugins']['client-control'] = {'max_body_size': p['maxRequestBytes']}
        if any(r.get('id') == route['id'] or any(
                uri == route['uri'] or (uri.endswith('*') and route['uri'].startswith(uri[:-1]))
                for uri in ([r['uri']] if 'uri' in r else r.get('uris', []))) for r in result['routes']):
            raise ValueError('semantic proposal route already exists; reconcile before materialization')
        route['labels']['ouf-mediation'] = 'semantic-proposal-v1'
        route['plugins']['serverless-pre-function']['functions'].append(CAPTURE_ENVELOPE)
        route['plugins']['request-validation']['body_schema'] = next(s for s in schemas if s['properties']['CapabilityID']['const'] == cap)
        route['plugins']['serverless-post-function']['functions'] = [function('execute_semantic_proposals', installation,
            delegation_key_env, semantic_owner_key_env, operational_binding={'capability': cap, 'owner': 'semantic', 'scope': scope},
            use_route_labels=use_route_labels)]
        route['plugins']['proxy-rewrite']['uri'] = path
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {f'{host}:{port}': 1},
                             'retries': 0, 'timeout': {'connect': 3, 'send': 3, 'read': 3}}
        result['routes'].append(route)
    result['semanticProposalProfile'] = 'ouf.semantic-proposal-channel.v1'
    result['semanticProposalOwnerKeyEnv'] = semantic_owner_key_env
    return result

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--existing', type=Path, required=True,
                   help='retained materialized installation; existing routes are preserved')
    p.add_argument('--oidc-client-secret-ref', required=True)
    p.add_argument('--delegation-key-env', required=True)
    p.add_argument('--semantic-owner-key-env', required=True)
    p.add_argument('--authorization-owner-key-env', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--adoption-only', action='store_true', help='extend a retained proposal channel with adopt')
    a = p.parse_args()
    a.output.write_text(json.dumps(add_to_existing(json.loads(a.existing.read_text()),
        json.loads(a.runtime.read_text()), a.delegation_key_env, a.semantic_owner_key_env,
        adoption_only=a.adoption_only), indent=2)+'\n')
