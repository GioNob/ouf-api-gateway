#!/usr/bin/env python3
"""Materialize only the governed HUMAN Semantic first-publication routes."""
import argparse
import json
from pathlib import Path

from tools.materialize_trusted_human_onboarding_runtime import materialize_route

ROUTES = {
    'semantic-artifact-propose': ('POST', '/api/semantic/v1/artifacts', 'ouf.semantic.propose'),
    'semantic-revision-validate': ('POST', '/api/semantic/v1/revisions/*', 'ouf.semantic.review.prepare'),
    'semantic-approval-request': ('POST', '/api/semantic/v1/approval-challenges', 'ouf.semantic.approval.request'),
    'semantic-human-card': ('GET', '/api/trusted-human/v1/semantic-approval-challenges/*', 'ouf.semantic.review'),
    'semantic-human-decision': ('POST', '/api/trusted-human/v1/semantic-approval-challenges/*', 'ouf.semantic.approve'),
    'semantic-human-publish': ('POST', '/api/trusted-human/v1/semantic-approval-challenges/*', 'ouf.semantic.publish'),
    'semantic-artifact-search': ('GET', '/api/semantic/v1/search', 'ouf.semantic.search'),
}
UUID = '[0-9a-fA-F-]{36}'
REGEX = {
    'semantic-revision-validate': '^/api/semantic/v1/revisions/' + UUID + ':validate$',
    'semantic-human-card': '^/api/trusted-human/v1/semantic-approval-challenges/' + UUID + '$',
    'semantic-human-decision': '^/api/trusted-human/v1/semantic-approval-challenges/' + UUID + '/decision$',
    'semantic-human-publish': '^/api/trusted-human/v1/semantic-approval-challenges/' + UUID + '/publish$',
}


def materialize(runtime, secret_ref):
    installation = runtime['x-ouf-installation']
    indexed = {r.get('id'): r for r in runtime['routes'] if isinstance(r, dict)}
    result = []
    for route_id, (method, uri, scope) in ROUTES.items():
        binding = indexed.get(route_id)
        if not binding or binding.get('uri') != uri or binding.get('methods') != [method]:
            raise ValueError('SEMANTIC_BINDING_MISSING_OR_CHANGED:' + route_id)
        policy = binding['x-ouf-policy']
        backend = binding['x-ouf-backend-binding']
        if (policy.get('requiredScope') != scope or policy.get('identity') != 'OIDC'
                or policy.get('allowedActorTypes') != ['HUMAN']
                or binding['x-ouf-capability'].get('capabilityId') != scope
                or backend.get('service') not in {'ouf-semantic', 'ouf-semantic-registry'}
                or backend.get('port') != 8080 or backend.get('path') != uri
                or binding.get('vars') != ([['uri', '~~', REGEX[route_id]]] if route_id in REGEX else None)):
            raise ValueError('SEMANTIC_BINDING_CONTRACT_CHANGED:' + route_id)
        route = materialize_route(binding, installation, secret_ref)
        route['labels']['ouf-surface'] = 'TRUSTED_HUMAN_SEMANTIC'
        if route_id in REGEX:
            route['vars'] = binding['vars']
        result.append(route)
    return {'formatVersion': '1.0', 'installationId': installation['installationId'],
            'installationRevision': installation['revision'], 'routes': result}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--oidc-client-secret-ref', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text()),
                                               a.oidc_client_secret_ref), indent=2) + '\n')
