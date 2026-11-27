#!/usr/bin/env python3
"""Validate the Semantic materialization for the governed Gateway release."""
OWNED = 'Semantic routes are owned by the governed Gateway release'

if __name__ == '__main__':
    raise SystemExit(OWNED)

from tools.materialize_semantic_human_runtime import REGEX, ROUTES

SAMPLE_ID = '00000000-0000-0000-0000-000000000000'


def validate(doc):
    routes = doc.get('routes')
    if not isinstance(routes, list) or len(routes) != len(ROUTES):
        raise ValueError('SEMANTIC_ROUTE_SET_INVALID')
    indexed = {r.get('id'): r for r in routes if isinstance(r, dict)}
    if set(indexed) != set(ROUTES):
        raise ValueError('SEMANTIC_ROUTE_SET_INVALID')
    for route_id, (method, uri, scope) in ROUTES.items():
        route = indexed[route_id]
        plugins = route.get('plugins') or {}
        oidc = plugins.get('openid-connect') or {}
        backend = route.get('upstream') or {}
        nodes = backend.get('nodes') or {}
        if (route.get('methods') != [method] or route.get('uri') != uri
                or route.get('vars') != ([['uri', '~~', REGEX[route_id]]] if route_id in REGEX else None)
                or route.get('labels', {}).get('ouf-surface') != 'TRUSTED_HUMAN_SEMANTIC'
                or route.get('labels', {}).get('ouf-capability') != scope
                or oidc.get('required_scopes') != [scope] or oidc.get('bearer_only') is not True
                or oidc.get('ssl_verify') is not True or oidc.get('use_jwks') is not True
                or not all(name in plugins for name in ('serverless-pre-function',
                                  'serverless-post-function', 'client-control'))
                or plugins.get('client-control', {}).get('max_body_size') != (
                    8388608 if route_id == 'semantic-rdf-import' else 65536)
                or backend.get('retries') != 0
                or nodes not in ({'ouf-semantic:8080': 1}, {'ouf-semantic-registry:8080': 1})):
            raise ValueError('SEMANTIC_ROUTE_CONTRACT_CHANGED:' + route_id)
    return [indexed[route_id] for route_id in ROUTES]


def sample_uri(route):
    return route['uri'].replace('*', SAMPLE_ID) + (
        ':validate' if route['id'] == 'semantic-revision-validate' else
        '/decision' if route['id'] == 'semantic-human-decision' else
        '/publish' if route['id'] == 'semantic-human-publish' else '')


def install(routes, admin):
    raise ValueError(OWNED)


def validate_snapshot(previous):
    raise ValueError(OWNED)
