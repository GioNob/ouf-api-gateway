#!/usr/bin/env python3
"""Install the exact HUMAN Semantic route set with a bounded rollback snapshot."""
import argparse
import json
import os
from pathlib import Path
import re

from ops.apisix.deploy_internal_m2m_routes import Admin, route_value, restore, snapshot
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
    previous = snapshot(set(ROUTES), admin)
    for route in routes:
        old = previous[route['id']]
        if old is not None and any(old.get(k) != v for k, v in route.items()):
            raise RuntimeError('EXISTING_SEMANTIC_ROUTE_DRIFT:' + route['id'])
    try:
        for route in routes:
            route_id = route['id']
            if previous[route_id] is None:
                code, _ = admin.route('PUT', route_id, route)
                if code not in (200, 201):
                    raise RuntimeError('SEMANTIC_ROUTE_WRITE_FAILED:' + route_id)
            code, body = admin.route('GET', route_id)
            if code != 200 or any(route_value(body).get(k) != v for k, v in route.items()):
                raise RuntimeError('SEMANTIC_ROUTE_READBACK_FAILED:' + route_id)
        for route in routes:
            code, _ = admin.curl(sample_uri(route), route['methods'][0])
            if code not in (401, 403):
                raise RuntimeError('SEMANTIC_ANONYMOUS_NOT_DENIED:' + route['id'] + ':' + str(code))
    except BaseException:
        restore(previous, admin)
        raise
    print('SEMANTIC_HUMAN_ROUTES_ACTIVE=true COUNT=' + str(len(routes)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--materialization', type=Path)
    mode.add_argument('--restore', type=Path)
    p.add_argument('--admin-key', type=Path, required=True)
    p.add_argument('--container', default='ouf-apisix')
    p.add_argument('--curl-image', default='curlimages/curl:8.16.0')
    p.add_argument('--backup-dir', type=Path, default=Path('/opt/ouf/backup'))
    args = p.parse_args()
    os.umask(0o077)
    if args.restore:
        previous = json.loads(args.restore.read_text())
        if not isinstance(previous, dict) or set(previous) != set(ROUTES):
            raise ValueError('SEMANTIC_SNAPSHOT_INVALID')
    else:
        routes = validate(json.loads(args.materialization.read_text()))
    admin = Admin(args, 'semantic-human-')
    try:
        if args.restore:
            restore(previous, admin)
            print('SEMANTIC_HUMAN_ROUTES_RESTORED=true')
        else:
            install(routes, admin)
    finally:
        admin.close()


if __name__ == '__main__':
    main()
