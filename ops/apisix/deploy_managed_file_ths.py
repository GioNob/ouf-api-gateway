#!/usr/bin/env python3
"""Install the picker and its OIDC login/callback routes with rollback."""
import argparse
import json
import os
from pathlib import Path

from ops.apisix.deploy_internal_m2m_routes import Admin, route_value, restore, snapshot
from tools.materialize_managed_file_ths import ROUTE_ID, URI, LOGIN_ROUTE_ID, LOGIN_URIS


def select(doc):
    routes = doc.get('routes')
    if (not isinstance(routes, list) or len(routes) != 2 or
            {r.get('id') for r in routes if isinstance(r, dict)} != {ROUTE_ID, LOGIN_ROUTE_ID}):
        raise ValueError('exact picker and OIDC route required')
    route = next(r for r in routes if r['id'] == ROUTE_ID)
    if (route.get('id') != ROUTE_ID or route.get('uri') != URI
            or route.get('methods') != ['GET', 'POST']
            or route.get('labels', {}).get('ouf-surface') != 'TRUSTED_HUMAN_MANAGED_FILE'
            or route.get('plugins', {}).get('proxy-control') != {'request_buffering': False}
            or route.get('plugins', {}).get('client-control') != {'max_body_size': 10485760}
            or route.get('upstream', {}).get('nodes') != {'ouf-onboarding:8080': 1}
            or route.get('upstream', {}).get('retries') != 0):
        raise ValueError('picker route contract mismatch')
    return route


def select_login(doc):
    route = next(r for r in doc['routes'] if r['id'] == LOGIN_ROUTE_ID)
    plugins = route.get('plugins', {})
    pre = plugins.get('serverless-pre-function', {})
    functions = pre.get('functions', [])
    if (set(route) != {'id', 'uris', 'methods', 'plugins', 'upstream'} or
            route.get('uris') != LOGIN_URIS or route.get('methods') != ['GET'] or
            set(plugins) != {'client-control', 'serverless-pre-function'} or
            plugins.get('client-control') != {'max_body_size': 65536} or
            pre.get('phase') != 'rewrite' or len(functions) != 1 or
            not isinstance(functions[0], str) or
            'ngx.req.clear_header(k)' not in functions[0] or
            route.get('upstream') != {'type': 'roundrobin', 'nodes': {'ouf-onboarding:8080': 1},
                                      'retries': 0, 'timeout': {'connect': 3, 'send': 3, 'read': 10}}):
        raise ValueError('OIDC login route contract mismatch')
    return route


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--materialization', type=Path)
    mode.add_argument('--restore', type=Path)
    p.add_argument('--admin-key', type=Path, required=True)
    p.add_argument('--container', default='ouf-apisix')
    p.add_argument('--curl-image', default='curlimages/curl:8.16.0')
    p.add_argument('--backup-dir', type=Path, default=Path('/opt/ouf/backup'))
    a = p.parse_args()
    os.umask(0o077)
    admin = Admin(a, 'managed-file-ths-')
    try:
        if a.restore:
            previous = json.loads(a.restore.read_text())
            if not isinstance(previous, dict) or set(previous) not in ({ROUTE_ID}, {ROUTE_ID, LOGIN_ROUTE_ID}):
                raise ValueError('snapshot must contain only picker/OIDC routes')
            restore(previous, admin)
            print('MANAGED_FILE_THS_RESTORED')
            return
        doc = json.loads(a.materialization.read_text())
        routes = [select(doc), select_login(doc)]
        previous = snapshot({ROUTE_ID, LOGIN_ROUTE_ID}, admin)
        try:
            for route in routes:
                route_id = route['id']
                if previous[route_id] is not None and any(previous[route_id].get(k) != v for k, v in route.items()):
                    raise RuntimeError('existing THS route drift: ' + route_id)
                if previous[route_id] is None:
                    code, _ = admin.route('PUT', route_id, route)
                    if code not in (200, 201):
                        raise RuntimeError('THS route write failed: ' + route_id)
                code, body = admin.route('GET', route_id)
                if code != 200 or any(route_value(body).get(k) != v for k, v in route.items()):
                    raise RuntimeError('THS route readback differs: ' + route_id)
            # No state-changing request or bearer credential is sent by the installer.
            code, _ = admin.curl('/trusted-human/managed-files/', 'GET')
            if code not in (302, 401, 403):
                raise RuntimeError(f'anonymous picker returned HTTP {code}')
            code, _ = admin.curl(LOGIN_URIS[0], 'GET')
            if code != 302:
                raise RuntimeError(f'OIDC login returned HTTP {code}')
        except BaseException:
            restore(previous, admin)
            raise
        print('MANAGED_FILE_THS_ACTIVE')
        print('OIDC_LOGIN_ROUTE_ACTIVE=true')
    finally:
        admin.close()


if __name__ == '__main__':
    main()
