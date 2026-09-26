#!/usr/bin/env python3
"""Install the single first-party managed-file picker route with rollback."""
import argparse
import json
import os
from pathlib import Path

from ops.apisix.deploy_internal_m2m_routes import Admin, route_value, restore, snapshot
from tools.materialize_managed_file_ths import ROUTE_ID, URI


def select(doc):
    routes = doc.get('routes')
    if not isinstance(routes, list) or len(routes) != 1:
        raise ValueError('exact picker route required')
    route = routes[0]
    if (route.get('id') != ROUTE_ID or route.get('uri') != URI
            or route.get('methods') != ['GET', 'POST']
            or route.get('labels', {}).get('ouf-surface') != 'TRUSTED_HUMAN_MANAGED_FILE'
            or route.get('plugins', {}).get('proxy-control') != {'request_buffering': False}
            or route.get('plugins', {}).get('client-control') != {'max_body_size': 10485760}
            or route.get('upstream', {}).get('nodes') != {'ouf-onboarding:8080': 1}
            or route.get('upstream', {}).get('retries') != 0):
        raise ValueError('picker route contract mismatch')
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
            if not isinstance(previous, dict) or set(previous) != {ROUTE_ID}:
                raise ValueError('snapshot must contain only the picker route')
            restore(previous, admin)
            print('MANAGED_FILE_THS_RESTORED')
            return
        route = select(json.loads(a.materialization.read_text()))
        previous = snapshot({ROUTE_ID}, admin)
        try:
            code, _ = admin.route('PUT', ROUTE_ID, route)
            if code not in (200, 201):
                raise RuntimeError('picker route write failed')
            code, body = admin.route('GET', ROUTE_ID)
            if code != 200 or any(route_value(body).get(k) != v for k, v in route.items()):
                raise RuntimeError('picker route readback differs')
            # No state-changing request or bearer credential is sent by the installer.
            code, _ = admin.curl('/trusted-human/managed-files/', 'GET')
            if code not in (302, 401, 403):
                raise RuntimeError(f'anonymous picker returned HTTP {code}')
        except BaseException:
            restore(previous, admin)
            raise
        print('MANAGED_FILE_THS_ACTIVE')
    finally:
        admin.close()


if __name__ == '__main__':
    main()
