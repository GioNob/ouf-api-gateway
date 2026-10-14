#!/usr/bin/env python3
"""Install only the governed streaming MCP upload route with private rollback.

This installs routing, not the MCP host attachment adapter. Keep the snapshot
until a real host fileParam upload, negative cases and rollback have passed.
"""
import argparse
import json
import os
from pathlib import Path

from ops.apisix.deploy_internal_m2m_routes import Admin, apply, restore, validate_routes

ROUTE_ID = 'mcp-managed-file-upload'
URI = '/internal/capabilities/v1/execute/managed.file/upload'
OWNER_PATH = '/api/internal/v1/onboarding/managed-file-mcp/upload'


def validate(route):
    if validate_routes([route]) != {ROUTE_ID}:
        raise ValueError('exact delegated upload route required')
    plugins = route['plugins']
    upstream = route['upstream']
    if (route['uri'] != URI or route['methods'] != ['POST'] or
            route['labels'].get('ouf-mediation') != 'managed-file-streaming-upload-v1' or
            plugins.get('proxy-control') != {'request_buffering': False} or
            plugins.get('client-control') != {'max_body_size': 10485760} or
            'request-validation' in plugins or
            plugins.get('proxy-rewrite', {}).get('uri') != OWNER_PATH or
            upstream.get('nodes') != {'ouf-onboarding:8080': 1} or
            upstream.get('retries') != 0):
        raise ValueError('streaming upload route contract mismatch')
    before = ' '.join(plugins['serverless-pre-function']['functions'])
    access = ' '.join(plugins['serverless-post-function']['functions'])
    if ("n~='x-ouf-file-id'" not in before or "n~='x-ouf-delegation'" not in before
            or 'ngx.req.read_body' in before or 'ngx.req.read_body' in access
            or 'X-OUF-Managed-File-Receipt' not in access):
        raise ValueError('upload metadata or no-buffering contract mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--materialization', type=Path)
    choice.add_argument('--restore', type=Path)
    parser.add_argument('--admin-key', type=Path, required=True)
    parser.add_argument('--container', default='ouf-apisix')
    parser.add_argument('--curl-image', default='curlimages/curl:8.16.0')
    parser.add_argument('--backup-dir', type=Path, default=Path('/opt/ouf/backup'))
    args = parser.parse_args()
    os.umask(0o077)
    previous = None
    if args.restore:
        previous = json.loads(args.restore.read_text())
        if not isinstance(previous, dict) or set(previous) != {ROUTE_ID}:
            raise ValueError('snapshot must contain only delegated upload route')
    else:
        route = json.loads(args.materialization.read_text())
        validate(route)
    admin = Admin(args, 'managed-file-upload-')
    try:
        if previous is not None:
            restore(previous, admin)
            print('MANAGED_FILE_UPLOAD_ROUTE_RESTORED')
            return
        code, _ = admin.curl('/apisix/admin/plugins/proxy-control?subsystem=http', admin=True)
        if code != 200:
            raise ValueError('APISIX_STREAMING_PLUGIN_UNAVAILABLE')
        apply([route], admin)
        print('MANAGED_FILE_UPLOAD_ROUTE_ACTIVE')
    finally:
        admin.close()


if __name__ == '__main__':
    main()
