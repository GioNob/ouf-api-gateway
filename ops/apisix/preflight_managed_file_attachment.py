#!/usr/bin/env python3
"""Read-only live inventory before publishing the ChatGPT attachment capability.

Never prints Docker environment values, the Admin key, JWTs or route bodies.
"""
import json
import argparse
from pathlib import Path
import subprocess
import sys

ROUTES = (
    'mcp-managed-file-upload',
    'mcp-managed-file-profile',
    'mcp-managed-file-preview',
    'mcp-managed-file-create',
)
ADMIN_KEY = Path('/opt/ouf/secrets/apisix-admin-key')


def inspect(name):
    result = subprocess.run(['docker', 'inspect', name], capture_output=True, check=False)
    if result.returncode:
        raise ValueError('CONTAINER_NOT_FOUND_' + name)
    docs = json.loads(result.stdout)
    if len(docs) != 1:
        raise ValueError('CONTAINER_INSPECT_UNEXPECTED')
    return docs[0]


def route_statuses(pid):
    # The child inherits only the APISIX network namespace. It reads the
    # host-mounted key itself, keeping it out of argv, output and diagnostics.
    code = '''import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
key=Path('/opt/ouf/secrets/apisix-admin-key').read_text().strip()
for name in json.loads(input()):
    req=Request('http://127.0.0.1:9180/apisix/admin/routes/'+name,headers={'X-API-KEY':key})
    try:
        with urlopen(req,timeout=5) as response: status=response.status
    except HTTPError as exc: status=exc.code
    print(name+'='+str(status))
'''
    child = subprocess.run(['nsenter', '-t', str(pid), '-n', 'python3', '-c', code],
                           input=json.dumps(ROUTES)+'\n', text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if child.returncode:
        raise ValueError('ADMIN_ROUTE_QUERY_FAILED')
    result = dict(line.split('=', 1) for line in child.stdout.splitlines())
    if set(result) != set(ROUTES) or any(value not in {'200', '404'} for value in result.values()):
        raise ValueError('ADMIN_ROUTE_STATUS_UNEXPECTED')
    return result


def main():
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mcp-container', default='ouf-mcp')
    parser.add_argument('--apisix-container', default='ouf-apisix')
    args = parser.parse_args()
    if os.geteuid() != 0 or not ADMIN_KEY.is_file():
        raise ValueError('ROOT_OR_ADMIN_KEY_REQUIRED')
    mcp = inspect(args.mcp_container)
    apisix = inspect(args.apisix_container)
    environment = dict(value.partition('=')[::2] for value in mcp['Config'].get('Env') or [])
    print('MCP_RUNNING=' + str(bool(mcp['State']['Running'])).lower())
    print('MCP_IMAGE_ID=' + mcp['Image'])
    print('UPLOAD_ENABLED=' + str(environment.get('MCP_MANAGED_UPLOAD_ENABLED') == 'true').lower())
    print('HOST_ORIGINS_CONFIGURED=' + str(bool(environment.get('MCP_HOST_FILE_ORIGINS'))).lower())
    print('APISIX_RUNNING=' + str(bool(apisix['State']['Running'])).lower())
    if not apisix['State']['Running'] or apisix['State']['Pid'] <= 0:
        raise ValueError('APISIX_NOT_RUNNING')
    for name, status in route_statuses(apisix['State']['Pid']).items():
        print('ROUTE_' + name + '_HTTP=' + status)
    print('NO_WRITES=true SECRET_VALUES_NOT_PRINTED=true')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print('ATTACHMENT_PREFLIGHT_BLOCKED=' + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
