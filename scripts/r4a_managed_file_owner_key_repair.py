#!/usr/bin/env python3
"""Repair the four live managed-file MCP Lua routes with a scoped snapshot.

Only the missing OWNER_KEY_ENV declaration may differ from the installed
materialization. Rebuild from an exact fetched source commit and roll back
the four routes on any installer failure. No key value is read or printed.
"""
import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPO = Path('/opt/ouf/gateway')
ROOT = Path('/etc/ouf/deploy-snapshots')
MATERIALIZATION = ROOT / 'r4a-mcp-routes-vqa3yS'
IDS = {f'mcp-managed-file-{name}' for name in ('profile', 'preview', 'create', 'handoff')}
OWNER_ENV = 'OUF_AUTHORIZATION_OWNER_KEY'


def run(args, *, env=None, input=None):
    result = subprocess.run(args, input=input, env=env, text=True,
                            capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError('COMMAND_FAILED_' + Path(args[0]).name.upper().replace('-', '_'))
    return result.stdout


def route_map(doc):
    routes = doc.get('routes', [])
    found = {r['id']: r for r in routes if isinstance(r, dict) and r.get('id') in IDS}
    if set(found) != IDS or len([r for r in routes if isinstance(r, dict) and r.get('id') in IDS]) != 4:
        raise RuntimeError('MANAGED_FILE_ROUTES_INCOMPLETE')
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('apply',))
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', args.revision):
        parser.error('root and an exact source revision required')
    revision = run(['git', '-c', 'safe.directory=' + str(REPO), '-C', str(REPO),
                    'rev-parse', args.revision + '^{commit}']).strip()
    if revision != args.revision:
        raise RuntimeError('PINNED_SOURCE_UNAVAILABLE')
    runtime = MATERIALIZATION / 'runtime.json'
    current_file = MATERIALIZATION / 'mcp-routes.json'
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='r4a-managed-file-key-', dir=ROOT) as folder:
        work = Path(folder)
        archive = subprocess.Popen(['git', '-c', 'safe.directory=' + str(REPO),
                                    '-C', str(REPO), 'archive', '--format=tar', revision],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            unpack = subprocess.run(['tar', '-xf', '-', '-C', str(work)],
                                    stdin=archive.stdout, capture_output=True, check=False)
        finally:
            archive.stdout.close()
        if archive.wait() or unpack.returncode:
            raise RuntimeError('GATEWAY_ARCHIVE_FAILED')
        env = {**os.environ, 'PYTHONPATH': str(work)}
        sys.path.insert(0, str(work))
        from ops.apisix.deploy_internal_m2m_routes import Admin, route_value
        admin_args = argparse.Namespace(backup_dir=ROOT,
            admin_key=Path('/opt/ouf/secrets/apisix-admin-key'),
            container='ouf-apisix', curl_image='curlimages/curl:8.16.0')
        with redirect_stdout(io.StringIO()):
            admin = Admin(admin_args, 'managed-file-owner-key-read-')
        try:
            current = {}
            for route_id in sorted(IDS):
                status, body = admin.route('GET', route_id)
                if status != 200:
                    raise RuntimeError('LIVE_ROUTE_NOT_FOUND_' + route_id)
                current[route_id] = route_value(body)
        finally:
            admin.close()
        output = work / 'mcp-routes.json'
        run([sys.executable, '-P', '-m', 'tools.materialize_managed_file_mcp',
             '--runtime', str(runtime), '--oidc-client-secret-ref',
             '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET', '--delegation-key-env',
             'OUF_GATEWAY_DELEGATION_KEY', '--owner-key-env', OWNER_ENV,
             '--output', str(output)], env=env)
        repaired = route_map(json.loads(output.read_text()))
        marker = 'local OWNER_KEY_ENV = "' + OWNER_ENV + '"\n'
        for route_id in sorted(IDS):
            old = current[route_id]
            new = repaired[route_id]
            old_function = old['plugins']['serverless-post-function']['functions'][0]
            new_function = new['plugins']['serverless-post-function']['functions'][0]
            if marker in old_function or new_function.count(marker) != 1:
                raise RuntimeError('UNEXPECTED_OWNER_KEY_STATE_' + route_id)
            check = json.loads(json.dumps(new))
            check['plugins']['serverless-post-function']['functions'][0] = new_function.replace(marker, '')
            if any(old.get(key) != value for key, value in check.items()):
                raise RuntimeError('UNRELATED_ROUTE_DRIFT_' + route_id)
        # The installer snapshots, verifies readback and anonymous denial, and
        # restores all four routes automatically on a failed write or check.
        result = run([sys.executable, '-P', '-m', 'ops.apisix.deploy_managed_file_mcp',
                      '--materialization', str(output), '--admin-key',
                      '/opt/ouf/secrets/apisix-admin-key', '--backup-dir', str(ROOT)], env=env)
        if 'MANAGED_FILE_MCP_ACTIVE' not in result:
            raise RuntimeError('ROUTE_INSTALL_UNVERIFIED')
        backups = [Path(line.partition('=')[2]) for line in result.splitlines()
                   if line.startswith('BACKUP=')]
        if len(backups) != 1 or not backups[0].is_file():
            raise RuntimeError('ROUTE_BACKUP_MISSING')
        backup = backups[0]
        old_bytes = current_file.read_bytes()
        try:
            (backup.parent / 'previous-materialization.json').write_bytes(old_bytes)
            pending = current_file.with_name('mcp-routes.repair-pending.json')
            pending.write_bytes(output.read_bytes())
            os.replace(pending, current_file)
        except OSError:
            pending.unlink(missing_ok=True)
            run([sys.executable, '-P', '-m', 'ops.apisix.deploy_managed_file_mcp',
                 '--restore', str(backup), '--admin-key',
                 '/opt/ouf/secrets/apisix-admin-key', '--backup-dir', str(ROOT)], env=env)
            raise RuntimeError('MATERIALIZATION_WRITE_FAILED_ROUTES_RESTORED')
        print('BACKUP=' + str(backup))
        print('MANAGED_FILE_OWNER_KEY_REPAIR=PASS ROUTES=4')
        print('SECRET_VALUES_NOT_READ_OR_PRINTED=true')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, TypeError, ValueError) as exc:
        code = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print('MANAGED_FILE_OWNER_KEY_REPAIR_BLOCKED=' + code, file=sys.stderr)
        raise SystemExit(1)
