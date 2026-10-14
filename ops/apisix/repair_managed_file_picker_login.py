#!/usr/bin/env python3
"""Repair the picker OIDC login/callback through a pinned, rollback-backed installer."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/etc/ouf/deploy-snapshots')
SOURCE_FILES = (
    'tools/materialize_managed_file_ths.py',
    'ops/apisix/deploy_managed_file_ths.py',
    'ops/apisix/deploy_internal_m2m_routes.py',
)


def run(args, **kwargs):
    return subprocess.run(args, check=False, capture_output=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--repo', type=Path, default=Path('/opt/ouf/gateway'))
    parser.add_argument('--materialization', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[0-9a-f]{40}', args.revision):
        raise ValueError('ROOT_OR_PINNED_REVISION_REQUIRED')
    root = ROOT.lstat()
    folder = args.materialization.lstat()
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or stat.S_IMODE(root.st_mode) != 0o700 or
            not stat.S_ISDIR(folder.st_mode) or folder.st_uid != 0 or stat.S_IMODE(folder.st_mode) != 0o700 or
            not (args.materialization / 'runtime.json').is_file()):
        raise ValueError('PRIVATE_MATERIALIZATION_REQUIRED')
    repo = args.repo.resolve(strict=True)
    git = ['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo)]
    resolved = run([*git, 'rev-parse', args.revision + '^{commit}'])
    if resolved.returncode or resolved.stdout.decode().strip() != args.revision:
        raise ValueError('PINNED_SOURCE_MISSING')
    with tempfile.TemporaryDirectory(prefix='r4a-picker-login-', dir=ROOT) as name:
        source = Path(name)
        os.chmod(source, 0o700)
        for path in SOURCE_FILES:
            result = run([*git, 'show', args.revision + ':' + path])
            if result.returncode:
                raise ValueError('PINNED_SOURCE_INCOMPLETE')
            target = source / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(result.stdout)
        env = {**os.environ, 'PYTHONPATH': str(source)}
        materialized = source / 'picker-routes.json'
        result = run([sys.executable, '-P', '-m', 'tools.materialize_managed_file_ths',
                      '--runtime', str(args.materialization / 'runtime.json'),
                      '--output', str(materialized)], env=env)
        if result.returncode:
            raise ValueError('MATERIALIZATION_FAILED')
        result = run([sys.executable, '-P', '-m', 'ops.apisix.deploy_managed_file_ths',
                      '--materialization', str(materialized),
                      '--admin-key', '/opt/ouf/secrets/apisix-admin-key',
                      '--backup-dir', str(ROOT)], env=env)
        for line in result.stdout.decode(errors='replace').splitlines():
            if line.startswith(('BACKUP=', 'MANAGED_FILE_THS_ACTIVE', 'OIDC_LOGIN_ROUTE_ACTIVE=')):
                print(line, flush=True)
        if result.returncode:
            raise ValueError('ROUTE_INSTALL_FAILED')
    print('PICKER_LOGIN_ROUTE=PASS')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError) as exc:
        print('PICKER_LOGIN_ROUTE_BLOCKED=' +
              (str(exc) if isinstance(exc, ValueError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
