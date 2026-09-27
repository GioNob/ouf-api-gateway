#!/usr/bin/env python3
"""Privately snapshot current APISIX/UDP Docker runtime before an R4a rollout.

The snapshot contains Docker environment secrets. Never print or commit it.
This command is read-only with respect to running containers.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


def save(backup_root: Path, containers: list[dict]) -> Path:
    root = backup_root.resolve(strict=True)
    metadata = root.stat()
    if not root.is_dir() or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError('backup root must be a root-owned private directory (0700)')
    if {c.get('Name') for c in containers} != {'/ouf-udp', '/ouf-apisix'}:
        raise ValueError('expected exactly the current UDP and APISIX containers')
    directory = Path(tempfile.mkdtemp(prefix='r4a-runtime-', dir=root))
    os.chmod(directory, 0o700)
    snapshot = directory / 'containers.inspect.json'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(snapshot, flags, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        json.dump(containers, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.chmod(snapshot, 0o600)
    return snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup-root', type=Path, default=Path('/opt/ouf/backup'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root for a private Docker snapshot')
    result = subprocess.run(['docker', 'inspect', 'ouf-udp', 'ouf-apisix'],
                            check=True, capture_output=True, text=True)
    snapshot = save(args.backup_root, json.loads(result.stdout))
    print('PRIVATE_DOCKER_SNAPSHOT=' + str(snapshot))
    print('SNAPSHOT_MODE=0600 ROOT_ONLY; CONTAINERS_UNCHANGED')


if __name__ == '__main__':
    main()
