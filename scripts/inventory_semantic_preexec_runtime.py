"""Read-only local Docker runtime inventory; no registration or container calls."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess


class InventoryDenied(RuntimeError):
    pass


def safe_ancestors(path):
    if not path.is_absolute() or '..' in path.parts:
        raise InventoryDenied('ABSOLUTE_ROOT_OWNED_PATH_REQUIRED')
    for parent in (path.parent, *path.parent.parents):
        value = parent.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise InventoryDenied('ROOT_OWNED_ANCESTORS_REQUIRED')


def command_path(path):
    safe_ancestors(path); value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022 \
            or not value.st_mode & 0o111:
        raise InventoryDenied('ROOT_OWNED_EXECUTABLE_REQUIRED')


def version(raw):
    value = raw.strip()
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9_.~-]+)?', value) or len(value) > 80:
        raise InventoryDenied('VERSION_FORMAT_UNPROVEN')
    return value


def collect(query):
    server = version(query('{{.ServerVersion}}'))
    default = query('{{.DefaultRuntime}}').strip()
    names = query('{{range $key, $value := .Runtimes}}{{$key}}{{println}}{{end}}').splitlines()
    if not 1 <= len(names) <= 32 or len(set(names)) != len(names) \
            or any(not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', v) for v in [default, *names]) \
            or default not in names:
        raise InventoryDenied('RUNTIME_NAMES_UNPROVEN')
    return {'serverVersion': server, 'defaultRuntime': default, 'runtimeNames': sorted(names)}


def inventory(query, runc_version):
    first = collect(query); second = collect(query)
    if first != second: raise InventoryDenied('RUNTIME_CHANGED_ACROSS_READS')
    return {'schema': 'ouf.semantic-preexec-runtime-inventory.v1', **first,
        'runcBinaryVersion': runc_version, 'readOnly': True, 'stableAcrossReads': True,
        'atomicSnapshotProven': False, 'ociHookIntegrationProven': False,
        'runtimeRegistrationAuthorized': False, 'startAuthorized': False,
        'providerCalls': 0, 'notReleaseAcceptance': True, 'noSecretsPrinted': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-path', required=True)
    parser.add_argument('--runc-path', required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise InventoryDenied('ROOT_REQUIRED')
        docker, runc = Path(args.docker_path), Path(args.runc_path)
        command_path(docker); command_path(runc)
        socket = Path('/run/docker.sock'); safe_ancestors(socket); metadata = socket.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o002:
            raise InventoryDenied('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        # Read only this private source directory as CLI config. Never inherit
        # credential helpers, remote DOCKER_HOST, proxy or user CLI configuration.
        source = Path(__file__).absolute().parent; safe_ancestors(source/'config.json')
        if source.stat().st_mode & 0o077 or (source/'config.json').exists() or (source/'config.json').is_symlink():
            raise InventoryDenied('PRIVATE_EMPTY_CLI_CONFIGURATION_REQUIRED')
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
        def run(argv):
            result = subprocess.run(argv, capture_output=True, text=True, timeout=8, env=env)
            if result.returncode or len(result.stdout) > 16384:
                raise InventoryDenied('LOCAL_RUNTIME_READ_UNPROVEN')
            return result.stdout
        def query(template):
            return run([str(docker), '--config', str(source), '--host', 'unix:///run/docker.sock',
                        'info', '--format', template])
        raw = run([str(runc), '--version']).splitlines()
        if not raw or not raw[0].startswith('runc version '): raise InventoryDenied('RUNC_VERSION_UNPROVEN')
        runc_value = version(raw[0].removeprefix('runc version '))
        value = inventory(query, runc_value)
        if socket.lstat() != metadata: raise InventoryDenied('DOCKER_SOCKET_METADATA_CHANGED')
        print('SEMANTIC_PREEXEC_RUNTIME_INVENTORY='+json.dumps(value, sort_keys=True))
        print('SEMANTIC_PREEXEC_RUNTIME_INVENTORY=PASS READ_ONLY=true OCI_HOOK_INTEGRATION_PROVEN=false'
              ' NO_RULE_UNIT_CONTAINER_CHANGED=true START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
    except (OSError, ValueError, subprocess.SubprocessError, InventoryDenied):
        # Do not expose CLI stderr, paths, daemon configuration or credentials.
        print('SEMANTIC_PREEXEC_RUNTIME_INVENTORY=BLOCKED READ_ONLY=true START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 1
    return 0


if __name__ == '__main__': raise SystemExit(main())
