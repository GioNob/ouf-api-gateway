#!/usr/bin/env python3
"""Prepare private UDP/APISIX R4a files without changing the running stack."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

SEARCH_KEY = 'OUF_UDP_SEARCH_OWNER_KEY'
UDP_KEY_FILE = '/run/secrets/udp-search-owner.key'
UDP_POLICY_TOKEN_FILE = '/run/ouf-udp-auth/token'
AUTH_REFRESH_SECONDS = '30'
AUTH_MAX_STALENESS_SECONDS = '300'
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z')


def private(path: Path, mode: int) -> None:
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f'{path}: expected root ownership and mode {mode:04o}')


def env_of(container: dict) -> dict[str, str]:
    result = {}
    for item in container['Config']['Env']:
        name, separator, value = item.partition('=')
        if not separator or not ENV_NAME.fullmatch(name) or name in result or '\n' in value or '\r' in value:
            raise ValueError('invalid existing Docker environment')
        result[name] = value
    return result


def write(path: Path, content: str, *, uid=0, gid=0, mode=0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)


def prepare(snapshot: Path, config: Path, projection: Path, tenant: str) -> Path:
    snapshot = snapshot.resolve(strict=True)
    config = config.resolve(strict=True)
    private(snapshot.parent, 0o700)
    private(snapshot, 0o600)
    snapshot_data = json.loads(snapshot.read_text(encoding='utf-8'))
    containers = {c['Name']: c for c in snapshot_data}
    if set(containers) != {'/ouf-udp', '/ouf-apisix'} or not tenant or len(tenant) > 128 or any(ch.isspace() for ch in tenant):
        raise ValueError('invalid snapshot or tenant')
    live = json.loads(subprocess.run(['docker', 'inspect', 'ouf-udp', 'ouf-apisix'], check=True,
                                     capture_output=True, text=True).stdout)
    if {c['Name']: c['Id'] for c in live} != {name: c['Id'] for name, c in containers.items()}:
        raise ValueError('container changed since private snapshot')
    if not all(c['State']['Running'] for c in live):
        raise ValueError('both original containers must still be running')
    apisix = containers['/ouf-apisix']
    udp = containers['/ouf-udp']
    if not any(m['Source'] == str(config) and m['Destination'] == '/usr/local/apisix/conf/config.yaml'
               and m['RW'] is False for m in apisix['Mounts']):
        raise ValueError('APISIX config path is not the mounted read-only source')
    if udp['Config']['User'] != '10004:10004':
        raise ValueError('UDP service identity differs from file owner 10004:10004')
    apisix_env, udp_env = env_of(apisix), env_of(udp)
    if SEARCH_KEY in apisix_env or any(name.startswith('OUF_UDP_SEARCH_') for name in udp_env):
        raise ValueError('search binding already configured')
    p = json.loads(projection.read_text(encoding='utf-8'))
    issuer = p['gateway']['issuerUrl']
    audience = p['gateway']['requiredAudience']
    workload = p['iam']['workloadClients']['mcpServer']
    if not all(isinstance(v, str) and v and '\n' not in v and '\r' not in v for v in (issuer, audience, workload)):
        raise ValueError('invalid installation projection')
    original = config.read_text(encoding='utf-8')
    marker = '  - GATEWAY_SUMMARY_RECEIPT_KEY\n'
    if original.count('nginx_config:\n  envs:\n') != 1 or original.count(marker) != 1 or SEARCH_KEY in original:
        raise ValueError('unexpected APISIX env configuration')
    candidate = original.replace(marker, marker + '  - ' + SEARCH_KEY + '\n', 1)
    if candidate.replace('  - ' + SEARCH_KEY + '\n', '', 1) != original:
        raise ValueError('APISIX config changed beyond new env name')
    key = secrets.token_hex(32)
    if key in apisix_env.values():
        raise ValueError('new key collides with existing secret')
    apisix_env[SEARCH_KEY] = key
    udp_env.update(OUF_UDP_SEARCH_TENANT_ID=tenant, OUF_UDP_SEARCH_ISSUER=issuer,
                   OUF_UDP_SEARCH_AUDIENCE=audience, OUF_UDP_SEARCH_WORKLOAD=workload,
                   OUF_UDP_SEARCH_OWNER_KEY_FILE=UDP_KEY_FILE,
                   OUF_AUTHORIZATION_REGISTRY_URL=registry_url,
                   OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=UDP_POLICY_TOKEN_FILE,
                   OUF_AUTHORIZATION_REFRESH_SECONDS=AUTH_REFRESH_SECONDS,
                   OUF_AUTHORIZATION_MAX_STALENESS_SECONDS=AUTH_MAX_STALENESS_SECONDS)
    target = Path(tempfile.mkdtemp(prefix='candidate-', dir=snapshot.parent))
    os.chmod(target, 0o700)
    write(target / 'apisix.env', ''.join(f'{k}={v}\n' for k, v in apisix_env.items()))
    write(target / 'udp.env', ''.join(f'{k}={v}\n' for k, v in udp_env.items()))
    write(target / 'udp-search-owner.key', key + '\n', uid=10004, gid=10004, mode=0o400)
    source = config.stat()
    write(target / 'apisix-config.yaml', candidate, uid=source.st_uid, gid=source.st_gid,
          mode=stat.S_IMODE(source.st_mode))
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--apisix-config', type=Path, default=Path('/opt/ouf/secrets/apisix-config-permissions.yaml'))
    parser.add_argument('--projection', type=Path, default=Path('/opt/ouf/installation/active-projection.json'))
    parser.add_argument('--tenant', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root to prepare private configuration')
    try:
        output = prepare(args.snapshot, args.apisix_config, args.projection, args.tenant)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'R4A_PREPARATION_BLOCKED: {type(error).__name__}\n')
    print('PRIVATE_R4A_CANDIDATE=' + str(output))
    print('CANDIDATE_PREPARED; RUNNING_CONTAINERS_AND_MOUNTED_CONFIG_UNCHANGED')


if __name__ == '__main__':
    main()
