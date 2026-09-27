#!/usr/bin/env python3
"""Check private R4a candidate and report non-secret Docker rollout metadata."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def private(path: Path, mode: int) -> None:
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError('private runtime path owner or mode differs')


def env_of(container: dict) -> dict[str, str]:
    values = {}
    for item in container['Config']['Env']:
        name, sep, value = item.partition('=')
        if not sep or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) or name in values or '\n' in value or '\r' in value:
            raise ValueError('invalid Docker environment')
        values[name] = value
    return values


def parse_env(path: Path) -> dict[str, str]:
    content = path.read_text(encoding='utf-8')
    entries = content.splitlines()
    if not content.endswith('\n') or len(entries) != len(set(item.partition('=')[0] for item in entries)):
        raise ValueError('invalid candidate environment structure')
    return env_of({'Config': {'Env': entries}})


def check(snapshot: Path, candidate: Path) -> list[str]:
    snapshot = snapshot.resolve(strict=True)
    candidate = candidate.resolve(strict=True)
    private(snapshot.parent, 0o700)
    private(snapshot, 0o600)
    private(candidate, 0o700)
    if candidate.parent != snapshot.parent:
        raise ValueError('candidate is outside the private snapshot directory')
    data = json.loads(snapshot.read_text(encoding='utf-8'))
    old = {c['Name']: c for c in data}
    if set(old) != {'/ouf-udp', '/ouf-apisix'}:
        raise ValueError('unexpected original containers')
    expected = {'apisix.env', 'udp.env', 'udp-search-owner.key', 'apisix-config.yaml'}
    if {p.name for p in candidate.iterdir()} != expected or any(p.is_symlink() for p in candidate.iterdir()):
        raise ValueError('unexpected candidate files')
    for name in ('apisix.env', 'udp.env'):
        private(candidate / name, 0o600)
    key_file = candidate / 'udp-search-owner.key'
    key_meta = key_file.stat()
    if (key_meta.st_uid, key_meta.st_gid, stat.S_IMODE(key_meta.st_mode)) != (10004, 10004, 0o400):
        raise ValueError('UDP key file owner or mode differs')
    key = key_file.read_text(encoding='ascii').strip()
    if not re.fullmatch('[0-9a-f]{64}', key):
        raise ValueError('invalid UDP key format')
    apisix_env = parse_env(candidate / 'apisix.env')
    udp_env = parse_env(candidate / 'udp.env')
    old_apisix, old_udp = env_of(old['/ouf-apisix']), env_of(old['/ouf-udp'])
    apisix_extra = {'OUF_UDP_SEARCH_OWNER_KEY'}
    udp_extra = {'OUF_UDP_SEARCH_TENANT_ID', 'OUF_UDP_SEARCH_ISSUER', 'OUF_UDP_SEARCH_AUDIENCE',
                 'OUF_UDP_SEARCH_WORKLOAD', 'OUF_UDP_SEARCH_OWNER_KEY_FILE'}
    if ({k: v for k, v in apisix_env.items() if k not in apisix_extra} != old_apisix or
            {k: v for k, v in udp_env.items() if k not in udp_extra} != old_udp or
            set(apisix_env) - set(old_apisix) != apisix_extra or
            set(udp_env) - set(old_udp) != udp_extra or
            apisix_env['OUF_UDP_SEARCH_OWNER_KEY'] != key or
            udp_env['OUF_UDP_SEARCH_OWNER_KEY_FILE'] != '/run/secrets/udp-search-owner.key'):
        raise ValueError('candidate environment differs beyond R4a bindings')
    mount = old['/ouf-apisix']['Mounts']
    config_mount = [m for m in mount if m['Destination'] == '/usr/local/apisix/conf/config.yaml']
    if len(config_mount) != 1 or config_mount[0]['RW'] is not False:
        raise ValueError('original APISIX YAML mount is unexpected')
    original = Path(config_mount[0]['Source'])
    yaml_file = candidate / 'apisix-config.yaml'
    meta = yaml_file.stat()
    source = original.stat()
    if (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) != (source.st_uid, source.st_gid, stat.S_IMODE(source.st_mode)):
        raise ValueError('candidate APISIX YAML permissions differ')
    previous = original.read_text(encoding='utf-8')
    if previous.count('  - GATEWAY_SUMMARY_RECEIPT_KEY\n') != 1 or 'OUF_UDP_SEARCH_OWNER_KEY' in previous or yaml_file.read_text(encoding='utf-8') != previous.replace(
            '  - GATEWAY_SUMMARY_RECEIPT_KEY\n',
            '  - GATEWAY_SUMMARY_RECEIPT_KEY\n  - OUF_UDP_SEARCH_OWNER_KEY\n', 1):
        raise ValueError('candidate APISIX YAML differs beyond R4a env inheritance')
    live = json.loads(subprocess.run(['docker', 'inspect', 'ouf-udp', 'ouf-apisix'],
                                     check=True, capture_output=True, text=True).stdout)
    if {c['Name']: c['Id'] for c in live} != {name: c['Id'] for name, c in old.items()}:
        raise ValueError('running containers changed since snapshot')
    if not all(c['State']['Running'] for c in live):
        raise ValueError('original services must be running')
    result = ['PRIVATE_CANDIDATE_VERIFIED=true', 'ORIGINAL_CONTAINERS_UNCHANGED=true']
    for name in ('/ouf-udp', '/ouf-apisix'):
        c = old[name]
        host = c['HostConfig']
        networks = c['NetworkSettings']['Networks']
        for network, n in sorted(networks.items()):
            aliases = sorted(set(n.get('Aliases') or []) - {c['Name'][1:], c['Id'][:12]})
            result.append(f'{name[1:]} network={network} aliases={json.dumps(aliases)}')
        result.append(f'{name[1:]} image={c["Image"]} user={c["Config"]["User"]!r} '
                      f'memory={host["Memory"]} restart={host["RestartPolicy"]["Name"]} '
                      f'binds={len(c["Mounts"])} ports={len(c["NetworkSettings"]["Ports"] or {})} '
                      f'entrypoint_items={len(c["Config"].get("Entrypoint") or [])} '
                      f'cmd_items={len(c["Config"].get("Cmd") or [])}')
        result.append(f'{name[1:]} primary_network={host.get("NetworkMode")} '
                      f'host_port_bindings={len(host.get("PortBindings") or {})} '
                      f'publish_all={bool(host.get("PublishAllPorts"))} '
                      f'read_only={bool(host.get("ReadonlyRootfs"))} '
                      f'tmpfs={len(host.get("Tmpfs") or {})} '
                      f'memory_swap={host.get("MemorySwap")} '
                      f'ipc={host.get("IpcMode")} '
                      f'log_driver={host.get("LogConfig", {}).get("Type")}')
        advanced = ('CapAdd', 'CapDrop', 'SecurityOpt', 'Devices', 'DeviceRequests',
                    'Dns', 'ExtraHosts', 'Ulimits', 'Sysctls', 'Binds', 'Mounts',
                    'GroupAdd', 'VolumesFrom', 'Links', 'PidMode', 'UsernsMode',
                    'CgroupnsMode', 'IpcMode', 'ShmSize', 'NanoCpus', 'CpuShares',
                    'CpuQuota', 'CpuPeriod', 'PidsLimit', 'OomKillDisable', 'Init')
        result.append(f'{name[1:]} advanced_option_names=' + json.dumps(
            [field for field in advanced if host.get(field) not in (None, False, 0, '', [], {}, 'private')]))
        if host.get('Privileged') or host.get('NetworkMode') not in networks:
            result.append(f'{name[1:]} EXTRA_RUNTIME_REVIEW_REQUIRED=true')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root to read private runtime metadata')
    try:
        lines = check(args.snapshot, args.candidate)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as e:
        parser.exit(1, f'R4A_PREFLIGHT_BLOCKED: {type(e).__name__}\n')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
