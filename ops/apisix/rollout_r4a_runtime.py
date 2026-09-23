#!/usr/bin/env python3
"""Stage R4a UDP then APISIX, retaining the original containers for rollback.

Default is dry-run. --apply changes one service at a time. No route is installed.
Private snapshot/candidate files stay on the host; this script prints no env values.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

IMAGES = {
    'udp': ('ouf-udp:r4a-3980fe2', 'sha256:96a0327f22ab07c34eaa3255b644b55e27d955519eefb4b218d83f3143f933be'),
    'apisix': ('sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d',
               'sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d'),
}


def docker(*args: str) -> str:
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True).stdout.strip()


def inspect(name: str) -> dict:
    return json.loads(docker('inspect', name))[0]


def env_map(entries: list[str]) -> dict[str, str]:
    out = {}
    for item in entries:
        name, sep, value = item.partition('=')
        if not sep or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) or name in out or '\n' in value or '\r' in value:
            raise ValueError('invalid environment format')
        out[name] = value
    return out


def private(path: Path, mode: int, uid=0, gid=0) -> None:
    st = path.stat()
    if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode) or path.is_symlink():
        raise ValueError('private file ownership or mode mismatch')


def snapshot_and_candidate(snapshot: Path, candidate: Path) -> dict:
    private(snapshot.parent, 0o700)
    private(snapshot, 0o600)
    private(candidate, 0o700)
    if candidate.parent != snapshot.parent or not candidate.name.startswith('candidate-'):
        raise ValueError('candidate is not adjacent to snapshot')
    old = {c['Name'][1:]: c for c in json.loads(snapshot.read_text(encoding='utf-8'))}
    if set(old) != {'ouf-udp', 'ouf-apisix'}:
        raise ValueError('unexpected snapshot')
    for service, original in [('udp', old['ouf-udp']), ('apisix', old['ouf-apisix'])]:
        f = candidate / f'{service}.env'
        private(f, 0o600)
        data = f.read_text(encoding='utf-8')
        if not data.endswith('\n'):
            raise ValueError('incomplete env file')
        now = env_map(data.splitlines())
        previous = env_map(original['Config']['Env'])
        additions = {'udp': {'OUF_UDP_SEARCH_TENANT_ID', 'OUF_UDP_SEARCH_ISSUER',
                             'OUF_UDP_SEARCH_AUDIENCE', 'OUF_UDP_SEARCH_WORKLOAD',
                             'OUF_UDP_SEARCH_OWNER_KEY_FILE'},
                     'apisix': {'OUF_UDP_SEARCH_OWNER_KEY'}}[service]
        if set(now) - set(previous) != additions or {k: v for k, v in now.items() if k not in additions} != previous:
            raise ValueError('existing environment changed')
        if service == 'udp' and now['OUF_UDP_SEARCH_OWNER_KEY_FILE'] != '/run/secrets/udp-search-owner.key':
            raise ValueError('unexpected UDP key target')
    key = candidate / 'udp-search-owner.key'
    private(key, 0o400, 10004, 10004)
    secret = key.read_text(encoding='ascii').strip()
    if not re.fullmatch('[a-f0-9]{64}', secret) or env_map((candidate/'apisix.env').read_text().splitlines())['OUF_UDP_SEARCH_OWNER_KEY'] != secret:
        raise ValueError('candidate keys differ')
    m = old['ouf-apisix']['Mounts']
    if len(m) != 1 or m[0]['Destination'] != '/usr/local/apisix/conf/config.yaml' or m[0]['RW']:
        raise ValueError('unexpected original APISIX bind')
    yaml = candidate / 'apisix-config.yaml'
    source = Path(m[0]['Source'])
    st, old_st = yaml.stat(), source.stat()
    if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (old_st.st_uid, old_st.st_gid, stat.S_IMODE(old_st.st_mode)):
        raise ValueError('YAML permissions changed')
    previous = source.read_text(encoding='utf-8')
    marker = '  - GATEWAY_SUMMARY_RECEIPT_KEY\n'
    if previous.count(marker) != 1 or 'OUF_UDP_SEARCH_OWNER_KEY' in previous or yaml.read_text(encoding='utf-8') != previous.replace(marker, marker+'  - OUF_UDP_SEARCH_OWNER_KEY\n', 1):
        raise ValueError('candidate YAML differs beyond one env name')
    return old


def validate(service: str, old: dict, candidate: Path, apply: bool) -> tuple[list[str], str]:
    name = 'ouf-' + service
    original = old[name]
    current = inspect(name)
    if current['Id'] != original['Id'] or not current['State']['Running']:
        raise ValueError('original service is no longer running at snapshot ID')
    if service == 'apisix' and apply:
        udp = inspect('ouf-udp')
        if udp['Image'] != IMAGES['udp'][1] or not udp['State']['Running']:
            raise ValueError('candidate UDP must run before APISIX')
    host = original['HostConfig']
    networks = original['NetworkSettings']['Networks']
    if service == 'udp':
        if (set(networks) != {'ouf-backend'} or original['Config']['User'] != '10004:10004' or
                host['Memory'] != 2147483648 or host['MemorySwap'] != 4294967296 or original['Mounts']):
            raise ValueError('UDP launch differs from reviewed baseline')
    elif (set(networks) != {'ouf-backend', 'ouf-gateway-control'} or
          host['NetworkMode'] != 'ouf-gateway-control' or original['Config']['User'] != 'apisix' or
          host['Memory'] != 0 or host['MemorySwap'] != 0 or len(original['Mounts']) != 1):
        raise ValueError('APISIX launch differs from reviewed baseline')
    if (host['NetworkMode'] not in networks or host['RestartPolicy']['Name'] != 'unless-stopped' or
            host.get('Privileged') or host.get('ReadonlyRootfs') or host.get('AutoRemove') or
            host.get('PortBindings') or host.get('PublishAllPorts') or host.get('Tmpfs') or
            host.get('CapAdd') or host.get('CapDrop') or host.get('SecurityOpt') or
            host.get('Devices') or host.get('DeviceRequests') or host.get('Dns') or
            host.get('ExtraHosts') or host.get('Ulimits') or host.get('Sysctls') or
            host.get('GroupAdd') or host.get('VolumesFrom') or host.get('Links') or
            host.get('PidMode') or host.get('UsernsMode') or host.get('NanoCpus') or
            host.get('CpuShares') or host.get('CpuQuota') or host.get('CpuPeriod') or
            host.get('PidsLimit') not in (None, 0) or host.get('OomKillDisable') or
            host.get('Init') or host.get('LogConfig', {}).get('Type') != 'json-file' or
            host.get('LogConfig', {}).get('Config') or host.get('IpcMode') != 'private'):
        raise ValueError('unsupported Docker launch option; review required')
    image, digest = IMAGES[service]
    image_info = json.loads(docker('image', 'inspect', image))[0]
    if image_info['Id'] != digest:
        raise ValueError('candidate image ID changed')
    image_config = image_info['Config']
    for key in ('Entrypoint', 'Cmd', 'WorkingDir', 'User'):
        if (original['Config'].get(key) or None) != (image_config.get(key) or None):
            raise ValueError('candidate image default launch differs from original')
    if image_config.get('Volumes') or image_config.get('Healthcheck') != original['Config'].get('Healthcheck'):
        raise ValueError('candidate image mount or healthcheck differs')
    args = ['create', '--name', name, '--pull', 'never', '--user', original['Config']['User'],
            '--restart', 'unless-stopped', '--network', host['NetworkMode'],
            '--shm-size', str(host['ShmSize']), '--log-driver', 'json-file',
            '--env-file', str(candidate / (service + '.env'))]
    if service == 'udp':
        args += ['--memory', str(host['Memory']), '--memory-swap', str(host['MemorySwap'])]
        args += ['--mount', 'type=bind,src='+str(candidate/'udp-search-owner.key')+',dst=/run/secrets/udp-search-owner.key,readonly']
    else:
        args += ['--mount', 'type=bind,src='+str(candidate/'apisix-config.yaml')+',dst=/usr/local/apisix/conf/config.yaml,readonly']
    for alias in sorted(set(networks[host['NetworkMode']].get('Aliases') or []) - {name, original['Id'][:12]}):
        args += ['--network-alias', alias]
    args.append(image)
    return args, digest


def save_state(path: Path, info: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(info, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def rollback(service: str, candidate: Path, state: dict) -> None:
    name, backup = 'ouf-'+service, state['backup']
    try:
        current = inspect(name)
    except subprocess.CalledProcessError:
        current = None
    if current and current['Id'] != state['old_id']:
        docker('update', '--restart', 'no', name)
        if current['State']['Running']:
            docker('stop', name)
        docker('rm', name)
    try:
        original = inspect(backup)
    except subprocess.CalledProcessError:
        original = None
    if original:
        if original['Id'] != state['old_id']:
            raise ValueError('rollback container identity mismatch')
        docker('rename', backup, name)
    restored = inspect(name)
    if restored['Id'] != state['old_id']:
        raise ValueError('cannot restore original container')
    if not restored['State']['Running']:
        docker('start', name)
    docker('update', '--restart', 'unless-stopped', name)
    if not inspect(name)['State']['Running']:
        raise ValueError('original container did not restart')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', required=True, type=Path)
    p.add_argument('--candidate', required=True, type=Path)
    p.add_argument('--service', choices=('udp', 'apisix'), required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error('run as root')
    state_path = a.candidate / ('rollout-' + a.service + '.json')
    try:
        if a.rollback:
            private(a.candidate, 0o700)
            private(state_path, 0o600)
            state = json.loads(state_path.read_text(encoding='utf-8'))
            if state['service'] != a.service:
                raise ValueError('rollback state differs from service')
            if a.service == 'udp':
                try:
                    api_state = json.loads((a.candidate/'rollout-apisix.json').read_text())
                    if inspect('ouf-apisix')['Id'] != api_state['old_id']:
                        raise ValueError('rollback APISIX before UDP')
                except FileNotFoundError:
                    pass
            rollback(a.service, a.candidate, state)
            print('ROLLBACK_RESTORED='+a.service)
            return
        old = snapshot_and_candidate(a.snapshot, a.candidate)
        args, digest = validate(a.service, old, a.candidate, a.apply)
        if state_path.exists():
            raise ValueError('service already staged; inspect state or rollback')
        print('R4A_DRY_RUN_OK='+a.service if not a.apply else 'R4A_APPLY_STARTED='+a.service)
        print('CANDIDATE_IMAGE_ID='+digest)
        print('ORIGINAL_ID_MATCH=true; ROLLBACK_ORIGINAL_RETAINED=true')
        if not a.apply:
            print('NO_CONTAINERS_CHANGED=true')
            return
        name = 'ouf-' + a.service
        backup = name + '-r4a-original'
        try:
            inspect(backup)
        except subprocess.CalledProcessError:
            pass
        else:
            raise ValueError('rollback name already exists')
        state = {'service': a.service, 'old_id': old[name]['Id'], 'backup': backup}
        save_state(state_path, state)
        try:
            docker('update', '--restart', 'no', name)
            docker('stop', name)
            docker('rename', name, backup)
            docker(*args)
            if a.service == 'apisix':
                docker('network', 'connect', 'ouf-backend', name)
            docker('start', name)
            time.sleep(5)
            current = inspect(name)
            if current['Image'] != digest or not current['State']['Running']:
                raise ValueError('candidate exited or has wrong image')
        except (subprocess.CalledProcessError, ValueError):
            rollback(a.service, a.candidate, state)
            raise ValueError('candidate failed; original restored')
        print('R4A_STAGED='+a.service)
        print('ORIGINAL_ROLLBACK_CONTAINER='+backup)
        print('HEALTH_AND_POLICY_PROBES_STILL_REQUIRED=true')
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        p.exit(1, 'R4A_ROLLOUT_BLOCKED: '+type(error).__name__+'\n')


if __name__ == '__main__':
    main()
