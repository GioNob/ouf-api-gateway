#!/usr/bin/env python3
"""Compile and prepare one private R4a route candidate; never write APISIX."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from tools.compile_config import ROOT, compile_config
from tools.apply_installation_projection import apply_projection
from tools.materialize_object_search import materialize

ROUTE_ID = 'execute-urban-object-search'


def docker(*args: str) -> str:
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True).stdout


def inspect(name: str) -> dict:
    return json.loads(docker('inspect', name))[0]


def write(path: Path, document: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        json.dump(document, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def prepare(candidate: Path, projection_path: Path) -> Path:
    candidate = candidate.resolve(strict=True)
    st = candidate.stat()
    if not candidate.is_dir() or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError('candidate must be a private root-owned directory')
    if ROOT.resolve() != (candidate / 'source').resolve():
        raise ValueError('run module from the archived R4a source under candidate/source')
    apisix, udp = inspect('ouf-apisix'), inspect('ouf-udp')
    if (not apisix['State']['Running'] or not udp['State']['Running'] or
            apisix['Image'] != 'sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d' or
            udp['Image'] != 'sha256:96a0327f22ab07c34eaa3255b644b55e27d955519eefb4b218d83f3143f933be'):
        raise ValueError('candidate container image or running state differs')
    if ('ouf-backend' not in apisix['NetworkSettings']['Networks'] or
            'ouf-backend' not in udp['NetworkSettings']['Networks']):
        raise ValueError('shared backend network missing')
    mounted = {m['Destination']: m for m in apisix['Mounts']}
    key_mounts = {m['Destination']: m for m in udp['Mounts']}
    if (mounted.get('/usr/local/apisix/conf/config.yaml', {}).get('Source') != str(candidate/'apisix-config.yaml') or
            key_mounts.get('/run/secrets/udp-search-owner.key', {}).get('Source') != str(candidate/'udp-search-owner.key') or
            mounted['/usr/local/apisix/conf/config.yaml']['RW'] or
            key_mounts['/run/secrets/udp-search-owner.key']['RW']):
        raise ValueError('R4a candidate mounts differ')
    env = dict(x.split('=', 1) for x in apisix['Config']['Env'] if '=' in x)
    udp_env = dict(x.split('=', 1) for x in udp['Config']['Env'] if '=' in x)
    key = (candidate / 'udp-search-owner.key').read_text(encoding='ascii').strip()
    if not re.fullmatch('[0-9a-f]{64}', key) or env.get('OUF_UDP_SEARCH_OWNER_KEY') != key:
        raise ValueError('APISIX and UDP key binding differs')
    nginx = docker('exec', 'ouf-apisix', 'cat', '/usr/local/apisix/conf/nginx.conf')
    if not re.search(r'^\s*env\s+(?:"OUF_UDP_SEARCH_OWNER_KEY"|OUF_UDP_SEARCH_OWNER_KEY)\s*;', nginx, re.M):
        raise ValueError('Nginx workers do not inherit the UDP search key')
    docker('exec', 'ouf-udp', 'wget', '-q', '-O', '/dev/null',
           'http://127.0.0.1:8080/actuator/health/readiness')
    p = json.loads(projection_path.read_text(encoding='utf-8'))
    expected = {'OUF_UDP_SEARCH_ISSUER': p['gateway']['issuerUrl'],
                'OUF_UDP_SEARCH_AUDIENCE': p['gateway']['requiredAudience'],
                'OUF_UDP_SEARCH_WORKLOAD': p['iam']['workloadClients']['mcpServer']}
    if any(udp_env.get(k) != v for k, v in expected.items()) or udp_env.get('OUF_UDP_SEARCH_TENANT_ID') != 'ouf-lab':
        raise ValueError('UDP search binding differs from active installation projection')
    paths = [candidate / (name+'.json') for name in ('compiled-r4a', 'runtime-r4a', 'materialization-r4a')]
    if any(path.exists() for path in paths):
        raise ValueError('route candidate files already exist')
    compiled = compile_config(ROOT / 'ouf-config')
    runtime = apply_projection(compiled, p)
    doc = materialize(runtime, '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET',
                      'OUF_GATEWAY_DELEGATION_KEY', 'OUF_AUTHORIZATION_OWNER_KEY',
                      'OUF_UDP_SEARCH_OWNER_KEY')
    routes = [r for r in doc['routes'] if r.get('id') == ROUTE_ID]
    if (len(routes) != 1 or routes[0]['uri'] != '/internal/capabilities/v1/execute/urban.object.search'
            or routes[0]['upstream']['nodes'] != {'ouf-udp-object-resolution:8080': 1}):
        raise ValueError('single bounded search route missing from materialization')
    for path, value in zip(paths, (compiled, runtime, doc)):
        write(path, value)
    return paths[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--projection', type=Path, default=Path('/opt/ouf/installation/active-projection.json'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root for private candidate output')
    try:
        path = prepare(args.candidate, args.projection)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'R4A_ROUTE_PREPARATION_BLOCKED: '+type(error).__name__+'\n')
    print('R4A_ROUTE_PREPARED_ONLY=true')
    print('MATERIALIZATION='+str(path))
    print('ROUTE_ID='+ROUTE_ID)
    print('APISIX_ROUTES_UNCHANGED=true')


if __name__ == '__main__':
    main()
