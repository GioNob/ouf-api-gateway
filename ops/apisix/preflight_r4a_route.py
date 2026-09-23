#!/usr/bin/env python3
"""Read-only APISIX Admin preflight for the private R4a materialization."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from ops.apisix.deploy_status_execute import Admin, inherits_env
from ops.apisix.deploy_object_search import ROUTE_ID, ROUTE_URI


def preflight(materialization: Path, key: Path, backup: Path) -> None:
    doc_path = materialization.resolve(strict=True)
    b = backup.resolve(strict=True)
    if (doc_path.stat().st_uid != 0 or stat.S_IMODE(doc_path.stat().st_mode) != 0o600 or
            b.stat().st_uid != 0 or stat.S_IMODE(b.stat().st_mode) != 0o700):
        raise ValueError('private materialization or backup permissions differ')
    doc = json.loads(doc_path.read_text(encoding='utf-8'))
    routes = [r for r in doc['routes'] if r.get('id') == ROUTE_ID]
    if (len(routes) != 1 or routes[0]['uri'] != ROUTE_URI or routes[0]['methods'] != ['POST'] or
            routes[0]['upstream']['nodes'] != {'ouf-udp-object-resolution:8080': 1} or
            routes[0]['upstream']['retries'] != 0 or
            routes[0]['plugins']['proxy-rewrite']['uri'] != '/api/udp/v1/objects/search'):
        raise ValueError('materialization does not contain the reviewed search route')
    apisix = json.loads(subprocess.run(['docker','inspect','ouf-apisix'],check=True,capture_output=True,text=True).stdout)[0]
    env = dict(x.split('=',1) for x in apisix['Config']['Env'] if '=' in x)
    names = (doc.get('delegationKeyEnv',''), doc.get('udpOwnerKeyEnv',''))
    if (names != ('OUF_GATEWAY_DELEGATION_KEY', 'OUF_UDP_SEARCH_OWNER_KEY') or
            any(not re.fullmatch('[A-Z][A-Z0-9_]{0,127}', n) or not re.fullmatch('[0-9a-fA-F]{64}',env.get(n,'')) for n in names) or
            routes[0]['plugins']['openid-connect'].get('client_secret') != '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET' or
            not env.get('OUF_GATEWAY_OIDC_CLIENT_SECRET')):
        raise ValueError('OIDC or dedicated signing key binding is missing')
    nginx = subprocess.run(['docker','exec','ouf-apisix','cat','/usr/local/apisix/conf/nginx.conf'],
                           check=True,capture_output=True,text=True).stdout
    if not all(inherits_env(nginx,n) for n in names):
        raise ValueError('Nginx does not inherit the required keys')
    if not key.is_file() or not key.read_text().strip():
        raise ValueError('APISIX Admin key file is missing or empty')
    image = 'curlimages/curl:8.16.0'
    subprocess.run(['docker','image','inspect',image],check=True,capture_output=True,text=True)
    args = argparse.Namespace(backup_dir=b,admin_key=key,container='ouf-apisix',curl_image=image)
    with contextlib.redirect_stdout(io.StringIO()):
        admin = Admin(args)
    try:
        code, _ = admin('GET', ROUTE_ID)
        if code != 404:
            raise ValueError('search route ID already exists or Admin API did not return 404')
    finally:
        shutil.rmtree(admin.work)
    print('R4A_ROUTE_PREFLIGHT=PASS')
    print('SEARCH_ROUTE_CURRENTLY_ABSENT=true')
    print('APISIX_ADMIN_READ_ONLY=true')
    print('BACKUP_ROOT_PRIVATE=true')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialization',required=True,type=Path)
    parser.add_argument('--admin-key',required=True,type=Path)
    parser.add_argument('--backup-dir',type=Path,default=Path('/opt/ouf/backup'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root')
    try:
        preflight(args.materialization,args.admin_key,args.backup_dir)
    except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError,json.JSONDecodeError) as error:
        parser.exit(1,'R4A_ROUTE_PREFLIGHT_BLOCKED: '+type(error).__name__+'\n')


if __name__ == '__main__':
    main()
