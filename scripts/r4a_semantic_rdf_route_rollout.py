#!/usr/bin/env python3
"""Install the pinned Semantic HUMAN route set after the Registry review-card upgrade.

Uses the active installation projection; the installer snapshots only its eight
Semantic route IDs, verifies readback and anonymous denial, and restores on
failure. This script never reads or prints OAuth secret values.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPO = Path('/opt/ouf/gateway')
SNAPSHOTS = Path('/etc/ouf/deploy-snapshots')
PROJECTION = Path('/opt/ouf/installation/active-projection.json')
SECRET_REF = '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET'


def run(argv, *, env=None, input=None):
    done = subprocess.run(argv, env=env, input=input, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=False)
    if done.returncode:
        raise RuntimeError('COMMAND_FAILED_' + Path(argv[0]).name.upper().replace('-', '_'))
    return done.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'apply'))
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', args.revision):
        raise RuntimeError('ROOT_AND_PINNED_REVISION_REQUIRED')
    safe = ['git', '-c', 'safe.directory=' + str(REPO), '-C', str(REPO)]
    if run([*safe, 'rev-parse', args.revision + '^{commit}']).decode().strip() != args.revision:
        raise RuntimeError('PINNED_SOURCE_UNAVAILABLE')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='r4a-semantic-rdf-', dir=SNAPSHOTS) as directory:
        work = Path(directory)
        archive = subprocess.Popen([*safe, 'archive', '--format=tar', args.revision],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            unpack = subprocess.run(['tar', '-xf', '-', '-C', str(work)],
                                    stdin=archive.stdout, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False)
        finally:
            archive.stdout.close()
        if archive.wait() or unpack.returncode:
            raise RuntimeError('PINNED_ARCHIVE_FAILED')
        env = {**os.environ, 'PYTHONPATH': str(work)}
        runtime = work / 'runtime.json'
        program = '''import json,sys
from pathlib import Path
from tools.compile_config import compile_config
from tools.apply_installation_projection import apply_projection
root, projection, output = map(Path, sys.argv[1:])
projected = apply_projection(compile_config(root / "ouf-config"), json.loads(projection.read_text()))
output.write_text(json.dumps(projected))
'''
        run([sys.executable, '-P', '-c', program, str(work), str(PROJECTION), str(runtime)], env=env)
        materialization = work / 'routes.json'
        run([sys.executable, '-P', '-m', 'tools.materialize_semantic_human_runtime',
             '--runtime', str(runtime), '--oidc-client-secret-ref', SECRET_REF,
             '--output', str(materialization)], env=env)
        verification = '''import json,sys
from ops.apisix.deploy_semantic_human import validate
routes = validate(json.load(open(sys.argv[1])))
assert len(routes) == 8 and sum(r["id"] == "semantic-rdf-import" for r in routes) == 1
print("SEMANTIC_RDF_ROUTE_MATERIALIZED=true COUNT=8")
'''
        print(run([sys.executable, '-P', '-c', verification, str(materialization)], env=env).decode().strip())
        if args.mode == 'plan':
            print('NO_PERSISTENT_WRITES=true')
            return
        result = run([sys.executable, '-P', '-m', 'ops.apisix.deploy_semantic_human',
                      '--materialization', str(materialization), '--admin-key',
                      '/opt/ouf/secrets/apisix-admin-key', '--backup-dir', str(SNAPSHOTS)], env=env)
        output = result.decode()
        if 'SEMANTIC_HUMAN_ROUTES_ACTIVE=true COUNT=8' not in output:
            raise RuntimeError('ROUTE_INSTALL_NOT_VERIFIED')
        for line in output.splitlines():
            if line.startswith('BACKUP='):
                print(line)
        print('SEMANTIC_RDF_GATEWAY_ROLLOUT=PASS ROUTES=8')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print('SEMANTIC_RDF_GATEWAY_BLOCKED=' + str(exc), file=sys.stderr)
        raise SystemExit(1)
