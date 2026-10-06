#!/usr/bin/env python3
"""Seal a root-private source package; never install/start a service or rules."""
import argparse
import json
import os
from pathlib import Path
import re

from scripts import prepare_semantic_provider_trust as trust


FILES = (
    'scripts/stage_semantic_lease_package.py', 'scripts/run_semantic_provider_lease_owner.py',
    'scripts/prepare_semantic_provider_trust.py', 'tools/materialize_semantic_lease_service.py',
    'tools/materialize_southbound_kernel.py', 'tools/materialize_southbound_lease_refresh.py',
    'tools/semantic_provider_dns.py', 'tools/semantic_provider_lease_owner.py', 'tools/semantic_provider_lease_nft.py',
)


def operate(args):
    if os.geteuid() != 0: raise trust.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit): raise trust.Blocked('IMMUTABLE_SOURCE_REQUIRED')
    root = args.package_root
    if not root.is_absolute() or '..' in root.parts: raise trust.Blocked('SAFE_ABSOLUTE_ROOT_REQUIRED')
    trust.ancestors(root)
    hashes = {}
    for name in FILES:
        path = root/'source'/name; trust.ancestors(path.parent)
        hashes[name] = trust.digest(trust.read_file(path, 0, 0))
    binding = {'schema': 'ouf.semantic-lease-source-package.v1', 'sourceCommit': args.source_commit,
               'sourceHashes': hashes, 'daemonStarted': False, 'systemdUnitInstalled': False,
               'rulesChanged': False, 'providerCalls': 0, 'notReleaseAcceptance': True}
    receipt = root/'source-package-receipt.json'
    if args.mode == 'verify':
        saved = json.loads(trust.read_file(receipt, 0, 0))
        if saved != binding: raise trust.Blocked('PACKAGE_BINDING_DRIFT')
    else:
        if receipt.exists() or receipt.is_symlink(): raise trust.Blocked('PACKAGE_RECEIPT_EXISTS_RECONCILE')
        if args.mode == 'apply': trust.write(receipt, json.dumps(binding, sort_keys=True).encode())
    return binding


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('plan','apply','verify'), required=True)
    parser.add_argument('--package-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args(argv)
    try:
        result = operate(args)
        print('SEMANTIC_LEASE_PACKAGE=PASS MODE='+args.mode+' FILES='+str(len(result['sourceHashes']))+
              ' ROOT_PRIVATE=true NO_DAEMON_STARTED=true NO_UNIT_INSTALLED=true NO_RULE_CHANGED=true'+
              ' NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_LEASE_PACKAGE_RECEIPT='+str(args.package_root/'source-package-receipt.json')+' PRIVATE=true')
        return 0
    except Exception:
        print('SEMANTIC_LEASE_PACKAGE=BLOCKED DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
