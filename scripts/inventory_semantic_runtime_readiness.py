#!/usr/bin/env python3
"""Read-only custody and readiness gates after the empty runtime transition.

Load only an explicitly hash-bound installer from the original private cohort.
No DNS, sockets, container exec/start, unit reload or nft write is performed.
An inventory PASS proves custody of RUNTIME_EMPTY, never startup readiness.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace


def installer(args):
    path = args.stage_root.parent / 'source/scripts/transition_semantic_runtime_guard.py'
    if not args.stage_root.is_absolute() or '..' in args.stage_root.parts \
            or not re.fullmatch('[0-9a-f]{64}', args.installer_sha256):
        raise ValueError('explicit sealed source required')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe source ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 \
                or info.st_size > 131072:
            raise ValueError('unsafe source')
        raw = os.read(fd, 131073)
    finally:
        os.close(fd)
    if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != args.installer_sha256:
        raise ValueError('installer source drift')
    spec = importlib.util.spec_from_file_location('sealed_readiness_installer', path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def collect(args, installation):
    """Reuse the sealed installer's independent custody checks under its lock."""
    if os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', args.stage_source_commit):
        raise ValueError('root and explicit source required')
    stage_args = SimpleNamespace(stage_root=args.stage_root,
                                 stage_source_commit=args.stage_source_commit)
    def observe():
        prepared = installation.stage(stage_args)
        g, receipt, artifacts, conf, intent, roots, original, gu, unit, drop, _ = prepared
        journal = g.read(Path(conf['journalFile']))
        if journal.get('schema') != 'ouf.semantic-runtime-transition.v1' \
                or journal.get('state') != 'RUNTIME_EMPTY' \
                or journal.get('transactionId') != conf['transactionId'] \
                or journal.get('configurationHash') != receipt['configurationHash'] \
                or journal.get('stageReceiptHash') != g.digest(g.private(args.stage_root/'runtime-stage-receipt.json')) \
                or journal.get('startAuthorized') is not False:
            raise ValueError('incomplete or foreign journal')
        installation.independent(g, receipt, intent, roots, original, conf)
        tables = g.tables(conf)
        if g.footprint(tables) != conf['expectedFootprint'] or not g.sets_empty(tables) \
                or g.digest(g.encoded(g.stable(tables, True))) != journal.get('leaseStructureHash'):
            raise ValueError('runtime or lease structure drift')
        for path, name in ((unit, 'guard.service'), (drop, 'docker-drop-in.conf')):
            if g.private(path) != artifacts[name]:
                raise ValueError('installed artifact drift')
        installation.loaded(g, receipt, artifacts, original, gu, unit, drop)
        manifest = g.read(roots['manifest_root']/'stopped-manifest.json')
        kernel = conf['kernel']
        # Summaries deliberately omit endpoint URLs, credentials, env, mounts,
        # command lines and raw systemd/Docker/nft readbacks.
        result = {
            'schema': 'ouf.semantic-runtime-readiness.v1',
            'stageSourceCommit': args.stage_source_commit,
            'configurationHash': receipt['configurationHash'],
            'journalHash': g.digest(g.private(Path(conf['journalFile']))),
            'leaseStructureHash': journal['leaseStructureHash'],
            'runtimeState': 'RUNTIME_EMPTY', 'candidateCount': len(manifest['containers']),
            'candidatesNeverStarted': True, 'runtimeCustodyVerified': True,
            'staticPurposes': sorted({f['purpose'] for f in kernel['staticFlows']}),
            'staticFlowCount': len(kernel['staticFlows']),
            'providerFlowCount': len(kernel['providerFlows']),
            'providerSetsEmpty': True, 'guardProfile': 'EMPTY_ONLY',
            'guardedInterfaceCount': len(kernel['guardedInterfaces']),
            'excludedSharedInterfaceCount': len(kernel['existingInterfaces']),
            'startupReady': False, 'startAuthorized': False,
            'activeLeaseLifecycleReady': False,
            'unprovenGates': ['INFRASTRUCTURE_AUTHORITY', 'SHARED_FACE_SOURCE_ENFORCEMENT',
                'LIVE_NAMESPACE_ADDRESS_BINDING', 'PACKET_SPOOF_BYPASS_IPV6',
                'OIDC_PURPOSE_TLS_REVOCATION_ADMISSION', 'ACTIVE_LEASE_GUARD_COORDINATION',
                'REAL_REBOOT'],
            'readOnly': True, 'providerCalls': 0, 'dnsCalls': 0,
            'notReleaseAcceptance': True, 'noSecretsPrinted': True,
            'atomicSnapshotProven': False,
        }
        return result, g.digest(g.encoded({'receipt': receipt, 'conf': conf, 'intent': intent,
            'journal': journal, 'manifest': manifest, 'original': original}))

    # Read before acquiring the existing lock only to obtain its sealed path;
    # repeat every custody check twice under the lock and reject drift.
    prepared = installation.stage(stage_args)
    guard, conf = prepared[0], prepared[3]
    fd = guard.lock(Path(conf['lockFile']))
    try:
        first, seal = observe()
        if installation.stage(stage_args)[3]['lockFile'] != conf['lockFile']:
            raise ValueError('common lock drift')
        second, again = observe()
        if first != second or seal != again:
            raise ValueError('custody changed across reads')
        first['stableAcrossReads'] = True
        return first
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-root', type=Path, required=True)
    parser.add_argument('--stage-source-commit', required=True)
    parser.add_argument('--installer-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ValueError('root required')
        result = collect(args, installer(args))
        print('SEMANTIC_RUNTIME_READINESS='+json.dumps(result, sort_keys=True))
        print('SEMANTIC_RUNTIME_READINESS_INVENTORY=PASS READ_ONLY=true STARTUP_READY=false'
              ' START_AUTHORIZED=false NO_IAM_OR_DNS_CALL=true NO_RULE_UNIT_CONTAINER_CHANGED=true'
              ' NO_SECRETS_PRINTED=true')
        return 0
    except Exception:
        print('SEMANTIC_RUNTIME_READINESS_INVENTORY=BLOCKED READ_ONLY=true'
              ' START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
