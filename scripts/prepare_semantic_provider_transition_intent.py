#!/usr/bin/env python3
"""Seal transition preconditions under the installed boot lock; no activation."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


LEASE_FILES = {
    'scripts/stage_semantic_lease_package.py', 'scripts/run_semantic_provider_lease_owner.py',
    'scripts/prepare_semantic_provider_trust.py', 'tools/materialize_semantic_lease_service.py',
    'tools/materialize_southbound_kernel.py', 'tools/materialize_southbound_lease_refresh.py',
    'tools/semantic_provider_dns.py', 'tools/semantic_provider_lease_owner.py',
    'tools/semantic_provider_lease_nft.py',
}


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def directory(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe directory')
    for p in (path, *path.parents):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('unsafe ancestor')


def private(path, limit=131072):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_nlink != 1 \
                or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > limit:
            raise ValueError('unsafe file')
        raw = os.read(fd, limit + 1)
        if len(raw) > limit: raise ValueError('size limit')
        return raw
    finally: os.close(fd)


def unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result: raise ValueError('duplicate key')
        result[k] = v
    return result


def read(path):
    raw = private(path)
    return json.loads(raw, object_pairs_hook=unique), digest(raw)


def write(path, raw):
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)


def lock(path):
    # Reuse the *existing* boot lock inode; do not create a second lock domain.
    directory(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_nlink != 1 \
                or stat.S_IMODE(s.st_mode) != 0o600: raise ValueError('unsafe boot lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = path.lstat()
        if (s.st_dev, s.st_ino) != (current.st_dev, current.st_ino): raise ValueError('lock replaced')
        return fd, (s.st_dev, s.st_ino)
    except Exception:
        os.close(fd); raise


def shared(value, table, canonical):
    if not isinstance(value, dict) or set(value) != {'nftables'} or not isinstance(value['nftables'], list):
        raise ValueError('ruleset shape')
    kept = []
    for entry in value['nftables']:
        if not isinstance(entry, dict): raise ValueError('ruleset entry')
        owned = any(isinstance(obj, dict) and obj.get('family') in ('inet', 'bridge') \
                    and (obj.get('table') == table or key == 'table' and obj.get('name') == table)
                    for key, obj in entry.items())
        if not owned: kept.append(entry)
    return canonical({'nftables': kept}, True)


def load_custody(args):
    path = Path(__file__).parent/'inventory_semantic_provider_guard_custody.py'
    if digest(private(path)) != args.custody_source_sha256: raise ValueError('custody source drift')
    spec = importlib.util.spec_from_file_location('sealed_transition_custody', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def capture(args, custody):
    report = custody.operate(args)
    for key, expected in (('manifestHash', args.expected_manifest_hash),
                          ('creationJournalHash', args.expected_creation_journal_hash),
                          ('bootInstallJournalHash', args.expected_boot_install_journal_hash)):
        if report.get(key) != expected: raise ValueError('operator custody binding drift')
    stage, stage_hash = read(args.boot_stage_root/'boot-stage-receipt.json')
    conf, conf_hash = read(args.boot_stage_root/'boot-configuration.json')
    cold, _ = read(args.network_root/'network-receipt.json')
    runtime, runtime_hash = read(args.runtime_root/'stage-receipt.json')
    if runtime.get('schema') != 'ouf.semantic-provider-runtime-stage.v1' \
            or runtime.get('notReleaseAcceptance') is not True or runtime.get('providerCalls') != 0:
        raise ValueError('runtime receipt invalid')
    for name, key in (('binding.json', 'bindingHash'), ('runtime-plan.json', 'planHash')):
        if digest(private(args.runtime_root/name)) != runtime[key]: raise ValueError('runtime drift')
    package, package_hash = read(args.lease_package_root/'source-package-receipt.json')
    if package.get('schema') != 'ouf.semantic-lease-source-package.v1' \
            or package.get('sourceCommit') != args.lease_source_commit \
            or set(package.get('sourceHashes', {})) != LEASE_FILES \
            or any(package.get(k) is not False for k in ('daemonStarted','systemdUnitInstalled','rulesChanged')) \
            or package.get('providerCalls') != 0 or package.get('notReleaseAcceptance') is not True:
        raise ValueError('lease cohort invalid')
    if stage.get('leasePackageReceiptHash') != package_hash: raise ValueError('boot lease cohort mismatch')
    for name, expected in package['sourceHashes'].items():
        if digest(private(args.lease_package_root/'source'/name)) != expected: raise ValueError('lease source drift')
    table = conf['tableName']
    whole = json.loads(custody.run([args.nft_path, '-j', 'list', 'ruleset']), object_pairs_hook=unique)
    owned = {f: json.loads(custody.run([args.nft_path, '-j', 'list', 'table', f, table]),
                           object_pairs_hook=unique) for f in ('inet', 'bridge')}
    owned = custody.canonical(owned)
    if digest(encoded(owned)) != read(args.manifest_root/'stopped-manifest.json')[0]['guardHash'] \
            or digest(encoded(custody.canonical(owned, True))) != conf['expectedFootprint']:
        raise ValueError('owned table changed')
    shared_rules = shared(whole, table, custody.canonical)
    result = {'schema': 'ouf.semantic-provider-transition-intent.v1', 'sourceCommit': args.source_commit,
        'custodySourceHash': args.custody_source_sha256,
        'intentSourceHash': digest(private(Path(__file__).resolve())),
        'state': 'PREFLIGHT_ONLY', 'custody': report,
        'bootStageReceiptHash': stage_hash, 'bootConfigurationHash': conf_hash,
        'runtimeReceiptHash': runtime_hash, 'leasePackageReceiptHash': package_hash,
        'roots': {k: str(getattr(args, k)) for k in ('manifest_root','creation_root','network_root',
                  'boot_stage_root','boot_install_root','runtime_root','lease_package_root','snapshot_root')},
        'bootLockFile': str(args.boot_lock_file),
        'tableName': table, 'guardedInterfaces': [cold['binding'][k] for k in ('internal_bridge','egress_bridge')],
        'ownedTableHash': digest(encoded(owned)), 'sharedStructureHash': digest(encoded(shared_rules)),
        'bootFootprint': conf['expectedFootprint'],
        'runtimeRulesApplied': False, 'runtimeGuardImplemented': False, 'startAuthorized': False,
        'leaseDaemonInstalled': False, 'kernelLeaseInstalled': False, 'providerCalls': 0,
        'notReleaseAcceptance': True, 'globalAtomicSnapshotProven': False,
        'requiredNext': ['SEALED_RUNTIME_GUARD_AND_COMMON_LOCK', 'EXPLICIT_GOVERNED_STATIC_FLOW_PROFILE',
            'EMPTY_PROVIDER_SETS_BOOTSTRAP', 'NATIVE_TRANSITION_AND_PARTIAL_RECOVERY_TESTS',
            'JOURNALLED_APPLY_AND_LOADED_PRESTART_CHECK', 'SEPARATE_POST_APPLY_LEASE_STRUCTURE_BINDING']}
    return result, owned, shared_rules


def operate(args, custody=None):
    if os.geteuid() != 0: raise ValueError('root required')
    for key in ('source_commit','lease_source_commit','creation_source_commit'):
        if not re.fullmatch('[0-9a-f]{40}', getattr(args, key)): raise ValueError('source binding required')
    for key in ('custody_source_sha256','expected_manifest_hash','expected_creation_journal_hash',
                'expected_boot_install_journal_hash'):
        if not re.fullmatch('[0-9a-f]{64}', getattr(args, key)): raise ValueError('hash binding required')
    for k in ('docker_path','nft_path','systemctl_path'):
        if not re.fullmatch('/[A-Za-z0-9_./-]+', getattr(args, k)) or '..' in Path(getattr(args, k)).parts:
            raise ValueError('unsafe executable')
    directory(args.snapshot_root.parent)
    if args.mode != 'verify' and os.path.lexists(args.snapshot_root): raise ValueError('existing intent reconcile')
    custody = load_custody(args) if custody is None else custody
    stage, _ = read(args.boot_stage_root/'boot-stage-receipt.json')
    rd = stage['profile']['runtimeDirectory']
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', rd) \
            or args.boot_lock_file != Path('/run')/rd/'guard.lock': raise ValueError('different boot lock')
    # Confirm the installed/loaded source and profile before touching its lock.
    custody.operate(args)
    fd, inode = lock(args.boot_lock_file)
    try:
        first = capture(args, custody)
        second = capture(args, custody)
        s = args.boot_lock_file.lstat()
        if (s.st_dev, s.st_ino) != inode or first != second: raise ValueError('preflight readback drift')
        result, owned, shared_rules = first
        artifacts = {'transition-intent.json': encoded(result), 'owned-before.json': encoded(owned),
                     'shared-before.json': encoded(shared_rules)}
        if args.mode == 'verify':
            directory(args.snapshot_root)
            if stat.S_IMODE(args.snapshot_root.stat().st_mode) != 0o700: raise ValueError('snapshot mode')
            for name, raw in artifacts.items():
                if private(args.snapshot_root/name, 2_000_000) != raw: raise ValueError('saved intent drift')
        elif args.mode == 'apply':
            args.snapshot_root.mkdir(mode=0o700)
            for name, raw in artifacts.items(): write(args.snapshot_root/name, raw)
            parent_fd = os.open(args.snapshot_root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
        return result
    finally: os.close(fd)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('plan','apply','verify'), required=True)
    for k in ('manifest-root','creation-root','network-root','boot-stage-root','boot-install-root',
              'runtime-root','lease-package-root','snapshot-root','boot-lock-file'):
        p.add_argument('--'+k, type=Path, required=True)
    for k in ('source-commit','lease-source-commit','creation-source-commit','custody-source-sha256',
              'expected-manifest-hash','expected-creation-journal-hash','expected-boot-install-journal-hash',
              'docker-path','nft-path','systemctl-path'):
        p.add_argument('--'+k, required=True)
    args = p.parse_args(argv)
    try:
        operate(args)
        print('SEMANTIC_PROVIDER_TRANSITION_INTENT=PASS MODE='+args.mode+
              ' BOOT_LOCK_REUSED=true PRIVATE_INTENT_ONLY=true NO_RUNTIME_RULE_CHANGED=true'
              ' NO_UNIT_CHANGED=true NO_CONTAINER_CHANGED=true START_AUTHORIZED=false'
              ' PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_PROVIDER_TRANSITION_INTENT_ROOT='+str(args.snapshot_root)+' PRIVATE=true')
        return 0
    except Exception:
        print('SEMANTIC_PROVIDER_TRANSITION_INTENT=BLOCKED PARTIAL_EVIDENCE_RETAINED=true'
              ' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
