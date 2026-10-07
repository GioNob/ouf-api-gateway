#!/usr/bin/env python3
"""Root-private coordinated owner/guard. No authorization creation or table adoption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading

FILES = ('scripts/run_semantic_coordinated_lease_owner.py',
         'tools/semantic_provider_coordinated_supervisor.py', 'tools/semantic_provider_lease_coordination.py',
         'tools/semantic_provider_lease_owner.py', 'tools/semantic_provider_lease_nft.py',
         'tools/semantic_provider_dns.py', 'tools/materialize_southbound_kernel.py',
         'tools/materialize_southbound_lease_refresh.py')


def ancestors(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('safe private path required')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe ancestor')


def private(path, limit=131072):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('unsafe private input')
        raw = os.read(fd, limit + 1)
        if len(raw) != info.st_size:
            raise ValueError('private input drift')
        return raw
    finally:
        os.close(fd)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_configuration(path, expected_hash, source_root):
    if not re.fullmatch('[0-9a-f]{64}', expected_hash):
        raise ValueError('explicit configuration hash required')
    raw = private(path)
    if digest(raw) != expected_hash:
        raise ValueError('configuration hash drift')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate configuration key')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    keys = {'schema', 'kernel', 'dns', 'expectedStructureHash', 'nftPath', 'nftSha256',
            'readBudgetSeconds', 'pollSeconds', 'commonLockFile', 'journalFile', 'binding', 'sourceHashes'}
    if not isinstance(value, dict) or set(value) != keys \
            or value['schema'] != 'ouf.semantic-coordinated-owner-runtime.v1' \
            or not isinstance(value['sourceHashes'], dict) or set(value['sourceHashes']) != set(FILES):
        raise ValueError('coordinated configuration closure required')
    for name in FILES:
        if digest(private(source_root / name)) != value['sourceHashes'][name]:
            raise ValueError('source closure drift')
    # Namespace packages only; an unsealed initializer must never run as root.
    for package in ('scripts', 'tools'):
        if os.path.lexists(source_root / package / '__init__.py'):
            raise ValueError('unsealed package initializer')
    nft = Path(value['nftPath'])
    ancestors(nft)
    fd = os.open(nft, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or info.st_mode & 0o022 or not info.st_mode & 0o111 or info.st_nlink != 1 \
                or info.st_size > 16_777_216:
            raise ValueError('unsafe nft executable')
        raw_nft = os.read(fd, 16_777_217)
        if len(raw_nft) != info.st_size or digest(raw_nft) != value['nftSha256']:
            raise ValueError('nft executable drift')
    finally:
        os.close(fd)
    for key in ('commonLockFile', 'journalFile'):
        private(Path(value[key]))  # existing owned files only; never create a lock/journal
    if not isinstance(value['binding'], dict) \
            or value['binding'].get('leaseStructureHash') != value['expectedStructureHash']:
        raise ValueError('lease structure binding required')
    return value


def run(args):
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise ValueError('root and isolated Python required')
    source_root = Path(__file__).resolve().parents[1]
    value = read_configuration(args.configuration, args.configuration_sha256, source_root)
    sys.path.insert(0, str(source_root))
    # Load operational code only after the complete installed source closure is verified.
    from tools.semantic_provider_lease_coordination import Coordinator, PrivateJournal, hold_common_lock
    from tools.semantic_provider_lease_nft import NftBackend
    from tools.semantic_provider_lease_owner import LeaseOwner
    from tools.semantic_provider_coordinated_supervisor import supervise
    backend = NftBackend([value['nftPath']], value['kernel'], value['expectedStructureHash'], value['readBudgetSeconds'])
    owner = LeaseOwner(value['kernel'], value['dns'], backend)
    journal = PrivateJournal(Path(value['journalFile']))
    coordinator = Coordinator(owner, value['binding'], lambda: hold_common_lock(Path(value['commonLockFile'])),
                              journal.read, journal.write)
    def check():
        if read_configuration(args.configuration, args.configuration_sha256, source_root) != value:
            raise ValueError('sealed configuration changed')
    if args.mode == 'guard':
        result = coordinator.guard()
        if not result['dockerPrestartStructuralGate']:
            raise ValueError('Docker pre-start requires quiescence')
        print('SEMANTIC_COORDINATED_GUARD=PASS QUIESCED=true START_AUTHORIZED=false')
    elif args.mode == 'quiesce':
        coordinator.quiesce()
        print('SEMANTIC_COORDINATED_QUIESCE=PASS SETS_REVOKED=true REAUTHORIZATION_REQUIRED=true')
    else:
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        supervise(coordinator, check, value['pollSeconds'], stop)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=('guard', 'supervise', 'quiesce'))
    parser.add_argument('--configuration', type=Path, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        run(args)
        return 0
    except Exception:
        print('SEMANTIC_COORDINATED_OWNER=BLOCKED NO_RAW_OUTPUT=true START_AUTHORIZED=false')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
