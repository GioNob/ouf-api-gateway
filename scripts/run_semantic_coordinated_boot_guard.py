#!/usr/bin/env python3
"""Isolated root command composing sealed lease revocation and empty restoration."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


def private(path, limit=2_000_000):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe path')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit:
            raise ValueError('unsafe input')
        raw = os.read(fd, limit + 1)
        if len(raw) != info.st_size: raise ValueError('input drift')
        return raw
    finally:
        os.close(fd)


def sealed(path, expected):
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('explicit seal required')
    raw = private(path)
    if hashlib.sha256(raw).hexdigest() != expected: raise ValueError('seal drift')
    return raw


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError('duplicate key')
        value[key] = item
    return value


def load_source(path, expected, name):
    raw = sealed(path, expected)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def run(args):
    if os.geteuid() != 0 or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('root isolated no-bytecode Python required')
    profile = json.loads(sealed(args.configuration, args.configuration_sha256), object_pairs_hook=unique)
    if set(profile) != {'schema', 'sourceHashes', 'coordinatedConfiguration', 'coordinatedConfigurationHash',
                        'bootConfiguration', 'bootConfigurationHash', 'bootGuardFile', 'bootGuardHash'} \
            or profile['schema'] != 'ouf.semantic-coordinated-boot-profile.v1':
        raise ValueError('closed boot profile required')
    root = Path(__file__).resolve().parents[1]
    names = {'scripts/run_semantic_coordinated_boot_guard.py', 'tools/semantic_provider_boot_coordination.py'}
    if not isinstance(profile['sourceHashes'], dict) or set(profile['sourceHashes']) != names:
        raise ValueError('boot source closure required')
    for name in names: sealed(root/name, profile['sourceHashes'][name])
    # The coordinated configuration already closes the eight owner source files.
    owner_raw = sealed(Path(profile['coordinatedConfiguration']), profile['coordinatedConfigurationHash'])
    owner_profile = json.loads(owner_raw, object_pairs_hook=unique)
    owner_cli = load_source(root/'scripts/run_semantic_coordinated_lease_owner.py',
                            owner_profile['sourceHashes']['scripts/run_semantic_coordinated_lease_owner.py'],
                            'sealed_coordinated_owner')
    value = owner_cli.read_configuration(Path(profile['coordinatedConfiguration']),
                                        profile['coordinatedConfigurationHash'], root)
    boot = load_source(Path(profile['bootGuardFile']), profile['bootGuardHash'], 'sealed_empty_boot_guard')
    boot_value = json.loads(sealed(Path(profile['bootConfiguration']), profile['bootConfigurationHash']),
                            object_pairs_hook=unique)
    boot.validate(boot_value)  # verifies the original compiler closure
    if boot_value['kernel'] != value['kernel'] or boot_value['nftPath'] != value['nftPath'] \
            or boot_value['lockFile'] != value['commonLockFile'] \
            or boot_value['journalFile'] == value['journalFile']:
        raise ValueError('different kernel, lock, executable or journal cohort')
    sys.path.insert(0, str(root))
    from tools.semantic_provider_boot_coordination import prepare_docker_boot
    from tools.semantic_provider_lease_coordination import Coordinator, PrivateJournal, hold_common_lock
    from tools.semantic_provider_lease_nft import NftBackend
    from tools.semantic_provider_lease_owner import LeaseOwner
    backend = NftBackend([value['nftPath']], value['kernel'], value['expectedStructureHash'], value['readBudgetSeconds'])
    owner = LeaseOwner(value['kernel'], value['dns'], backend)
    journal = PrivateJournal(Path(value['journalFile']))
    coord = Coordinator(owner, value['binding'], lambda: hold_common_lock(Path(value['commonLockFile'])),
                        journal.read, journal.write)
    result = prepare_docker_boot(coord, lambda: boot.membership(boot_value),
                                 lambda: boot.restore(boot_value, profile['bootConfigurationHash']))
    print('SEMANTIC_COORDINATED_BOOT_GUARD=' + json.dumps(result, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', type=Path, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        run(args)
        return 0
    except Exception:
        print('SEMANTIC_COORDINATED_BOOT_GUARD=BLOCKED DOCKER_START_MUST_BE_DENIED=true NO_RAW_OUTPUT=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
