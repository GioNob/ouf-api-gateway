#!/usr/bin/env python3
"""Supervised lease owner; root-private sealed config, exclusive lock, no API."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading

from scripts import prepare_semantic_provider_trust as trust
from tools.materialize_southbound_kernel import fields
from tools.semantic_provider_lease_nft import NftBackend
from tools.semantic_provider_lease_owner import LeaseOwner, LeaseDenied


def read_configuration(path, expected_hash):
    if not path.is_absolute() or '..' in path.parts or not re.fullmatch('[0-9a-f]{64}', expected_hash):
        raise trust.Blocked('SEALED_CONFIG_BINDING_REQUIRED')
    trust.ancestors(path.parent)
    raw = trust.read_file(path, 0, 0, limit=131072)
    if hashlib.sha256(raw).hexdigest() != expected_hash: raise trust.Blocked('CONFIG_HASH_DRIFT')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise trust.Blocked('DUPLICATE_CONFIG_KEY')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    fields(value, ('schema', 'kernel', 'dns', 'expectedStructureHash', 'nftPath', 'readBudgetSeconds', 'pollSeconds'))
    if value['schema'] != 'ouf.semantic-lease-owner-runtime.v1': raise trust.Blocked('CONFIG_SCHEMA_INVALID')
    nft_path = Path(value['nftPath'])
    if not nft_path.is_absolute() or '..' in nft_path.parts or not re.fullmatch('/[A-Za-z0-9_./-]+', str(nft_path)):
        raise trust.Blocked('EXPLICIT_NFT_EXECUTABLE_REQUIRED')
    # Timing is explicit and bounded; expiry still denies even if cadence loses.
    if type(value['pollSeconds']) is not int or not 1 <= value['pollSeconds'] <= 300:
        raise trust.Blocked('BOUNDED_POLL_INTERVAL_REQUIRED')
    return value


def lock(path):
    if not path.is_absolute() or '..' in path.parts: raise trust.Blocked('SAFE_LOCK_PATH_REQUIRED')
    trust.ancestors(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise trust.Blocked('LOCK_OWNER_MODE_UNSAFE')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except Exception:
        os.close(fd); raise trust.Blocked('OWNER_LOCK_UNAVAILABLE') from None


def supervise(owner, check_configuration, poll_seconds, stop, *, log=print):
    # Restart never restores cached relative TTL or an observation from disk.
    owner.revoke()
    try:
        while not stop.is_set():
            check_configuration()
            try:
                owner.refresh()
                log('SEMANTIC_LEASE_CYCLE=PASS FRESH_DNS=true BOTH_FAMILIES_READ_BACK=true', flush=True)
            except LeaseDenied as error:
                if str(error) != 'REFRESH_FAILED_SETS_REVOKED': raise
                log('SEMANTIC_LEASE_CYCLE=DENIED SETS_REVOKED=true', flush=True)
            stop.wait(poll_seconds)
    finally:
        owner.revoke()
        log('SEMANTIC_LEASE_STOP=PASS SETS_REVOKED=true', flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', type=Path, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    parser.add_argument('--lock-file', type=Path, required=True)
    args = parser.parse_args(argv); fd = None
    try:
        if os.geteuid() != 0: raise trust.Blocked('ROOT_REQUIRED')
        value = read_configuration(args.configuration, args.configuration_sha256)
        fd = lock(args.lock_file)
        backend = NftBackend([value['nftPath']], value['kernel'], value['expectedStructureHash'], value['readBudgetSeconds'])
        owner = LeaseOwner(value['kernel'], value['dns'], backend)
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, lambda *_: stop.set())
        def check():
            if read_configuration(args.configuration, args.configuration_sha256) != value:
                raise trust.Blocked('SEALED_CONFIGURATION_CHANGED')
        supervise(owner, check, value['pollSeconds'], stop)
        return 0
    except Exception:
        # Never dump config, DNS contents, subprocess output or arbitrary error.
        print('SEMANTIC_LEASE_OWNER=BLOCKED FINITE_EXPIRY_FALLBACK_REQUIRED=true NO_SECRETS_PRINTED=true', flush=True)
        return 1
    finally:
        if fd is not None: os.close(fd)


if __name__ == '__main__': raise SystemExit(main())
