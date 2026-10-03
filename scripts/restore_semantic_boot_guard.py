#!/usr/bin/env python3
"""Restore two sealed deny-only tables before Docker; never adopt foreign rules."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def private(path, limit=131072):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe path')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('unsafe ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 \
                or info.st_size > limit or stat.S_IMODE(info.st_mode) != 0o600: raise ValueError('unsafe file')
        raw = os.read(fd, limit+1)
        if len(raw) > limit: raise ValueError('large file')
        return raw
    finally: os.close(fd)


def normalized(value):
    if isinstance(value, list): return [normalized(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes', 'expires')}
    return value


def footprint(value):
    return hashlib.sha256(json.dumps(normalized(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def execute(command, raw=None):
    value = subprocess.run(command, input=raw, capture_output=True, text=True, timeout=20)
    if value.returncode or len(value.stdout) > 2_000_000: raise ValueError('nft operation unproven')
    return value.stdout


def observed(nft, table):
    return {f: json.loads(execute([nft, '-j', 'list', 'table', f, table])) for f in ('inet', 'bridge')}


def restore(value):
    if set(value) != {'schema', 'nftPath', 'tableName', 'rules', 'expectedFootprint'} \
            or value['schema'] != 'ouf.semantic-deny-boot-guard.v1' \
            or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', value['tableName']) \
            or not re.fullmatch('/[A-Za-z0-9_./-]+', value['nftPath']) \
            or '..' in Path(value['nftPath']).parts \
            or not re.fullmatch('[0-9a-f]{64}', value['expectedFootprint']): raise ValueError('sealed profile invalid')
    table = value['tableName']; nft = value['nftPath']; rules = value['rules']
    prefix = 'create table inet '+table+'\ncreate table bridge '+table+'\n'
    if not isinstance(rules, str) or not rules.startswith(prefix) or 'flush ' in rules or 'delete ' in rules \
            or 'elements' in rules or ' set ' in rules: raise ValueError('deny-only bootstrap required')
    current = json.loads(execute([nft, '-j', 'list', 'tables']))
    selected = {f for item in current['nftables'] if 'table' in item
                for f in (item['table']['family'],) if f in ('inet', 'bridge') and item['table']['name'] == table}
    if selected and selected != {'inet', 'bridge'}: raise ValueError('partial ownership requires reconciliation')
    if selected:
        if footprint(observed(nft, table)) != value['expectedFootprint']: raise ValueError('existing ownership drift')
        return False
    before = json.loads(execute([nft, '-j', 'list', 'ruleset']))
    execute([nft, '-f', '-'], rules)
    if footprint(observed(nft, table)) != value['expectedFootprint']: raise ValueError('restored structure drift')
    after = json.loads(execute([nft, '-j', 'list', 'ruleset']))
    after['nftables'] = [v for v in after['nftables'] if not any(isinstance(item, dict)
        and item.get('family') in ('inet','bridge') and (item.get('table') == table or key == 'table' and item.get('name') == table)
        for key, item in v.items())]
    if footprint(before) != footprint(after): raise ValueError('shared structure changed')
    return True


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--configuration', type=Path, required=True)
    p.add_argument('--configuration-sha256', required=True)
    p.add_argument('--lock-file', type=Path, required=True)
    args = p.parse_args(argv); fd = None
    try:
        if os.geteuid() != 0: raise ValueError('root required')
        raw = private(args.configuration)
        if not re.fullmatch('[0-9a-f]{64}', args.configuration_sha256) or hashlib.sha256(raw).hexdigest() != args.configuration_sha256:
            raise ValueError('sealed profile drift')
        # Reuse private-file ancestry validation before creating the lock.
        for directory in (args.lock_file.parent, *args.lock_file.parent.parents):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022: raise ValueError('unsafe lock ancestor')
        if not args.lock_file.is_absolute() or '..' in args.lock_file.parts: raise ValueError('safe lock path required')
        fd = os.open(args.lock_file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('unsafe lock file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        created = restore(json.loads(raw))
        print('SEMANTIC_BOOT_GUARD=PASS RESTORED='+str(created).lower()+' DENY_ONLY=true SHARED_RULES_PRESERVED=true NO_PROVIDER_CALL=true', flush=True)
        return 0
    except Exception:
        print('SEMANTIC_BOOT_GUARD=BLOCKED DOCKER_START_MUST_BE_DENIED=true NO_SECRETS_PRINTED=true', flush=True)
        return 1
    finally:
        if fd is not None: os.close(fd)


if __name__ == '__main__': raise SystemExit(main())
