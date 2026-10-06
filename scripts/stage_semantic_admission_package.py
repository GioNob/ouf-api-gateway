"""Seal a new private admission source package v3. No runtime/network installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from importlib.util import module_from_spec, spec_from_file_location


def metadata(path):
    for parent in (path.parent, *path.parent.parents):
        value = parent.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise RuntimeError('PRIVATE_ANCESTOR_REQUIRED')
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_gid != 0 \
            or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or value.st_size > 131072:
        raise RuntimeError('PRIVATE_SOURCE_REQUIRED')


def operate(mode, root, commit, hook_hash):
    if os.geteuid() != 0 or not root.is_absolute() or '..' in root.parts \
            or not re.fullmatch('[0-9a-f]{40}', commit) or not re.fullmatch('[0-9a-f]{64}', hook_hash):
        raise RuntimeError('EXPLICIT_PRIVATE_SOURCE_BINDING_REQUIRED')
    value = root.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or stat.S_IMODE(value.st_mode) != 0o700:
        raise RuntimeError('NEW_PRIVATE_PACKAGE_REQUIRED')
    source = root/'source'; hook = source/'scripts/semantic_provider_preexec_hook.py'; metadata(hook)
    raw = hook.read_bytes()
    if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != hook_hash:
        raise RuntimeError('TRUSTED_BOOTSTRAP_HASH_REQUIRED')
    # The bootstrap is pinned before importing its metadata reader/constants.
    spec = spec_from_file_location('private_preexec_bootstrap', hook)
    module = module_from_spec(spec)
    exec(compile(raw, str(hook), 'exec'), module.__dict__)
    names = ['scripts/stage_semantic_admission_package.py', 'scripts/stage_semantic_preexec_package.py',
             'scripts/semantic_provider_docker_runtime.py', module.SELF,
             'scripts/semantic_provider_admission_preparer.py',
             *('tools/'+name+'.py' for name in module.MODULES), 'tools/semantic_provider_deployment_admission.py']
    if Path(__file__).absolute() != source/names[0]: raise RuntimeError('EXACT_STAGE_SOURCE_REQUIRED')
    hashes = {name: hashlib.sha256(module.private_bytes(source/name)).hexdigest() for name in names}
    capabilities = {}
    for name, path in {'python': '/usr/bin/python3', 'runc': '/usr/bin/runc', 'nft': '/usr/sbin/nft',
            'ip': '/usr/sbin/ip', 'nsenter': '/usr/bin/nsenter', 'unshare': '/usr/bin/unshare',
            'busybox': '/usr/bin/busybox','mount':'/usr/bin/mount','umount':'/usr/bin/umount'}.items():
        target = Path(path)
        try:
            resolved = target.resolve(strict=True); info = resolved.lstat()
            trusted = stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 \
                and bool(info.st_mode & 0o111)
            for parent in (resolved.parent, *resolved.parent.parents):
                item = parent.lstat()
                trusted = trusted and stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022
        except OSError: trusted = False
        capabilities[name] = bool(trusted)
    receipt = {'schema': 'ouf.semantic-admission-source-package.v3', 'sourceCommit': commit,
        'sourceHashes': hashes, 'pythonVersion': '.'.join(map(str, sys.version_info[:3])),
        'trustedToolsAvailable': capabilities, 'runtimeRegistered': False, 'rulesChanged': False,
        'unitsChanged': False, 'containersChanged': False, 'startAuthorized': False,
        'runtimeAdapterInstalled': False, 'admissionPreparerInstalled': False,
        'providerCalls': 0, 'notReleaseAcceptance': True, 'noSecretsPrinted': True}
    path = root/'source-package-receipt.json'
    if mode == 'verify':
        if module.parse(module.private_bytes(path)) != receipt: raise RuntimeError('PRIVATE_PACKAGE_DRIFT')
    elif mode in ('plan', 'apply'):
        if path.exists() or path.is_symlink(): raise RuntimeError('DO_NOT_REPLAY_PACKAGE_APPLY')
        if mode == 'apply':
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                raw = json.dumps(receipt, sort_keys=True).encode()
                with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(fd)
            finally: os.close(fd)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
    else: raise RuntimeError('EXPLICIT_PACKAGE_MODE_REQUIRED')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=['plan', 'apply', 'verify'])
    parser.add_argument('--package-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--hook-source-sha256', required=True)
    args = parser.parse_args()
    try:
        result = operate(args.mode, args.package_root, args.source_commit, args.hook_source_sha256)
        print('SEMANTIC_ADMISSION_PACKAGE='+json.dumps(result, sort_keys=True))
        print('SEMANTIC_ADMISSION_PACKAGE=PASS MODE='+args.mode+' PRIVATE_SOURCE_ONLY=true'
              ' NO_RULE_UNIT_CONTAINER_CHANGED=true RUNTIME_REGISTERED=false START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 0
    except Exception as error:
        reason = str(error)
        if not re.fullmatch('[A-Z_]{1,80}', reason): reason = 'PRIVATE_PACKAGE_UNPROVEN'
        print('SEMANTIC_ADMISSION_PACKAGE=BLOCKED MODE='+args.mode+' REASON='+reason+' NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
