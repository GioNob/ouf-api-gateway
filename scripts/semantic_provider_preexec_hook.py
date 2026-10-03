"""Source-sealed private driver and synchronous OCI gate. No runtime registration.

Invoke with trusted Python -I -B and a root-private configuration. An installer
must stage/approve the profile and journals separately; this driver creates none.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types


MODULES = ('materialize_southbound_kernel', 'materialize_southbound_lease_refresh',
    'semantic_provider_dns', 'semantic_provider_lease_nft', 'semantic_provider_lease_owner',
    'materialize_semantic_shared_faces', 'semantic_provider_lease_coordination',
    'semantic_provider_preexec', 'semantic_provider_preexec_native')
SELF = 'scripts/semantic_provider_preexec_hook.py'


def private_bytes(path):
    if not path.is_absolute() or '..' in path.parts: raise RuntimeError('PRIVATE_PATH_REQUIRED')
    for parent in (path.parent, *path.parent.parents):
        value = parent.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise RuntimeError('PRIVATE_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_gid != 0 \
                or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1 or value.st_size > 131072:
            raise RuntimeError('PRIVATE_FILE_REQUIRED')
        raw = os.read(fd, 131073)
        if len(raw) > 131072: raise RuntimeError('PRIVATE_INPUT_UNBOUNDED')
        return raw
    finally: os.close(fd)


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise RuntimeError('DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def load(path):
    config_raw = private_bytes(path); value = parse(config_raw)
    fields = {'schema', 'sourceRoot', 'sourceHashes', 'profile', 'kernel', 'dns',
            'coordinationBinding', 'coordinationJournal', 'preexecJournal', 'lockFile', 'commands', 'budgetSeconds'}
    if value.get('schema') in ('ouf.semantic-preexec-driver.v2','ouf.semantic-preexec-driver.v3'): fields.add('runtimeBinding')
    if value.get('schema') == 'ouf.semantic-preexec-driver.v3': fields.update(('authorityBinding','authorityScope'))
    if set(value) != fields or value['schema'] not in ('ouf.semantic-preexec-driver.v1', 'ouf.semantic-preexec-driver.v2','ouf.semantic-preexec-driver.v3'):
        raise RuntimeError('EXACT_DRIVER_CONFIGURATION_REQUIRED')
    root = Path(value['sourceRoot'])
    if root.lstat().st_mode & 0o077 or not root.is_dir(): raise RuntimeError('PRIVATE_SOURCE_ROOT_REQUIRED')
    modules = (*MODULES, 'semantic_provider_admission') if value['schema'] == 'ouf.semantic-preexec-driver.v3' else MODULES
    paths = [SELF, *('tools/'+name+'.py' for name in modules)]
    if set(value['sourceHashes']) != set(paths) or Path(__file__).absolute() != root/SELF:
        raise RuntimeError('EXACT_SOURCE_PACKAGE_REQUIRED')
    verified = {}
    for relative in paths:
        expected = value['sourceHashes'][relative]
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
            raise RuntimeError('SOURCE_HASH_REQUIRED')
        raw = private_bytes(root/relative)
        if hashlib.sha256(raw).hexdigest() != expected: raise RuntimeError('SOURCE_PACKAGE_DRIFT')
        verified[relative] = raw
    # No sys.path/PYTHONPATH imports or bytecode cache: execute only the exact
    # verified modules in dependency order, with a synthetic closed package.
    package = types.ModuleType('tools'); package.__path__ = []; sys.modules['tools'] = package
    for name in modules:
        full = 'tools.'+name; module = types.ModuleType(full)
        module.__file__ = str(root/'tools'/str(name+'.py')); module.__package__ = 'tools'
        sys.modules[full] = module; setattr(package, name, module)
        exec(compile(verified['tools/'+name+'.py'], module.__file__, 'exec'), module.__dict__)
    if private_bytes(path) != config_raw: raise RuntimeError('DRIVER_CONFIGURATION_DRIFT')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--mode', required=True, choices=['plan', 'apply', 'verify', 'reconcile', 'rollback', 'hook', 'start'])
    args = parser.parse_args()
    try:
        if os.geteuid() != 0 or not sys.flags.isolated or not sys.dont_write_bytecode:
            raise RuntimeError('ROOT_ISOLATED_NO_BYTECODE_REQUIRED')
        value = load(Path(args.configuration))
        from tools.semantic_provider_lease_coordination import Coordinator, PrivateJournal, hold_common_lock
        from tools.semantic_provider_lease_nft import NftBackend
        from tools.semantic_provider_lease_owner import LeaseOwner
        from tools.semantic_provider_preexec import Preexec
        from tools.semantic_provider_preexec_native import NativeBackend
        lease_backend = NftBackend([value['commands']['nft']], value['kernel'],
            value['coordinationBinding']['leaseStructureHash'], value['budgetSeconds'])
        owner = LeaseOwner(value['kernel'], value['dns'], lease_backend)
        journal = PrivateJournal(Path(value['coordinationJournal']))
        coordination = Coordinator(owner, value['coordinationBinding'],
            lambda: hold_common_lock(Path(value['lockFile'])), journal.read, journal.write)
        backend = NativeBackend(value['profile'], value['commands'], value['budgetSeconds'])
        gate = Preexec(value['profile'], backend, coordination, PrivateJournal(Path(value['preexecJournal'])))
        authorizer = None
        if value['schema'] == 'ouf.semantic-preexec-driver.v3':
            from tools.semantic_provider_admission import authority
            authorizer = lambda: authority(value['authorityBinding'], value['authorityScope'], lambda p: private_bytes(Path(p)))
        if args.mode == 'start':
            if value['schema'] not in ('ouf.semantic-preexec-driver.v2','ouf.semantic-preexec-driver.v3'):
                raise RuntimeError('SEALED_RUNTIME_BINDING_REQUIRED')
            state = backend.runtime(value['runtimeBinding'], 'state')
            result = gate.before_process(state, lambda: backend.runtime(value['runtimeBinding'], 'start'), authorizer)
        elif args.mode == 'hook':
            raw = sys.stdin.buffer.read(16385)
            if len(raw) > 16384: raise RuntimeError('OCI_STATE_UNBOUNDED')
            result = gate.before_process(parse(raw), authorizer=authorizer)
        else: result = gate.operate(args.mode, authorizer)
        print('SEMANTIC_PREEXEC='+json.dumps({'schema': 'ouf.semantic-preexec-result.v1',
            'mode': args.mode, 'result': result, 'providerCalls': 0, 'notReleaseAcceptance': True,
            'noSecretsPrinted': True}, sort_keys=True))
        return 0
    except Exception as error:
        # The bootstrap and native layers never print config/source/CLI stderr.
        reason = str(error)
        if not re.fullmatch('[A-Z_]{1,80}', reason): reason = 'PREEXEC_OPERATION_UNPROVEN'
        print('SEMANTIC_PREEXEC=BLOCKED MODE='+args.mode+' REASON='+reason+' NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
