"""Named runc adapter with explicit admission broker and guarded start.

No daemon configuration, runtime registration or candidate creation. All runtime
operations require an explicitly staged CID. Recovery never replays create.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


class Denied(RuntimeError): pass


def require(value, reason='ADAPTER_BINDING_UNPROVEN'):
    if not value:
        if reason == 'ADAPTER_BINDING_UNPROVEN': reason += '_L'+str(sys._getframe(1).f_lineno)
        raise Denied(reason)


def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_ADAPTER_JSON_KEY'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def read(path, private=True):
    ancestors(path); fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and (stat.S_IMODE(before.st_mode) == 0o600 if private else not before.st_mode & 0o022)
                and before.st_size <= 131072)
        raw = os.read(fd, 131073); after = os.fstat(fd)
        require(len(raw) <= 131072 and all(getattr(before, k) == getattr(after, k)
                for k in ('st_dev','st_ino','st_mode','st_uid','st_size','st_mtime_ns','st_ctime_ns')))
        return raw
    finally: os.close(fd)


def executable(path, expected):
    path = Path(path); ancestors(path); info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_mode & 0o111)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        h = hashlib.sha256(); count = 0
        while True:
            raw = os.read(fd, 65536)
            if not raw: break
            count += len(raw); require(count <= 64000000); h.update(raw)
        require(h.hexdigest() == expected, 'ADAPTER_EXECUTABLE_DRIFT')
    finally: os.close(fd)


def save(path, old, value):
    require(parse(read(path)) == old, 'ADAPTER_JOURNAL_DRIFT')
    # Caller holds the existing per-CID lock. Never borrow the guard lock here.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.adapter-', delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(json.dumps(value, sort_keys=True).encode()); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            temp.unlink(); raise
    try:
        require(parse(read(path)) == old, 'ADAPTER_JOURNAL_DRIFT'); os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if temp.exists(): temp.unlink()


def arguments(argv):
    require(0 < len(argv) <= 40 and all(len(v) <= 4096 for v in argv), 'RUNTIME_ARGUMENTS_UNBOUNDED')
    values = {}; operation = None; position = 0
    global_values = {'--root', '--log', '--log-format'}
    while position < len(argv):
        item = argv[position]
        if item in ('--debug', '--systemd-cgroup'): position += 1; continue
        if item in global_values:
            require(item not in values and position+1 < len(argv)); values[item] = argv[position+1]; position += 2; continue
        operation = item; position += 1; break
    require(operation in ('create','start','state','delete','kill','--version','version','features'), 'UNSUPPORTED_RUNTIME_OPERATION')
    if operation in ('--version','version','features'):
        require(position == len(argv)); return operation, None, values
    require('--root' in values)
    opts = {'create': {'--bundle', '-b', '--pid-file', '--console-socket', '--preserve-fds'},
            'start': set(), 'state': set(), 'delete': set(), 'kill': set()}[operation]
    bools = {'create': {'--no-pivot', '--no-new-keyring'}, 'start': set(), 'state': set(),
             'delete': {'--force', '-f'}, 'kill': {'--all', '-a'}}[operation]
    while position < len(argv) and argv[position].startswith('-'):
        item = argv[position]; position += 1
        require(item not in values)
        if item in bools: values[item] = True
        else:
            require(item in opts and position < len(argv)); values[item] = argv[position]; position += 1
    require(position < len(argv)); cid = argv[position]; position += 1
    require(re.fullmatch('[0-9a-f]{64}', cid), 'EXACT_DOCKER_CID_REQUIRED')
    if operation == 'kill':
        require(position+1 == len(argv) and re.fullmatch('[0-9]{1,2}|SIG[A-Z]{2,10}', argv[position]))
    else: require(position == len(argv))
    if operation == 'create':
        require(('--bundle' in values) != ('-b' in values) and values.get('--preserve-fds', '0') == '0')
    return operation, cid, values


def capture(argv, timeout=20):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        output.seek(0); raw = output.read(16385)
        require(result.returncode == 0 and len(raw) <= 16384, 'ADMISSION_OR_DRIVER_FAILED')
        return raw


def binding(config, cid):
    return digest({**{k: v for k, v in config.items() if k != 'candidates'}, 'candidate': config['candidates'][cid]})


def operate(config_path, argv):
    original = read(config_path); config = parse(original)
    require(set(config) == {'schema','sourceHash','runtimePath','runtimeSha256','pythonPath','pythonSha256',
        'driverPath','driverSha256','admissionPath','admissionSha256','admissionConfiguration',
        'admissionConfigurationHash','registryRoot','runtimeStateRoot','candidates'}
        and config['schema'] == 'ouf.semantic-docker-runtime-adapter.v1')
    require(hashlib.sha256(read(Path(__file__))).hexdigest() == config['sourceHash'], 'ADAPTER_SOURCE_DRIFT')
    executable(config['runtimePath'], config['runtimeSha256']); executable(config['pythonPath'], config['pythonSha256'])
    require(hashlib.sha256(read(Path(config['driverPath']))).hexdigest() == config['driverSha256'])
    require(hashlib.sha256(read(Path(config['admissionPath']))).hexdigest() == config['admissionSha256'])
    require(hashlib.sha256(read(Path(config['admissionConfiguration']))).hexdigest() == config['admissionConfigurationHash'])
    operation, cid, options = arguments(argv)
    if cid is None:
        return subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=5).returncode
    require(cid in config['candidates'], 'UNSTAGED_DOCKER_CANDIDATE')
    entry = config['candidates'][cid]
    require(set(entry) == {'approvalRef','bundleParents'} and re.fullmatch('[0-9a-f]{64}', entry['approvalRef'])
            and isinstance(entry['bundleParents'], list) and 1 <= len(entry['bundleParents']) <= 4)
    directory = Path(config['registryRoot'])/cid; ancestors(directory/'adapter.json')
    require(stat.S_IMODE(directory.lstat().st_mode) == 0o700)
    root = Path(options['--root']).resolve(); state_parent = Path(config['runtimeStateRoot'])
    require(root.is_relative_to(state_parent) and root != state_parent, 'RUNTIME_STATE_ROOT_UNPROVEN')
    lock = directory/'operation.lock'; read(lock)
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record_path = directory/'adapter.json'; record = parse(read(record_path))
        require(set(record) == {'schema','containerId','configurationHash','state','runtimeRoot','bundleHash','driverHash'}
                and record['schema'] == 'ouf.semantic-docker-runtime-journal.v1'
                and record['containerId'] == cid and record['configurationHash'] == binding(config, cid))
        require(record['runtimeRoot'] in (None, str(root)))
        require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
        shadow = directory/'bundle'; driver = directory/'driver.json'
        python = [config['pythonPath'], '-I', '-B']
        admission = [*python, config['admissionPath'], '--configuration', config['admissionConfiguration'],
                     '--container-id', cid, '--bundle', str(shadow), '--runtime-root', str(root)]
        def publish(state, **extra):
            nonlocal record
            value = {**record, 'state': state, **extra}; save(record_path, record, value); record = value
        def driver_call(mode):
            require(hashlib.sha256(read(driver)).hexdigest() == record['driverHash'], 'SEALED_ADMISSION_DRIVER_DRIFT')
            return capture([*python, config['driverPath'], '--configuration', str(driver), '--mode', mode])
        if operation == 'create':
            require(record['state'] == 'STAGED', 'DO_NOT_REPLAY_RUNTIME_CREATE')
            bundle = Path(options.get('--bundle', options.get('-b'))).resolve()
            require(str(bundle.parent) in entry['bundleParents'] and bundle.name == cid)
            oci = parse(read(bundle/'config.json', private=False))
            rootfs = Path(oci['root']['path'])
            require('..' not in rootfs.parts and str(rootfs) not in ('', '.'), 'ROOTFS_PATH_ESCAPE_DENIED')
            if not rootfs.is_absolute():
                rootfs = (bundle/rootfs).resolve(strict=True)
                require(rootfs.is_relative_to(bundle), 'ROOTFS_PATH_ESCAPE_DENIED')
                oci['root']['path'] = str(rootfs)
            require(not set(oci.get('hooks', {})) - {'prestart','createRuntime'}, 'UNSUPPORTED_DOCKER_HOOK_PHASE')
            networks = [v for v in oci['linux']['namespaces'] if v.get('type') == 'network']
            require(len(networks) == 1 and set(networks[0]) == {'type','path'}, 'DOCKER_PREPARED_NAMESPACE_REQUIRED')
            # Docker commonly spells the root-owned /run alias /var/run. The
            # admission broker still verifies the actual inode and live links.
            networks[0]['path'] = str(Path(networks[0]['path']).resolve(strict=True))
            hook = {'path': config['pythonPath'], 'args': [*python, config['driverPath'],
                    '--configuration', str(driver), '--mode', 'hook'], 'timeout': 10}
            oci.setdefault('hooks', {}).setdefault('createRuntime', []).append(hook)
            publish('PREPARING', runtimeRoot=str(root), bundleHash=digest(oci))
            shadow.mkdir(mode=0o700)
            target = shadow/'config.json'
            with target.open('xb') as stream:
                os.chmod(target, 0o600); stream.write(json.dumps(oci).encode()); stream.flush(); os.fsync(stream.fileno())
            for parent in (shadow, directory):
                directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
            capture([*admission, '--mode', 'prepare'])
            grant_raw = read(driver); grant = parse(grant_raw)
            require(grant['schema'] == 'ouf.semantic-preexec-driver.v2' and grant['profile']['containerId'] == cid
                    and grant['profile']['bundlePath'] == str(shadow) and grant['profile']['bundleHash'] == digest(oci)
                    and grant['profile']['namespacePath'] == networks[0]['path']
                    and grant['profile']['applicationStartAuthorized'] is True
                    and grant['profile']['infrastructureAuthorityComplete'] is True
                    and grant['sourceRoot']+'/scripts/semantic_provider_preexec_hook.py' == config['driverPath']
                    and grant['sourceHashes']['scripts/semantic_provider_preexec_hook.py'] == config['driverSha256']
                    and grant['runtimeBinding'] == {'path': config['runtimePath'], 'sha256': config['runtimeSha256'], 'root': str(root)})
            publish('CREATING', driverHash=hashlib.sha256(grant_raw).hexdigest())
            rewritten = list(argv); option = '--bundle' if '--bundle' in options else '-b'
            rewritten[rewritten.index(option)+1] = str(shadow)
            require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
            # Preserve the init process's inherited stderr, which becomes the
            # container's application stderr stream after explicit start.
            result = subprocess.run([config['runtimePath'], *rewritten],
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=20)
            require(result.returncode == 0, 'RUNTIME_CREATE_DENIED'); publish('CREATED'); return 0
        require(record['state'] in {'PREPARING','CREATING','CREATED','STARTING','STARTED','DELETING','DELETED'})
        if operation == 'start':
            require(record['state'] == 'CREATED', 'OWNED_CREATED_RUNTIME_REQUIRED')
            publish('STARTING'); driver_call('start'); publish('STARTED'); return 0
        require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
        if operation == 'delete':
            require(record['state'] != 'DELETED', 'DO_NOT_REPLAY_RUNTIME_DELETE'); publish('DELETING')
        result = subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=10)
        if operation == 'delete' and result.returncode == 0:
            # Successful runc delete is followed by the driver's independent
            # dead-generation and owned-handle rollback proof.
            require(record['driverHash'] is not None, 'UNPREPARED_DELETE_REQUIRES_RECOVERY')
            driver_call('rollback'); publish('DELETED')
        return result.returncode
    finally: os.close(fd)


def main():
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode)
        require(len(sys.argv) >= 4 and sys.argv[1] == '--configuration')
        return operate(Path(sys.argv[2]), sys.argv[3:])
    except Exception as error:
        reason = str(error) if isinstance(error, Denied) and re.fullmatch('[A-Z0-9_]{1,80}', str(error)) else 'DOCKER_RUNTIME_OPERATION_UNPROVEN'
        # containerd retrieves the standard runc JSON log on failure. Preserve
        # that protocol with a constant redacted message, never raw exceptions.
        try:
            if '--log' in sys.argv:
                path = Path(sys.argv[sys.argv.index('--log')+1]); ancestors(path)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
                try:
                    info = os.fstat(fd)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                            and not info.st_mode & 0o022 and info.st_size < 131072)
                    value = {'level':'error','msg':'SEMANTIC_DOCKER_RUNTIME_BLOCKED_'+reason,
                             'time':datetime.now(timezone.utc).isoformat()}
                    os.write(fd, (json.dumps(value)+'\n').encode())
                finally: os.close(fd)
        except Exception: pass
        print('SEMANTIC_DOCKER_RUNTIME=BLOCKED REASON='+reason, file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())
