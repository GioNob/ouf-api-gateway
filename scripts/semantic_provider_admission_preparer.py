"""Source-sealed deployment preparer; no authority issuance or runtime registration.

The approved deployment supplies existing lease custody/common lock, an external
creation-acceptance receipt, a fresh deployment approval and an existing STAGED
admission journal. Interrupted preparation is preserved for explicit recovery.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import socket
import subprocess
import sys
import tempfile
import time
import types

SELF = 'scripts/semantic_provider_admission_preparer.py'
DRIVER = 'scripts/semantic_provider_preexec_hook.py'
MODULES = ('materialize_southbound_kernel','materialize_southbound_lease_refresh','semantic_provider_dns',
    'semantic_provider_lease_nft','semantic_provider_lease_owner','materialize_semantic_shared_faces',
    'semantic_provider_lease_coordination','semantic_provider_preexec','semantic_provider_preexec_native',
    'semantic_provider_deployment_admission')


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def signature(value):
    # A successful read may update atime (relatime); that is not content drift.
    return tuple(getattr(value,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                                          'st_size','st_mtime_ns','st_ctime_ns'))


def private(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'PRIVATE_PATH_REQUIRED')
    for parent in (path.parent,*path.parent.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'PRIVATE_ANCESTOR_REQUIRED')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= 131072, 'PRIVATE_FILE_REQUIRED')
        raw = os.read(fd,131073); after = os.fstat(fd)
        require(len(raw) <= 131072 and signature(before) == signature(after), 'PRIVATE_READ_DRIFT')
        return raw
    finally: os.close(fd)


def parse(raw):
    def unique(pairs):
        out = {}
        for k,v in pairs:
            require(k not in out,'DUPLICATE_JSON_KEY'); out[k] = v
        return out
    return json.loads(raw,object_pairs_hook=unique)


def executable(path, expected):
    p = Path(path); require(p.is_absolute() and '..' not in p.parts,'EXPLICIT_EXECUTABLE_REQUIRED')
    for parent in (p.parent,*p.parent.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,'TRUSTED_COMMAND_ANCESTOR_REQUIRED')
    fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o111
                and not before.st_mode & 0o022 and before.st_size <= 64000000,'TRUSTED_COMMAND_REQUIRED')
        h = hashlib.sha256(); size = 0
        while True:
            raw = os.read(fd,65536)
            if not raw: break
            size += len(raw); require(size <= 64000000,'COMMAND_SIZE_UNBOUNDED')
            h.update(raw)
        require(h.hexdigest() == expected and signature(os.fstat(fd)) == signature(before),'COMMAND_BINARY_DRIFT')
    finally: os.close(fd)


def load(path):
    raw = private(path); cfg = parse(raw)
    fields = {'schema','sourceRoot','sourceHashes','pythonPath','pythonHash','commands','commandHashes',
            'candidate','kernel','dns','coordinationBinding','coordinationJournal','lockFile','budgetSeconds','hostNetworkNamespace'}
    modules = MODULES
    if cfg.get('schema') == 'ouf.semantic-admission-preparer.v2':
        fields.add('consumptionBinding')
        modules = (*modules, 'semantic_provider_deployment_protocol', 'semantic_provider_deployment_consumption')
    require(set(cfg) == fields and cfg['schema'] in ('ouf.semantic-admission-preparer.v1','ouf.semantic-admission-preparer.v2'),
            'EXACT_PREPARER_CONFIGURATION_REQUIRED')
    root = Path(cfg['sourceRoot']); require(stat.S_IMODE(root.lstat().st_mode) == 0o700,'PRIVATE_SOURCE_ROOT_REQUIRED')
    paths = [SELF,DRIVER,*('tools/'+m+'.py' for m in modules)]
    require(Path(__file__).absolute() == root/SELF and set(cfg['sourceHashes']) == set(paths),'EXACT_SOURCE_SET_REQUIRED')
    verified = {p:private(root/p) for p in paths}
    for p,content in verified.items():
        require(hashlib.sha256(content).hexdigest() == cfg['sourceHashes'][p],'SOURCE_PACKAGE_DRIFT')
    require(set(cfg['commands']) == set(cfg['commandHashes']) == {'nft','ip','nsenter','unshare','mount','umount'},
            'EXPLICIT_NATIVE_COMMANDS_REQUIRED')
    executable(cfg['pythonPath'],cfg['pythonHash'])
    for name,p in cfg['commands'].items(): executable(p,cfg['commandHashes'][name])
    require(type(cfg['budgetSeconds']) is int and 1 <= cfg['budgetSeconds'] <= 5,'BOUNDED_DRIVER_REQUIRED')
    require(type(cfg['hostNetworkNamespace']) is int and cfg['hostNetworkNamespace'] > 0,'SEALED_HOST_NAMESPACE_REQUIRED')
    package = types.ModuleType('tools'); package.__path__ = []; sys.modules['tools'] = package
    for name in modules:
        full = 'tools.'+name; module = types.ModuleType(full); module.__package__ = 'tools'
        module.__file__ = str(root/'tools'/str(name+'.py')); sys.modules[full] = module; setattr(package,name,module)
        exec(compile(verified['tools/'+name+'.py'],module.__file__,'exec'),module.__dict__)
    require(private(path) == raw,'PREPARER_CONFIGURATION_DRIFT')
    return cfg,raw


def create(path,value):
    raw = json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    require(len(raw) <= 131072,'PRIVATE_RESULT_UNBOUNDED')
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as f: f.write(raw); f.flush(); os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def operate(args):
    cfg,config_raw = load(args.configuration)
    from tools.semantic_provider_deployment_admission import authority, application_hash, transport_hash, live_profile, mirrors, isolated_template
    from tools.semantic_provider_preexec import digest
    from tools.semantic_provider_preexec_native import NativeBackend
    from tools.semantic_provider_lease_coordination import PrivateJournal,hold_common_lock,Coordinator
    from tools.semantic_provider_lease_nft import NftBackend
    from tools.semantic_provider_lease_owner import LeaseOwner
    candidate = cfg['candidate']
    require(set(candidate) == {'containerId','transactionId','bundlePath','applicationHash','networkBindings','transport',
        'tableName','runtimeBinding','authorityBinding','authorityScope','creationAcceptance'},'EXACT_CANDIDATE_INTENT_REQUIRED')
    require(args.container_id == candidate['containerId'] and re.fullmatch('[0-9a-f]{64}',args.container_id)
        and args.bundle == candidate['bundlePath'] and args.runtime_root == candidate['runtimeBinding']['root'],
        'CANDIDATE_RUNTIME_BINDING_DRIFT')
    require(candidate['tableName'] != cfg['kernel']['tableName'],'DISTINCT_OWNED_TABLES_REQUIRED')
    root = Path(args.bundle).parent; require(stat.S_IMODE(root.lstat().st_mode) == 0o700,'PRIVATE_CANDIDATE_ROOT_REQUIRED')
    deadline = time.monotonic()+18
    def run(name,argv,raw=None):
        executable(cfg['commands'][name],cfg['commandHashes'][name])
        with tempfile.TemporaryFile() as out:
            remain = deadline-time.monotonic(); require(remain > 0,'PREPARER_DEADLINE_MISSED')
            p = subprocess.run([cfg['commands'][name],*argv],input=raw,text=True,stdout=out,
                stderr=subprocess.DEVNULL,timeout=remain,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            require(p.returncode == 0,'NATIVE_PREPARATION_UNPROVEN')
            out.seek(0); result = out.read(2000001); require(len(result) <= 2000000,'NATIVE_OUTPUT_UNBOUNDED')
            return result.decode()
    def invoke(argv,raw=None):
        with tempfile.TemporaryFile() as out:
            remain = deadline-time.monotonic(); require(remain > 0,'PREPARER_DEADLINE_MISSED')
            p = subprocess.run(argv,input=raw,text=True,stdout=out,stderr=subprocess.DEVNULL,
                timeout=remain,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            out.seek(0); result = out.read(131073)
            require(p.returncode == 0 and len(result) <= 131072,'SEALED_WORKER_OR_DRIVER_DENIED')
            return result.decode()
    python = [cfg['pythonPath'],'-I','-B']
    if args.mode == 'template':
        value = parse(sys.stdin.buffer.read(131073))
        require(set(value) == {'profile','mirrors','parentNamespace'},'EXACT_TEMPLATE_REQUEST_REQUIRED')
        require(value['parentNamespace'] == cfg['hostNetworkNamespace'],'TEMPLATE_PARENT_NAMESPACE_BINDING_DRIFT')
        result = isolated_template(value['profile'],value['mirrors'],value['parentNamespace'],os.stat('/proc/self/ns/net').st_ino,run)
        print(json.dumps(result,sort_keys=True)); return
    require(os.stat('/proc/self/ns/net').st_ino == cfg['hostNetworkNamespace'],'HOST_NAMESPACE_CUSTODY_DRIFT')
    journal = PrivateJournal(root/'admission.json'); record = journal.read()
    require(set(record) == {'schema','transactionId','configurationHash','state','driverHash','namespaceOwned','namespaceInode','containerGeneration'}
        and record['schema'] == 'ouf.semantic-admission-journal.v1'
        and record['transactionId'] == candidate['transactionId']
        and record['configurationHash'] == hashlib.sha256(config_raw).hexdigest(),'ADMISSION_JOURNAL_BINDING_DRIFT')
    def publish(state,**extra):
        nonlocal record
        with hold_common_lock(Path(cfg['lockFile'])):
            updated = {**record,'state':state,**extra}; journal.write(record,updated); record = updated
    if args.mode == 'cleanup':
        require(record['state'] == 'PROTECTED' and hashlib.sha256(private(root/'driver.json')).hexdigest() == record['driverHash'],
                'OWNED_CLEANUP_REQUIRED')
        with hold_common_lock(Path(cfg['lockFile'])):
            prior = PrivateJournal(root/'preexec.json').read()
            require(prior['state'] == 'ROLLED_BACK' and prior['transactionId'] == candidate['transactionId'],
                    'INDEPENDENT_ROLLBACK_REQUIRED')
            grant = parse(private(root/'driver.json'))
            backend = NativeBackend(grant['profile'],grant['commands'],cfg['budgetSeconds'])
            require(record['containerGeneration'] is not None
                    and backend.generation_alive(record['containerGeneration']) is False,'LIVE_GENERATION_CLEANUP_DENIED')
            if record['namespaceOwned']:
                namespace = root/'netns'; require(namespace.lstat().st_ino == record['namespaceInode'],'OWNED_NAMESPACE_DRIFT')
                run('umount',[str(namespace)]); namespace.unlink()
            updated = {**record,'state':'CLEANED'}; journal.write(record,updated)
        return
    require(args.mode == 'prepare' and record['state'] == 'STAGED' and record['driverHash'] is None
            and record['namespaceOwned'] is False and record['namespaceInode'] is None
            and record['containerGeneration'] is None,'EXPLICIT_RECOVERY_NO_REPLAY')
    scope = candidate['authorityScope']
    require(scope['containerId'] == candidate['containerId'] and scope['transactionId'] == candidate['transactionId']
        and scope['applicationHash'] == candidate['applicationHash'] and scope['transportHash'] == transport_hash(candidate),
        'APPROVAL_INTENT_SCOPE_DRIFT')
    authority(candidate['authorityBinding'],scope,private)
    creation = candidate['creationAcceptance']
    require(set(creation) == {'path','sha256'},'EXTERNAL_CREATION_ACCEPTANCE_REQUIRED')
    raw = private(creation['path']); accepted = parse(raw)
    require(hashlib.sha256(raw).hexdigest() == creation['sha256'] == scope['creationAcceptanceHash']
        and set(accepted) == {'schema','containerId','applicationHash','transportHash','accepted'}
        and accepted['schema'] == 'ouf.semantic-container-creation-acceptance.v1' and accepted['accepted'] is True
        and all(accepted[k] == scope[k] for k in ('containerId','applicationHash','transportHash')),
        'CREATION_ACCEPTANCE_BINDING_UNPROVEN')
    if cfg['schema'] == 'ouf.semantic-admission-preparer.v2':
        from tools.semantic_provider_deployment_consumption import Consumption
        sealed = cfg['consumptionBinding']
        require(set(sealed) == {'journalPath','binding','evidenceHash'},'EXACT_CONSUMPTION_BINDING_REQUIRED')
        consumption = Consumption(sealed['binding'],PrivateJournal(Path(sealed['journalPath'])),
                                  lambda:hold_common_lock(Path(cfg['lockFile'])))
        with consumption.hold_lock():
            receipt = consumption.record()
            require(receipt['state'] == 'READY' and receipt['driverHash'] is None
                    and receipt['bundleHash'] == candidate['applicationHash']
                    and receipt['approvalHash'] == candidate['authorityBinding']['sha256']
                    and receipt['evidenceHash'] == sealed['evidenceHash']
                    and all(receipt[k] == scope[k] for k in ('installationRef','entityRef','containerId','transactionId')),
                    'CONSUMPTION_PREPARATION_CUSTODY_DRIFT')
    state = parse(sys.stdin.buffer.read(16385))
    require(state.get('id') == args.container_id and state.get('bundle') == args.bundle and state.get('status') == 'created'
            and type(state.get('pid')) is int and state['pid'] > 1,'CREATED_OCI_STATE_REQUIRED')
    bundle = parse(private(Path(args.bundle)/'config.json'))
    require(application_hash(bundle) == candidate['applicationHash'],'APPLICATION_ACCEPTANCE_DRIFT')
    owner = LeaseOwner(cfg['kernel'],cfg['dns'],NftBackend([cfg['commands']['nft']],cfg['kernel'],
        cfg['coordinationBinding']['leaseStructureHash'],cfg['budgetSeconds']))
    coord = Coordinator(owner,cfg['coordinationBinding'],lambda:hold_common_lock(Path(cfg['lockFile'])),
        PrivateJournal(Path(cfg['coordinationJournal'])).read,PrivateJournal(Path(cfg['coordinationJournal'])).write)
    with coord.hold_lock():
        value = coord.journal()
        require(value['state'] == 'QUIESCED' and not value['leaseAuthorized'] and not any(coord.sets()),'EXISTING_LEASE_QUIESCENCE_REQUIRED')
        authority(candidate['authorityBinding'],scope,private)
    require(not (root/'driver.json').exists() and not (root/'preexec.json').exists(),'FOREIGN_ADMISSION_ARTIFACT_PRESERVED')
    publish('PREPARING')
    networks = [v for v in bundle['linux']['namespaces'] if v.get('type') == 'network']
    require(len(networks) == 1,'EXACT_NETWORK_NAMESPACE_REQUIRED')
    namespace = networks[0].get('path')
    owned = not bool(namespace)
    if owned:
        namespace = str(root/'netns'); create(Path(namespace),{})
        run('mount',['--bind','/proc/'+str(state['pid'])+'/ns/net',namespace])
    inode = os.stat(namespace).st_ino
    publish('PREPARING',namespaceOwned=owned,namespaceInode=inode)
    children = [v for v in parse(run('nsenter',['--net='+namespace,cfg['commands']['ip'],'-j','addr','show'])) if v['ifname'] != 'lo']
    indexes = {v['link_index'] for v in children}
    indexes.update(v['peerIngress']['ifindex'] for v in candidate['transport'] if v['peerIngress']['kind'] != 'HOST')
    require(len(indexes) <= 160,'NATIVE_PEER_COUNT_UNBOUNDED')
    hosts = []
    for index in sorted(indexes):
        name = socket.if_indextoname(index)
        found = parse(run('ip',['-j','link','show','dev',name]))
        require(len(found) == 1 and found[0]['ifindex'] == index and found[0]['ifname'] == name,
                'HOST_INDEX_NAME_BINDING_DRIFT')
        hosts.append(found[0])
    profile = live_profile(candidate,bundle,namespace,inode,children,hosts)
    backend = NativeBackend(profile,{k:cfg['commands'][k] for k in ('nft','ip','nsenter')},cfg['budgetSeconds'])
    runtime_state = backend.runtime(candidate['runtimeBinding'],'state')
    require(all(runtime_state.get(k) == state[k] for k in ('id','bundle','pid','status')),'INDEPENDENT_RUNTIME_STATE_DRIFT')
    generation = backend.bindings(profile,state)
    publish('PREPARING',containerGeneration=generation)
    packet = {'profile':profile,'mirrors':mirrors(profile,hosts),'parentNamespace':os.stat('/proc/self/ns/net').st_ino}
    argv = [cfg['commands']['unshare'],'--net','--fork',*python,str(Path(__file__).absolute()),
            '--configuration',str(args.configuration),'--mode','template','--container-id',args.container_id,
            '--bundle',args.bundle,'--runtime-root',args.runtime_root]
    result = parse(invoke(argv,json.dumps(packet)))
    require(result['isolated'] is True and result['profileHash'] == digest(profile),'INDEPENDENT_TEMPLATE_BINDING_DRIFT')
    profile['expectedFootprint'] = result['footprint']
    authority(candidate['authorityBinding'],scope,private)
    require(private(args.configuration) == config_raw,'PREPARER_CONFIGURATION_DRIFT')
    driver = {'schema':'ouf.semantic-preexec-driver.v3','sourceRoot':cfg['sourceRoot'],
        'sourceHashes':{p:h for p,h in cfg['sourceHashes'].items() if p != SELF},'profile':profile,
        'kernel':cfg['kernel'],'dns':cfg['dns'],'coordinationBinding':cfg['coordinationBinding'],
        'coordinationJournal':cfg['coordinationJournal'],'preexecJournal':str(root/'preexec.json'),
        'lockFile':cfg['lockFile'],'commands':{k:cfg['commands'][k] for k in ('nft','ip','nsenter')},
        'budgetSeconds':cfg['budgetSeconds'],'runtimeBinding':candidate['runtimeBinding'],
        'authorityBinding':candidate['authorityBinding'],'authorityScope':scope}
    if cfg['schema'] == 'ouf.semantic-admission-preparer.v2':
        sealed = cfg['consumptionBinding']
        require(set(sealed) == {'journalPath','binding','evidenceHash'},'EXACT_CONSUMPTION_BINDING_REQUIRED')
        from tools.semantic_provider_deployment_consumption import Consumption
        consumption = Consumption(sealed['binding'],PrivateJournal(Path(sealed['journalPath'])),
                                  lambda:hold_common_lock(Path(cfg['lockFile'])))
        with consumption.hold_lock():
            receipt = consumption.record()
            require(receipt['state'] == 'READY' and receipt['driverHash'] is None
                    and receipt['generation'] == generation and receipt['bundleHash'] == candidate['applicationHash']
                    and receipt['approvalHash'] == candidate['authorityBinding']['sha256']
                    and receipt['evidenceHash'] == sealed['evidenceHash']
                    and all(receipt[k] == scope[k] for k in ('installationRef','entityRef','containerId','transactionId')),
                    'CONSUMPTION_PREPARATION_CUSTODY_DRIFT')
        driver['schema'] = 'ouf.semantic-preexec-driver.v4'
        driver['consumptionBinding'] = sealed
    create(root/'preexec.json',{'schema':'ouf.semantic-preexec-journal.v1','transactionId':candidate['transactionId'],
        'configurationHash':digest(profile),'state':'STAGED','sharedStructureHash':None,'containerGeneration':None})
    create(root/'driver.json',driver)
    driver_hash = hashlib.sha256(private(root/'driver.json')).hexdigest()
    publish('PREPARED',driverHash=driver_hash)
    for mode in ('plan','apply','verify'):
        invoke([*python,str(Path(cfg['sourceRoot'])/DRIVER),'--configuration',str(root/'driver.json'),'--mode',mode])
    publish('PROTECTED')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--configuration',type=Path,required=True)
    for key in ('container-id','bundle','runtime-root'): p.add_argument('--'+key,required=True)
    p.add_argument('--mode',choices=('prepare','template','cleanup'),required=True); args = p.parse_args()
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_BYTECODE_REQUIRED')
        operate(args); return 0
    except Exception as e:
        reason = str(e)
        if not re.fullmatch('[A-Z_]{1,80}',reason): reason = 'ADMISSION_PREPARATION_UNPROVEN'
        print('SEMANTIC_ADMISSION_PREPARER=BLOCKED REASON='+reason+' NO_SECRETS_PRINTED=true',file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main())
