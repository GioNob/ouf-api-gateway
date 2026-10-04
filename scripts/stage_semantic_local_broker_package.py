"""Private source-only broker package v7: pinned closed manifest, no source execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SELF='scripts/stage_semantic_local_broker_package.py'
MODULES=('materialize_southbound_kernel','materialize_southbound_lease_refresh','semantic_provider_dns',
    'semantic_provider_lease_nft','semantic_provider_lease_owner','materialize_semantic_shared_faces',
    'semantic_provider_lease_coordination','semantic_provider_preexec','semantic_provider_preexec_native',
    'semantic_provider_deployment_admission','semantic_provider_deployment_protocol','semantic_provider_deployment_consumption',
    'semantic_provider_deployment_authentication','semantic_provider_deployment_reauthorization','semantic_provider_deployment_producer')
NAMES=(SELF,'scripts/semantic_provider_deployment_broker.py','scripts/semantic_provider_docker_runtime.py',
    'scripts/semantic_provider_admission_preparer.py','scripts/semantic_provider_preexec_hook.py',
    *('tools/'+name+'.py' for name in MODULES))


def require(ok,reason):
    if not ok:raise RuntimeError(reason)


def private(path):
    require(path.is_absolute() and '..' not in path.parts,'PRIVATE_PATH_REQUIRED')
    for parent in (path.parent,*path.parent.parents):
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'PRIVATE_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_size<=131072,
                'PRIVATE_BOUNDED_FILE_REQUIRED')
        raw=os.read(fd,131073);after=os.fstat(fd)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        require(len(raw)<=131072 and all(getattr(before,k)==getattr(after,k) for k in fields),'PRIVATE_READ_DRIFT')
        return raw
    finally:os.close(fd)


def manifest(raw):
    require(len(raw)<=8192,'SOURCE_MANIFEST_UNBOUNDED')
    try:text=raw.decode('ascii')
    except UnicodeError:raise RuntimeError('ASCII_SOURCE_MANIFEST_REQUIRED') from None
    values={}
    for line in text.splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)',line)
        require(match is not None,'EXACT_SOURCE_MANIFEST_REQUIRED')
        value,name=match.groups()
        require(name in NAMES and name not in values,'EXACT_CLOSED_SOURCE_SET_REQUIRED');values[name]=value
    require(set(values)==set(NAMES),'EXACT_CLOSED_SOURCE_SET_REQUIRED')
    return values


def parse(raw):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'DUPLICATE_RECEIPT_KEY');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique)


def tools_available():
    result={}
    for name,path in {'python':'/usr/bin/python3','runc':'/usr/bin/runc','nft':'/usr/sbin/nft','ip':'/usr/sbin/ip',
        'nsenter':'/usr/bin/nsenter','unshare':'/usr/bin/unshare','busybox':'/usr/bin/busybox',
        'mount':'/usr/bin/mount','umount':'/usr/bin/umount','openssl':'/usr/bin/openssl'}.items():
        try:
            target=Path(path).resolve(strict=True);info=target.lstat()
            ok=stat.S_ISREG(info.st_mode) and info.st_uid==0 and bool(info.st_mode&0o111) and not info.st_mode&0o022
            for parent in (target.parent,*target.parents):
                item=parent.lstat();ok=ok and stat.S_ISDIR(item.st_mode) and item.st_uid==0 and not item.st_mode&0o022
        except OSError:ok=False
        result[name]=bool(ok)
    return result


def operate(mode,root,commit,expected_manifest_hash):
    require(os.geteuid()==0 and root.is_absolute() and '..' not in root.parts
            and re.fullmatch('[0-9a-f]{40}',commit) and re.fullmatch('[0-9a-f]{64}',expected_manifest_hash),
            'EXPLICIT_PRIVATE_PACKAGE_BINDING_REQUIRED')
    for directory in (root,root/'source',root/'source/scripts',root/'source/tools'):
        info=directory.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0
            and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_PACKAGE_DIRECTORY_REQUIRED')
    require(Path(__file__).absolute()==root/'source'/SELF,'EXACT_STAGE_SOURCE_REQUIRED')
    manifest_path=root/'sources.sha256';manifest_raw=private(manifest_path)
    require(hashlib.sha256(manifest_raw).hexdigest()==expected_manifest_hash,'PINNED_SOURCE_MANIFEST_REQUIRED')
    expected=manifest(manifest_raw)
    contents={name:private(root/'source'/name) for name in NAMES}
    for name,raw in contents.items():
        require(hashlib.sha256(raw).hexdigest()==expected[name],'PINNED_SOURCE_HASH_DRIFT')
        # Compile only. Not even the hook/bootstrap is imported or executed.
        compile(raw,str(root/'source'/name),'exec')
    capabilities=tools_available()
    require(private(manifest_path)==manifest_raw and all(private(root/'source'/name)==raw for name,raw in contents.items()),
            'SOURCE_CHANGED_DURING_STAGING')
    receipt={'schema':'ouf.semantic-local-broker-source-package.v7','sourceCommit':commit,
        'sourceManifestHash':expected_manifest_hash,'sourceHashes':expected,'sourceCount':len(NAMES),
        'sourceCustodyVerified':True,'sourceBodiesExecuted':0,'pythonVersion':'.'.join(map(str,sys.version_info[:3])),
        'trustedToolsAvailable':capabilities,'runtimeRegistered':False,'rulesChanged':False,'unitsChanged':False,
        'containersChanged':False,'startAuthorized':False,'runtimeAdapterInstalled':False,'admissionPreparerInstalled':False,
        'brokerInstalled':False,'externalProducerInstalled':False,'signatureVerifierInstalled':False,
        'trustPolicyProvisioned':False,'keysGenerated':0,'privateKeysRead':0,'signaturesIssued':0,'providerCalls':0,
        'notReleaseAcceptance':True,'noSecretsPrinted':True}
    path=root/'source-package-receipt.json'
    if mode=='verify':require(parse(private(path))==receipt,'PRIVATE_PACKAGE_DRIFT')
    elif mode in ('plan','apply'):
        require(not path.exists() and not path.is_symlink(),'DO_NOT_REPLAY_PACKAGE_APPLY')
        if mode=='apply':
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(fd,'wb',closefd=False) as stream:
                    stream.write(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode());stream.flush();os.fsync(fd)
            finally:os.close(fd)
            directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(directory)
            finally:os.close(directory)
            require(parse(private(path))==receipt,'PRIVATE_RECEIPT_PUBLICATION_UNPROVEN')
    else:require(False,'EXPLICIT_PACKAGE_MODE_REQUIRED')
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',required=True,choices=('plan','apply','verify'))
    parser.add_argument('--package-root',required=True,type=Path)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    args=parser.parse_args()
    try:
        result=operate(args.mode,args.package_root,args.source_commit,args.source_manifest_sha256)
        print('SEMANTIC_LOCAL_BROKER_PACKAGE='+json.dumps(result,sort_keys=True))
        print('SEMANTIC_LOCAL_BROKER_PACKAGE=PASS MODE='+args.mode+' PRIVATE_SOURCE_ONLY=true SOURCE_BODIES_EXECUTED=0'
            ' NO_RULE_UNIT_CONTAINER_CHANGED=true RUNTIME_REGISTERED=false START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 0
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z_]{1,80}',reason):reason='PRIVATE_PACKAGE_UNPROVEN'
        print('SEMANTIC_LOCAL_BROKER_PACKAGE=BLOCKED MODE='+args.mode+' REASON='+reason+' NO_SECRETS_PRINTED=true')
        return 1


if __name__=='__main__':raise SystemExit(main())
