"""Narrow recovery of an unapplied private package: source 0755 -> 0700.

Original source/manifest pins remain mandatory. Receipt presence refuses any
recovery. No source import, receipt creation, ownership change or runtime call.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def require(ok,reason):
    if not ok:raise RuntimeError(reason)


def attrs(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
        'st_size','st_mtime_ns','st_ctime_ns'))


def private(path):
    for parent in (path.parent,*path.parent.parents):
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
            'TRUSTED_PACKAGE_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
            and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_size<=131072,
            'PRIVATE_ORIGINAL_SOURCE_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==before.st_size and attrs(before)==attrs(os.fstat(fd)),
            'ORIGINAL_SOURCE_READ_DRIFT')
        return raw
    finally:os.close(fd)


def inspect(root,expected):
    require(root.is_absolute() and '..' not in root.parts and os.geteuid()==0
        and re.fullmatch('[0-9a-f]{64}',expected),'EXPLICIT_ROOT_PACKAGE_PIN_REQUIRED')
    require(not os.path.lexists(root/'source-package-receipt.json'),'RECEIPT_EXISTS_DO_NOT_REPLAY')
    directories={}
    for relative in ('','source','source/scripts','source/tools'):
        path=root/relative;info=path.lstat();mode=stat.S_IMODE(info.st_mode)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0
            and mode in ((0o700,0o755) if relative=='source' else (0o700,)),
            'UNEXPECTED_DIRECTORY_METADATA_DO_NOT_REPAIR')
        directories[relative]={'mode':format(mode,'04o'),'uid':info.st_uid,'gid':info.st_gid,
            'dev':info.st_dev,'inode':info.st_ino}
    raw=private(root/'sources.sha256');require(hashlib.sha256(raw).hexdigest()==expected,'ORIGINAL_MANIFEST_PIN_REQUIRED')
    entries={}
    for line in raw.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ((?:scripts|tools)/[A-Za-z0-9_]+\.py)',line)
        require(match is not None and match[2] not in entries,'EXACT_ORIGINAL_MANIFEST_REQUIRED');entries[match[2]]=match[1]
    require(len(entries)==26 and 'scripts/stage_semantic_local_producers_package.py' in entries,
        'ORIGINAL_V8_SOURCE_SET_REQUIRED')
    contents={p:private(root/'source'/p) for p in entries}
    require(all(hashlib.sha256(raw).hexdigest()==entries[p] for p,raw in contents.items()),'ORIGINAL_SOURCE_HASH_DRIFT')
    require(private(root/'sources.sha256')==raw and not os.path.lexists(root/'source-package-receipt.json'),
        'PACKAGE_CHANGED_DURING_INSPECTION')
    return directories,contents


def operate(mode,root,expected):
    directories,contents=inspect(root,expected);corrected=False
    if mode=='repair' and directories['source']['mode']=='0755':
        fd=os.open(root/'source',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);value=directories['source']
            require((before.st_dev,before.st_ino,before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))
                ==(value['dev'],value['inode'],0,0,0o755),'SOURCE_DIRECTORY_CHANGED')
            require(not os.path.lexists(root/'source-package-receipt.json'),'RECEIPT_EXISTS_DO_NOT_REPLAY')
            os.fchmod(fd,0o700);os.fsync(fd);corrected=True
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'SOURCE_MODE_REPAIR_UNPROVEN')
        finally:os.close(fd)
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    after,again=inspect(root,expected)
    require(again==contents and all(after[k]==v for k,v in directories.items() if k!='source')
        and all(after['source'][k]==directories['source'][k] for k in ('uid','gid','dev','inode')),
        'PACKAGE_CHANGED_DURING_DIRECTORY_RECOVERY')
    require(mode in ('inspect','repair') and (mode=='inspect' or after['source']['mode']=='0700'),
        'EXPLICIT_DIRECTORY_RECOVERY_MODE_REQUIRED')
    return {'schema':'ouf.semantic-private-package-directory-recovery.v1','mode':mode,'packageRoot':str(root),
        'sourceManifestHash':expected,'sourceCount':len(contents),'directoriesBefore':directories,'directoriesAfter':after,
        'sourceModeCorrected':corrected,'sourceBodiesExecuted':0,'receiptCreated':False,'ownershipChanged':False,
        'rulesChanged':False,'unitsChanged':False,'containersChanged':False,'runtimeRegistered':False,
        'startAuthorized':False,'privateKeysRead':0,'signaturesIssued':0,'providerCalls':0,'noSecretsPrinted':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('inspect','repair'),required=True)
    parser.add_argument('--package-root',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True);args=parser.parse_args()
    try:
        value=operate(args.mode,args.package_root,args.source_manifest_sha256)
        print('SEMANTIC_PACKAGE_DIRECTORY_RECOVERY='+json.dumps(value,sort_keys=True))
        print('SEMANTIC_PACKAGE_DIRECTORY_RECOVERY=PASS MODE='+args.mode+' NO_SOURCE_BODY_EXECUTED=true NO_START_AUTHORIZED=true')
        return 0
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z_]{1,80}',reason):reason='PRIVATE_DIRECTORY_RECOVERY_UNPROVEN'
        print('SEMANTIC_PACKAGE_DIRECTORY_RECOVERY=BLOCKED REASON='+reason+' NO_SECRETS_PRINTED=true');return 1


if __name__=='__main__':raise SystemExit(main())
