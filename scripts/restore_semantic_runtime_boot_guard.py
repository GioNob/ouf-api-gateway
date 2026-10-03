#!/usr/bin/env python3
"""Sealed empty-set runtime boot guard with a persistent transition gate."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()


def directory(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe directory')
    for p in (path, *path.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise ValueError('unsafe ancestor')


def private(path, limit=2_000_000):
    directory(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 \
                or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>limit: raise ValueError('unsafe file')
        raw=os.read(fd,limit+1)
        if len(raw)>limit: raise ValueError('size limit')
        return raw
    finally: os.close(fd)


def unique(pairs):
    value={}
    for k,v in pairs:
        if k in value: raise ValueError('duplicate key')
        value[k]=v
    return value


def read(path): return json.loads(private(path),object_pairs_hook=unique)


def safe_path(value):
    if not isinstance(value,str) or not re.fullmatch('/[A-Za-z0-9_./-]+',value) \
            or '..' in Path(value).parts: raise ValueError('unsafe explicit path')
    return Path(value)


def lock(path, create=False):
    directory(path.parent)
    flags=os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK
    fd=os.open(path,flags|(os.O_CREAT if create else 0),0o600)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 \
                or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError('unsafe lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        now=path.lstat()
        if (s.st_dev,s.st_ino)!=(now.st_dev,now.st_ino): raise ValueError('lock replaced')
        return fd
    except Exception: os.close(fd); raise


def run(command, raw=None):
    r=subprocess.run(command,input=raw,capture_output=True,text=True,timeout=25)
    if r.returncode or len(r.stdout)>2_000_000: raise ValueError('operation unproven')
    return r.stdout


def stable(v, lease=False, omit_set_elements=True):
    if isinstance(v,list):
        return [stable(x,lease,omit_set_elements) for x in v if lease or not isinstance(x,dict) or 'metainfo' not in x]
    if isinstance(v,dict):
        if omit_set_elements and isinstance(v.get('set'),dict):
            return {'set':stable({k:x for k,x in v['set'].items() if k!='elem'},lease,omit_set_elements)}
        excluded=('packets','bytes','expires') if lease else ('handle','packets','bytes','expires')
        return {k:stable(x,lease,omit_set_elements) for k,x in v.items() if k not in excluded}
    return v


def footprint(v): return digest(encoded(stable(v)))


def shared(v, table):
    if not isinstance(v,dict) or set(v)!={'nftables'} or not isinstance(v['nftables'],list):
        raise ValueError('ruleset shape')
    kept=[]
    for item in v['nftables']:
        if not isinstance(item,dict): raise ValueError('ruleset entry')
        owned=any(isinstance(obj,dict) and obj.get('family') in ('inet','bridge') \
            and (obj.get('table')==table or k=='table' and obj.get('name')==table) for k,obj in item.items())
        if not owned: kept.append(item)
    return stable({'nftables':kept},omit_set_elements=False)


def compiler(configuration):
    path=safe_path(configuration['compilerFile'])
    raw=private(path)
    if not re.fullmatch('[0-9a-f]{64}',configuration['compilerHash']) \
            or digest(raw)!=configuration['compilerHash']: raise ValueError('compiler drift')
    spec=importlib.util.spec_from_file_location('sealed_runtime_kernel_compiler',path)
    module=importlib.util.module_from_spec(spec); exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def rules(configuration):
    value=compiler(configuration).materialize(configuration['kernel'],empty_provider_sets=True)
    table=value['tableName']
    return 'create table inet '+table+'\ncreate table bridge '+table+'\n'+value['nftRules']


def validate(configuration):
    if set(configuration)!={'schema','nftPath','kernel','compilerFile','compilerHash','expectedFootprint',
                             'journalFile','transactionId','lockFile'} \
            or configuration['schema']!='ouf.semantic-runtime-boot-guard.v1' \
            or not re.fullmatch('[0-9a-f]{64}',configuration['expectedFootprint']) \
            or not re.fullmatch('[0-9a-f]{64}',configuration['transactionId']): raise ValueError('sealed profile invalid')
    for k in ('nftPath','journalFile','lockFile'): safe_path(configuration[k])
    if any(v['addresses'] for v in configuration['kernel']['providerFlows']): raise ValueError('empty bootstrap required')
    return rules(configuration)


def tables(configuration):
    return {f:json.loads(run([configuration['nftPath'],'-j','list','table',f,configuration['kernel']['tableName']]),
                         object_pairs_hook=unique) for f in ('inet','bridge')}


def membership(configuration):
    raw=json.loads(run([configuration['nftPath'],'-j','list','tables']),object_pairs_hook=unique)
    return {v['table']['family'] for v in raw['nftables'] if 'table' in v \
            and v['table']['name']==configuration['kernel']['tableName'] \
            and v['table']['family'] in ('inet','bridge')}


def sets_empty(value):
    return all(not obj.get('set',{}).get('elem') for family in value.values() for obj in family['nftables'])


def restore(configuration, configuration_hash):
    bootstrap=validate(configuration)
    journal=read(safe_path(configuration['journalFile']))
    if journal.get('schema')!='ouf.semantic-runtime-transition.v1' \
            or journal.get('state')!='RUNTIME_EMPTY' \
            or journal.get('transactionId')!=configuration['transactionId'] \
            or journal.get('configurationHash')!=configuration_hash \
            or journal.get('startAuthorized') is not False: raise ValueError('transition incomplete')
    nft=configuration['nftPath']; table=configuration['kernel']['tableName']
    present=membership(configuration)
    if present and present!={'inet','bridge'}: raise ValueError('partial tables')
    before=shared(json.loads(run([nft,'-j','list','ruleset']),object_pairs_hook=unique),table)
    if present:
        current=tables(configuration)
        if footprint(current)!=configuration['expectedFootprint']: raise ValueError('runtime structure drift')
        # This initial profile is intentionally empty-only. A nonempty lease
        # requires its own coordinated lifecycle, never silently flushing an owner.
        if not sets_empty(current): raise ValueError('active leases require coordination')
        restored=False
    else:
        run([nft,'-f','-'],bootstrap); restored=True
    current=tables(configuration)
    if footprint(current)!=configuration['expectedFootprint'] or not sets_empty(current):
        raise ValueError('restore readback drift')
    after=shared(json.loads(run([nft,'-j','list','ruleset']),object_pairs_hook=unique),table)
    if before!=after: raise ValueError('shared structure drift')
    # Restoring tables changes handles. Never silently rebind the frozen lease
    # backend hash: a later lease installation needs explicit reconciliation.
    lease_hash=digest(encoded(stable(current,True)))
    return {'restored':restored,'leaseStructureHash':lease_hash,
            'leaseStructureReconciliationRequired':restored or lease_hash!=journal.get('leaseStructureHash'),
            'startAuthorized':False}


def native_template(value):
    if os.geteuid()!=0 or value['parentNetworkNamespace']==os.stat('/proc/self/ns/net').st_ino:
        raise ValueError('isolated namespace required')
    safe_path(value['nftPath'])
    bootstrap=rules(value)
    if membership(value): raise ValueError('namespace collision')
    run([value['nftPath'],'-f','-'],bootstrap)
    current=tables(value)
    if not sets_empty(current): raise ValueError('template not empty')
    return stable(current)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-template',action='store_true')
    p.add_argument('--configuration',type=Path)
    p.add_argument('--configuration-sha256')
    p.add_argument('--lock-file',type=Path)
    args=p.parse_args(argv); fd=None
    try:
        if os.geteuid()!=0: raise ValueError('root required')
        if args.native_template:
            raw=sys.stdin.buffer.read(131073)
            if len(raw)>131072: raise ValueError('template input bound')
            print(encoded(native_template(json.loads(raw,object_pairs_hook=unique))).decode()); return 0
        raw=private(args.configuration,131072)
        if not re.fullmatch('[0-9a-f]{64}',args.configuration_sha256 or '') \
                or digest(raw)!=args.configuration_sha256: raise ValueError('configuration drift')
        value=json.loads(raw,object_pairs_hook=unique)
        if args.lock_file!=safe_path(value['lockFile']): raise ValueError('different lock domain')
        fd=lock(args.lock_file,create=True)
        result=restore(value,args.configuration_sha256)
        print('SEMANTIC_RUNTIME_BOOT_GUARD=PASS RESTORED='+str(result['restored']).lower()+
              ' EMPTY_PROVIDER_SETS=true START_AUTHORIZED=false LEASE_RECONCILIATION_REQUIRED='+
              str(result['leaseStructureReconciliationRequired']).lower()+' NO_PROVIDER_CALL=true')
        return 0
    except Exception:
        print('SEMANTIC_RUNTIME_BOOT_GUARD=BLOCKED DOCKER_START_MUST_BE_DENIED=true NO_SECRETS_PRINTED=true'); return 1
    finally:
        if fd is not None: os.close(fd)


if __name__=='__main__': raise SystemExit(main())
