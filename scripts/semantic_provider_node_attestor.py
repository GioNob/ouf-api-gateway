"""Source-sealed node attestor; explicit v2/v3 live mandate, no key generation or start."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types

SELF = 'scripts/semantic_provider_node_attestor.py'
MODULES = ('materialize_southbound_kernel','materialize_southbound_lease_refresh','semantic_provider_dns',
    'semantic_provider_lease_nft','semantic_provider_lease_owner','materialize_semantic_shared_faces',
    'semantic_provider_lease_coordination','semantic_provider_preexec','semantic_provider_preexec_native',
    'semantic_provider_deployment_admission','semantic_provider_deployment_protocol',
    'semantic_provider_deployment_consumption','semantic_provider_deployment_authentication',
    'semantic_provider_deployment_reauthorization','semantic_provider_deployment_producer',
    'semantic_provider_deployment_signing','semantic_provider_installer_approval','semantic_provider_node_observation','semantic_provider_node_attestor')

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
    raw=private(path);cfg=parse(raw);root=Path(cfg['sourceRoot'])
    require(stat.S_IMODE(root.lstat().st_mode)==0o700,'PRIVATE_ISSUER_SOURCE_ROOT_REQUIRED')
    paths=[SELF,*('tools/'+name+'.py' for name in MODULES)]
    require(Path(__file__).absolute()==root/SELF and set(cfg['sourceHashes'])==set(paths),'EXACT_ISSUER_SOURCE_CLOSURE_REQUIRED')
    verified={p:private(root/p) for p in paths}
    for p,content in verified.items():require(hashlib.sha256(content).hexdigest()==cfg['sourceHashes'][p],'ISSUER_SOURCE_PACKAGE_DRIFT')
    package=types.ModuleType('tools');package.__path__=[];sys.modules['tools']=package
    for name in MODULES:
        full='tools.'+name;module=types.ModuleType(full);module.__package__='tools'
        module.__file__=str(root/'tools'/(name+'.py'));sys.modules[full]=module;setattr(package,name,module)
        exec(compile(verified['tools/'+name+'.py'],module.__file__,'exec'),module.__dict__)
    executable(cfg['pythonBinding']['path'],cfg['pythonBinding']['sha256'])
    require(Path(sys.executable).absolute()==Path(cfg['pythonBinding']['path']),'ISSUER_INTERPRETER_BINDING_DRIFT')
    require(private(path)==raw,'ISSUER_CONFIGURATION_DRIFT')
    return cfg,raw


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--configuration',required=True)
    args=parser.parse_args()
    try:
        cfg,raw=load(args.configuration)
        from tools.semantic_provider_node_attestor import NodeAttestor
        configured={'python':cfg['pythonBinding'],
            'source':{'path':str(Path(__file__).absolute()),'sha256':cfg['sourceHashes'][SELF]},
            'configuration':{'path':str(Path(args.configuration).absolute()),'sha256':hashlib.sha256(raw).hexdigest()}}
        reply=NodeAttestor(cfg,raw,args.configuration,configured).emit(sys.stdin.buffer.read(4097))
        sys.stdout.buffer.write(reply);return 0
    except Exception:
        print('SEMANTIC_NODE_ATTESTOR=DENIED NO_SECRETS_PRINTED=true',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
