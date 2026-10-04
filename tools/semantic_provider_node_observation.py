"""Read-only bounded rootfs and live created-candidate observations.

No trust is inferred from a digest. A distinct signed acceptance mandate must
bind the expected full OCI and rootfs seal to the intent/artifact/transport.
"""
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile

from tools.semantic_provider_deployment_authentication import attributes,ancestors,decode
from tools.semantic_provider_deployment_producer import encoded,program
from tools.semantic_provider_deployment_admission import application_hash,live_profile,transport_hash
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_preexec import PreexecDenied

def require(ok,reason):
    if not ok:raise PreexecDenied(reason)

def rootfs_seal(path,limits,budget):
    """Stream every entry, metadata, regular-file content and xattr; no exclusions.

    Relative symlinks are sealed as links, never followed. Special files are
    refused. Limits/deadline are enforced while enumerating and hashing.
    """
    require(set(limits)=={'maxEntries','maxBytes','maxDepth'} and
        all(type(v) is int for v in limits.values()) and 1<=limits['maxEntries']<=100000
        and 1<=limits['maxBytes']<=8589934592 and 1<=limits['maxDepth']<=64,'BOUNDED_ROOTFS_LIMITS_REQUIRED')
    path=Path(path);ancestors(path);h=hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00');count=total=queued=0
    def add(item):
        raw=encoded(item);h.update(len(raw).to_bytes(4,'big'));h.update(raw)
    def metadata(info):
        return {'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'links':info.st_nlink}
    def xattrs(fd):
        names=os.listxattr(fd);require(len(names)<=64,'ROOTFS_XATTRS_UNBOUNDED');result={}
        for name in sorted(names):
            budget.check();value=os.getxattr(fd,name);require(len(value)<=4096 and len(name)<=255,'ROOTFS_XATTRS_UNBOUNDED')
            result[name]=value.hex()
        return result
    def walk(fd,relative,depth):
        nonlocal count,total,queued
        budget.check();require(depth<=limits['maxDepth'],'ROOTFS_DEPTH_UNBOUNDED')
        before=os.fstat(fd);require(stat.S_ISDIR(before.st_mode),'ROOTFS_DIRECTORY_REQUIRED')
        count+=1;require(count<=limits['maxEntries'],'ROOTFS_ENTRIES_UNBOUNDED')
        add({'path':relative,'kind':'directory',**metadata(before),'xattrs':xattrs(fd)})
        names=[]
        with os.scandir(fd) as entries:
            for entry in entries:
                budget.check();names.append(entry.name);queued+=1
                require(queued+count<=limits['maxEntries'],'ROOTFS_ENTRIES_UNBOUNDED')
        for name in sorted(names):
            queued-=1
            budget.check();require(len(os.fsencode(name))<=255,'ROOTFS_NAME_UNBOUNDED')
            child=relative+'/'+name if relative else name;info=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                nested=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                try:
                    require(attributes(info)==attributes(os.fstat(nested)),'ROOTFS_ENTRY_REPLACED')
                    walk(nested,child,depth+1)
                finally:os.close(nested)
            elif stat.S_ISREG(info.st_mode):
                count+=1;require(count<=limits['maxEntries'],'ROOTFS_ENTRIES_UNBOUNDED')
                require(total+info.st_size<=limits['maxBytes'],'ROOTFS_BYTES_UNBOUNDED')
                stream=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                try:
                    require(attributes(info)==attributes(os.fstat(stream)),'ROOTFS_ENTRY_REPLACED')
                    content=hashlib.sha256();size=0;attrs=xattrs(stream)
                    while True:
                        budget.check();raw=os.read(stream,65536)
                        if not raw:break
                        size+=len(raw);total+=len(raw);require(total<=limits['maxBytes'],'ROOTFS_BYTES_UNBOUNDED');content.update(raw)
                    require(size==info.st_size and attributes(info)==attributes(os.fstat(stream)),'ROOTFS_CONTENT_CHANGED')
                    add({'path':child,'kind':'file',**metadata(info),'size':size,'sha256':content.hexdigest(),'xattrs':attrs})
                finally:os.close(stream)
            elif stat.S_ISLNK(info.st_mode):
                count+=1;require(count<=limits['maxEntries'],'ROOTFS_ENTRIES_UNBOUNDED')
                target=os.readlink(name,dir_fd=fd);require(len(os.fsencode(target))<=4096,'ROOTFS_LINK_UNBOUNDED')
                # Linux symlink user/security xattrs need pathname access. Do
                # not silently omit them: refuse any such metadata.
                link_path=path/child
                require(not os.listxattr(link_path,follow_symlinks=False),'ROOTFS_SYMLINK_XATTR_UNSUPPORTED')
                add({'path':child,'kind':'symlink',**metadata(info),'target':target})
            else:raise PreexecDenied('ROOTFS_SPECIAL_ENTRY_UNSUPPORTED')
            require(attributes(info)==attributes(os.stat(name,dir_fd=fd,follow_symlinks=False)),'ROOTFS_ENTRY_CHANGED')
        require(attributes(before)==attributes(os.fstat(fd)),'ROOTFS_DIRECTORY_CHANGED')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);walk(fd,'',0)
        require(attributes(before)==attributes(path.lstat()),'ROOTFS_ROOT_REPLACED')
    finally:os.close(fd)
    budget.check();return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':count,'bytes':total}

class NodeObservation:
    def __init__(self,cfg,budget):self.cfg,self.budget=cfg,budget
    def run(self,item,args,limit=131072):
        path=program(item,self.budget)
        with tempfile.TemporaryFile() as output:
            try:p=subprocess.run([path,*args],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,
                timeout=self.budget.remaining(2),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            except (OSError,subprocess.TimeoutExpired):raise PreexecDenied('NODE_OBSERVATION_UNPROVEN') from None
            output.seek(0);raw=output.read(limit+1)
        require(p.returncode==0 and len(raw)<=limit,'NODE_OBSERVATION_UNPROVEN');program(item,self.budget);return raw
    def observe(self,request,journal,bundle_reader):
        root=Path(journal['runtimeRoot']);ancestors(root/'state')
        require(root.is_absolute() and any(root!=Path(p) and root.is_relative_to(Path(p)) for p in self.cfg['runtimeRootParents']),
            'NODE_RUNTIME_ROOT_OUTSIDE_APPROVAL')
        state=decode(self.run(self.cfg['runtimeBinding'],['--root',str(root),'state',request['containerId']],16384),16384)
        require(state.get('id')==request['containerId'] and state.get('status')=='created' and
            type(state.get('pid')) is int and state['pid']>1,'NODE_LIVE_CREATED_STATE_REQUIRED')
        bundle=Path(state['bundle']);ancestors(bundle/'config.json')
        require(bundle.is_absolute() and any(Path(p) in bundle.parents for p in self.cfg['bundleParents']),
            'NODE_BUNDLE_OUTSIDE_APPROVAL')
        raw=bundle_reader(bundle/'config.json');oci=decode(raw,131072)
        require(application_hash(oci)==request['applicationHash']==journal['bundleHash'],'NODE_FULL_OCI_DRIFT')
        generation=NativeBackend.generation(None,state['pid'])
        require(generation==request['generation'],'NODE_GENERATION_DRIFT')
        root_path=Path(oci['root']['path']);root_path=root_path if root_path.is_absolute() else bundle/root_path
        require('..' not in root_path.parts,'NODE_ROOTFS_PATH_REQUIRED')
        seal=rootfs_seal(root_path,self.cfg['rootfsLimits'],self.budget)
        import json
        networks=[v for v in oci['linux']['namespaces'] if v.get('type')=='network']
        require(len(networks)==1,'NODE_NETWORK_NAMESPACE_REQUIRED')
        namespace=networks[0].get('path') or '/proc/'+str(state['pid'])+'/ns/net'
        require(Path(namespace).stat().st_ino==generation['namespaceInode'],'NODE_NAMESPACE_INODE_DRIFT')
        ip=self.cfg['commands']['ip'];ns=self.cfg['commands']['nsenter']
        children=json.loads(self.run(ns,['--net='+namespace,ip['path'],'-j','addr','show']))
        children=[v for v in children if v['ifname']!='lo'];hosts=[]
        require(len(children)==len(self.cfg['candidate']['networkBindings']),'NODE_UNAPPROVED_INTERFACE')
        program(ip,self.budget)
        for child in children:
            name=socket.if_indextoname(child['link_index'])
            hosts.extend(json.loads(self.run(ip,['-j','link','show','dev',name])))
        candidate={**self.cfg['candidate'],'containerId':request['containerId'],'transactionId':request['transactionId'],
            'applicationHash':request['applicationHash'],'bundlePath':str(bundle)}
        require(transport_hash(candidate)==request['transportHash'],'NODE_TRANSPORT_DRIFT')
        live_profile(candidate,oci,namespace,generation['namespaceInode'],children,hosts)
        require(NativeBackend.generation(None,state['pid'])==generation,'NODE_GENERATION_CHANGED')
        return {'applicationHash':request['applicationHash'],'rootfsSeal':seal,'generation':generation,
            'bundle':str(bundle),'rootfs':str(root_path),'state':state}
