#!/usr/bin/env python3
"""Read-only boot custody after stopped creation; no IAM, DNS or provider calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def private(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe path')
    for p in (path.parent, *path.parent.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022: raise ValueError('unsafe ancestor')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 \
                or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>131072: raise ValueError('unsafe file')
        raw=os.read(fd,131073)
        if len(raw)>131072: raise ValueError('large file')
        return raw
    finally: os.close(fd)


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def read(path):
    raw=private(path)
    return json.loads(raw),digest(raw)


def run(command):
    r=subprocess.run(command,capture_output=True,text=True,timeout=30)
    if r.returncode or len(r.stdout)>2_000_000: raise ValueError('readback failed')
    return r.stdout


def canonical(value,stable=False):
    if isinstance(value,list):
        return [canonical(v,stable) for v in value if not stable or not isinstance(v,dict) or 'metainfo' not in v]
    if isinstance(value,dict):
        excluded=('packets','bytes','expires','handle') if stable else ('packets','bytes','expires')
        return {k:canonical(v,stable) for k,v in value.items() if k not in excluded}
    return value


def candidate(spec,journal,row):
    state=row['State']; labels=row['Config'].get('Labels') or {};host=row['HostConfig']
    if row['Id']!=journal['candidateIds'][spec['name']] or row['Name']!='/'+spec['name'] or row['Image']!=spec['image'] \
            or state['Status']!='created' or state['Running'] or state.get('Restarting') \
            or not state['StartedAt'].startswith('0001-01-01T') \
            or labels.get('ouf.semantic.candidate.transaction')!=journal['transaction'] \
            or labels.get('ouf.semantic.candidate.manifest')!=journal['manifestHash'] \
            or host['RestartPolicy']['Name']!='no': raise ValueError('candidate custody drift')
    # This is custody inventory, not a replacement for full creation/configuration acceptance.
    return row['Id']


def operate(args):
    if os.geteuid()!=0 or not re.fullmatch('[0-9a-f]{40}',args.creation_source_commit): raise ValueError('root/source required')
    for path in (args.docker_path,args.nft_path,args.systemctl_path):
        if not re.fullmatch('/[A-Za-z0-9_./-]+',path) or '..' in Path(path).parts: raise ValueError('explicit path required')
    manifest,mh=read(args.manifest_root/'stopped-manifest.json')
    journal,jh=read(args.creation_root/'creation-journal.json')
    if manifest.get('schema')!='ouf.semantic-provider-stopped-manifest.v1' or manifest.get('startAuthorized') is not False \
            or len(manifest.get('containers',[]))!=2 or journal.get('schema')!='ouf.semantic-provider-stopped-create.v1' \
            or journal.get('sourceCommit')!=args.creation_source_commit or journal.get('state')!='CREATED_STOPPED' \
            or journal.get('startAuthorized') is not False or journal.get('manifestHash')!=mh \
            or set(journal.get('candidateIds',{}))!={c['name'] for c in manifest['containers']} \
            or len(set(journal['candidateIds'].values()))!=2: raise ValueError('creation binding drift')
    for spec in manifest['containers']:
        candidate(spec,journal,json.loads(run([args.docker_path,'inspect','--type','container',spec['name']]))[0])
    cold,ch=read(args.network_root/'network-receipt.json')
    if ch!=manifest['networkReceiptHash']: raise ValueError('cold receipt drift')
    for role,nid in cold['networkIds'].items():
        net=json.loads(run([args.docker_path,'network','inspect',nid]))[0]
        binding=cold['binding']
        if net['Id']!=nid or net['Name']!=binding[role+'_network'] or net['Driver']!='bridge' or net['EnableIPv6'] \
                or net['Internal']!=(role=='internal') or net.get('Options',{}).get('com.docker.network.bridge.name')!=binding[role+'_bridge'] \
                or set(net.get('Containers') or {})-set(journal['candidateIds'].values()): raise ValueError('owned network drift')
    stage,sh=read(args.boot_stage_root/'boot-stage-receipt.json')
    install,ih=read(args.boot_install_root/'install-journal.json')
    if stage.get('schema')!='ouf.semantic-boot-guard-stage.v1' or install.get('schema')!='ouf.semantic-boot-guard-install.v1' \
            or install.get('state')!='installed' or install.get('stageReceiptHash')!=sh or stage.get('coldReceiptHash')!=ch \
            or stage['profile']['root']!=str(args.boot_stage_root) or install['stageRoot']!=str(args.boot_stage_root):
        raise ValueError('boot custody drift')
    if set(stage['artifactHashes'])!={'boot-configuration.json','guard.service','docker-drop-in.conf'} \
            or set(stage['sourceHashes'])!={'restore_semantic_boot_guard.py','stage_semantic_boot_guard.py'}:
        raise ValueError('boot cohort drift')
    for name,h in stage['artifactHashes'].items():
        if digest(private(args.boot_stage_root/name))!=h: raise ValueError('boot artifact drift')
    for name,h in stage['sourceHashes'].items():
        if digest(private(args.boot_stage_root/'source/scripts'/name))!=h: raise ValueError('boot source drift')
    profile=stage['profile']; root=Path(install['unitRoot']); guard=profile['guardUnit']+'.service'; docker=profile['dockerUnit']
    for name,target in [('guard.service',root/guard),('docker-drop-in.conf',root/(docker+'.d')/('90-'+profile['guardUnit']+'.conf'))]:
        if private(target)!=private(args.boot_stage_root/name): raise ValueError('installed file drift')
    for unit,substate in ((docker,'running'),(guard,'exited')):
        properties=('LoadState','ActiveState','SubState','MainPID','NeedDaemonReload','ExecStartPre')
        raw=run([args.systemctl_path,'show','--all',unit,*['--property='+p for p in properties]])
        row=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        if row['LoadState']!='loaded' or row['ActiveState']!='active' or row['SubState']!=substate or row['NeedDaemonReload']!='no':
            raise ValueError('loaded boot drift')
        if unit==docker and (row['MainPID']!=install['proof']['dependentMainPID'] \
                or digest(row.get('ExecStartPre','').encode())!=install['proof']['dependentExecStartPreFingerprint']):
            raise ValueError('Docker/pre-start custody drift')
    conf,_=read(args.boot_stage_root/'boot-configuration.json');table=cold['binding']['table_name']
    if conf['schema']!='ouf.semantic-deny-boot-guard.v1' or conf['tableName']!=table or conf['nftPath']!=args.nft_path:
        raise ValueError('deny boot binding drift')
    tables={f:json.loads(run([args.nft_path,'-j','list','table',f,table])) for f in ('inet','bridge')}
    if digest(encoded(canonical(tables,True)))!=conf['expectedFootprint'] \
            or digest(encoded(canonical(tables)))!=manifest['guardHash']: raise ValueError('guard footprint drift')
    return {'schema':'ouf.semantic-provider-guard-custody.v1','creationJournalHash':jh,'manifestHash':mh,
            'bootInstallJournalHash':ih,'candidateCount':2,'neverStarted':True,'bootProfile':'DENY_ONLY',
            'bootTransitionRequiredBeforeRuntimeRules':True,'startAuthorized':False,'kernelLeaseInstalled':False,
            'readOnly':True,'providerCalls':0,'notReleaseAcceptance':True,'noSecretsPrinted':True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest-root','creation-root','network-root','boot-stage-root','boot-install-root'): p.add_argument('--'+name,type=Path,required=True)
    for name in ('creation-source-commit','docker-path','nft-path','systemctl-path'): p.add_argument('--'+name,required=True)
    try:
        print('SEMANTIC_PROVIDER_GUARD_CUSTODY='+json.dumps(operate(p.parse_args()),sort_keys=True))
        print('SEMANTIC_PROVIDER_GUARD_CUSTODY_INVENTORY=PASS READ_ONLY=true NO_IAM_OR_DNS_CALL=true NO_CONTAINER_OR_RULE_CHANGED=true NO_SECRETS_PRINTED=true')
    except Exception:
        print('SEMANTIC_PROVIDER_GUARD_CUSTODY_INVENTORY=BLOCKED NO_CHANGES=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None

if __name__=='__main__': main()
