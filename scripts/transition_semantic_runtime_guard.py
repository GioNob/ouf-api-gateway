#!/usr/bin/env python3
"""Journalled deny-to-empty runtime transition; never restart Docker or candidates."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import uuid


def bootstrap_read(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe path')
    for p in (path.parent,*path.parent.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise ValueError('unsafe ancestor')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 \
                or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>2_000_000: raise ValueError('unsafe file')
        raw=os.read(fd,2_000_001)
        if len(raw)>2_000_000: raise ValueError('size limit')
        return raw
    finally: os.close(fd)


def module(path, expected):
    raw=bootstrap_read(path)
    if hashlib.sha256(raw).hexdigest()!=expected: raise ValueError('source drift')
    spec=importlib.util.spec_from_file_location('sealed_runtime_transition_'+path.stem,path)
    value=importlib.util.module_from_spec(spec); exec(compile(raw,str(path),'exec'),value.__dict__)
    return value


def command_definition(value):
    pairs=re.findall(r'(path|argv\[\]|ignore_errors)=([^;]*);',value)
    if not pairs or len(pairs)%3 or any(pairs[i][0]!=key
            for i,key in enumerate(('path','argv[]','ignore_errors')*(len(pairs)//3))):
        raise ValueError('command definition unproven')
    return [(k,v.strip()) for k,v in pairs]


def show(guard, systemctl, unit):
    props=('LoadState','ActiveState','SubState','MainPID','FragmentPath','DropInPaths','ExecStart',
           'ExecStartPre','NeedDaemonReload','Requires','After','UnitFileState')
    text=guard.run([systemctl,'show','--all',unit,*['--property='+p for p in props]])
    value=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
    value.setdefault('ExecStartPre',''); return value


def fsync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def replace(guard, path, raw, permitted):
    # Only replace a byte-for-byte owned old/new file; no foreign-file adoption.
    if guard.private(path) not in permitted: raise ValueError('foreign installed file')
    if guard.private(path)==raw: return
    temp=path.parent/('.ouf-runtime-'+uuid.uuid4().hex)
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)
    # Recheck ownership immediately before the atomic publication.
    if guard.private(path) not in permitted: raise ValueError('installed file changed')
    os.replace(temp,path); fsync_directory(path.parent)


def journal(guard, path, record):
    guard.directory(path.parent)
    if os.path.lexists(path): guard.private(path)
    temp=path.parent/('.journal-'+uuid.uuid4().hex)
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(guard.encoded(record)); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)
    os.replace(temp,path); fsync_directory(path.parent)


def stage(args):
    receipt=json.loads(bootstrap_read(args.stage_root/'runtime-stage-receipt.json'))
    if receipt.get('schema')!='ouf.semantic-runtime-transition-stage.v1' \
            or receipt.get('sourceCommit')!=args.stage_source_commit or receipt.get('startAuthorized') is not False \
            or receipt.get('notReleaseAcceptance') is not True or receipt.get('nativeTemplateIsolated') is not True:
        raise ValueError('stage receipt binding')
    source=args.stage_root.parent/'source/scripts'
    guard=module(source/'restore_semantic_runtime_boot_guard.py',receipt['sourceHashes']['restore_semantic_runtime_boot_guard.py'])
    for name,h in receipt['sourceHashes'].items():
        if name not in ('restore_semantic_runtime_boot_guard.py','stage_semantic_runtime_transition.py',
                        'transition_semantic_runtime_guard.py') or guard.digest(guard.private(source/name))!=h:
            raise ValueError('stage source drift')
    if set(receipt['sourceHashes'])!={'restore_semantic_runtime_boot_guard.py','stage_semantic_runtime_transition.py',
                                     'transition_semantic_runtime_guard.py'}: raise ValueError('source cohort incomplete')
    if guard.digest(guard.private(Path(__file__).absolute()))!=receipt['sourceHashes']['transition_semantic_runtime_guard.py']:
        raise ValueError('installer source drift')
    artifacts={}
    for name,h in receipt['artifactHashes'].items():
        if name not in ('runtime-configuration.json','native-template.json','guard.service','docker-drop-in.conf'):
            raise ValueError('artifact cohort')
        raw=guard.private(args.stage_root/name)
        if guard.digest(raw)!=h: raise ValueError('stage artifact drift')
        artifacts[name]=raw
    if set(artifacts)!={'runtime-configuration.json','native-template.json','guard.service','docker-drop-in.conf'}:
        raise ValueError('artifact cohort incomplete')
    conf=json.loads(artifacts['runtime-configuration.json'],object_pairs_hook=guard.unique)
    guard.validate(conf)
    if guard.digest(artifacts['runtime-configuration.json'])!=receipt['configurationHash'] \
            or conf['journalFile']!=str(args.stage_root/'transition-journal.json') \
            or guard.footprint(json.loads(artifacts['native-template.json']))!=conf['expectedFootprint']:
        raise ValueError('native/configuration binding')
    intent_root=Path(receipt['intentRoot']); intent=guard.read(intent_root/'transition-intent.json')
    if guard.digest(guard.private(intent_root/'transition-intent.json'))!=receipt['intentHash']:
        raise ValueError('intent drift')
    roots={k:Path(v) for k,v in intent['roots'].items()}
    original_stage=guard.read(roots['boot_stage_root']/'boot-stage-receipt.json')
    original_install=guard.read(roots['boot_install_root']/'install-journal.json')
    if guard.digest(guard.private(roots['boot_stage_root']/'boot-stage-receipt.json'))!=intent['bootStageReceiptHash'] \
            or guard.digest(guard.private(roots['boot_install_root']/'install-journal.json'))!=intent['custody']['bootInstallJournalHash']:
        raise ValueError('original boot custody drift')
    profile=receipt['profile']
    if profile['guardUnit']!=original_stage['profile']['guardUnit'] \
            or profile['dockerUnit']!=original_stage['profile']['dockerUnit'] \
            or profile['runtimeDirectory']!=original_stage['profile']['runtimeDirectory'] \
            or conf['lockFile']!=intent['bootLockFile']: raise ValueError('unit/common lock drift')
    unitroot=guard.safe_path(original_install['unitRoot']); dependent=profile['dockerUnit']
    guardunit=profile['guardUnit']+'.service'
    # These paths come from the verified original installation, never a new target choice.
    unit=unitroot/guardunit; drop=unitroot/(dependent+'.d')/('90-'+profile['guardUnit']+'.conf')
    old_artifacts={}
    for name in ('guard.service','docker-drop-in.conf','boot-configuration.json'):
        raw=guard.private(roots['boot_stage_root']/name)
        if guard.digest(raw)!=original_stage['artifactHashes'][name]: raise ValueError('original artifact drift')
        old_artifacts[name]=raw
    return guard,receipt,artifacts,conf,intent,roots,original_install,guardunit,unit,drop,old_artifacts


def independent(guard, receipt, intent, roots, original_install, conf):
    exe=receipt['executables']; row=show(guard,exe['systemctl_path'],receipt['profile']['dockerUnit'])
    baseline=original_install['baseline']
    if row['LoadState']!='loaded' or row['ActiveState']!='active' or row['SubState']!='running' \
            or row['MainPID']!=original_install['proof']['dependentMainPID'] \
            or row['FragmentPath']!=baseline['FragmentPath'] or row['UnitFileState']!=baseline['UnitFileState'] \
            or command_definition(row['ExecStart'])!=command_definition(baseline['ExecStart']):
        raise ValueError('running dependent drift')
    manifest=guard.read(roots['manifest_root']/'stopped-manifest.json')
    creation=guard.read(roots['creation_root']/'creation-journal.json')
    if guard.digest(guard.private(roots['manifest_root']/'stopped-manifest.json'))!=intent['custody']['manifestHash'] \
            or guard.digest(guard.private(roots['creation_root']/'creation-journal.json'))!=intent['custody']['creationJournalHash']:
        raise ValueError('candidate custody drift')
    for spec in manifest['containers']:
        c=json.loads(guard.run([exe['docker_path'],'inspect','--type','container',spec['name']]))[0]
        state=c['State']; labels=c['Config'].get('Labels') or {}
        if c['Id']!=creation['candidateIds'][spec['name']] or c['Name']!='/'+spec['name'] or c['Image']!=spec['image'] \
                or state['Status']!='created' or state['Running'] or state.get('Restarting') \
                or not state['StartedAt'].startswith('0001-01-01T') \
                or labels.get('ouf.semantic.candidate.transaction')!=creation['transaction'] \
                or labels.get('ouf.semantic.candidate.manifest')!=creation['manifestHash'] \
                or c['HostConfig']['RestartPolicy']['Name']!='no': raise ValueError('started/foreign candidate')
    cold=guard.read(roots['network_root']/'network-receipt.json')
    for role,nid in cold['networkIds'].items():
        net=json.loads(guard.run([exe['docker_path'],'network','inspect',nid]))[0]
        if net['Id']!=nid or net['Name']!=cold['binding'][role+'_network'] or net['Driver']!='bridge' \
                or net['EnableIPv6'] or net['Internal']!=(role=='internal') \
                or net.get('Options',{}).get('com.docker.network.bridge.name')!=cold['binding'][role+'_bridge'] \
                or set(net.get('Containers') or {})-set(creation['candidateIds'].values()): raise ValueError('foreign network')
    if guard.digest(guard.encoded(guard.shared(json.loads(guard.run([exe['nft_path'],'-j','list','ruleset'])),intent['tableName']))) \
            !=intent['sharedStructureHash']: raise ValueError('shared structure drift')
    # Recheck all immutable runtime/lease inputs, without imports or IAM calls.
    runtime=guard.read(roots['runtime_root']/'stage-receipt.json')
    if guard.digest(guard.private(roots['runtime_root']/'stage-receipt.json'))!=intent['runtimeReceiptHash']:
        raise ValueError('runtime receipt drift')
    for name,key in (('binding.json','bindingHash'),('runtime-plan.json','planHash')):
        if guard.digest(guard.private(roots['runtime_root']/name))!=runtime[key]: raise ValueError('runtime input drift')
    package=guard.read(roots['lease_package_root']/'source-package-receipt.json')
    if guard.digest(guard.private(roots['lease_package_root']/'source-package-receipt.json'))!=intent['leasePackageReceiptHash']:
        raise ValueError('lease package drift')
    for name,h in package['sourceHashes'].items():
        if guard.digest(guard.private(roots['lease_package_root']/'source'/name))!=h: raise ValueError('lease source drift')
    return row


def loaded(guard,receipt,artifacts,original_install,guardunit,unit,drop):
    systemctl=receipt['executables']['systemctl_path']; dependent=receipt['profile']['dockerUnit']
    row=show(guard,systemctl,dependent); baseline=original_install['baseline']
    command=next(x[len('ExecStartPre='):] for x in artifacts['docker-drop-in.conf'].decode().splitlines() if x.startswith('ExecStartPre='))
    expected=[('path',command.split()[0]),('argv[]',command),('ignore_errors','no')]
    if row['NeedDaemonReload']!='no' or row['DropInPaths'].split()!=[str(drop)] \
            or command_definition(row['ExecStartPre'])!=expected: raise ValueError('loaded pre-start drift')
    for k in ('Requires','After'):
        if set(row[k].split())!=set(baseline[k].split())|{guardunit}: raise ValueError('dependency graph drift')
    g=show(guard,systemctl,guardunit)
    gc=next(x[len('ExecStart='):] for x in artifacts['guard.service'].decode().splitlines() if x.startswith('ExecStart='))
    if g['FragmentPath']!=str(unit) or g['DropInPaths'] or g['NeedDaemonReload']!='no' \
            or command_definition(g['ExecStart'])!=[('path',gc.split()[0]),('argv[]',gc),('ignore_errors','no')]:
        raise ValueError('loaded guard drift')


def operate(args):
    if os.geteuid()!=0 or not re.fullmatch('[0-9a-f]{40}',args.stage_source_commit): raise ValueError('root/source required')
    g,r,a,c,intent,roots,original,gu,unit,drop,old=stage(args)
    g.safe_path(args.analyze_path)
    journal_path=Path(c['journalFile']); exists=os.path.lexists(journal_path)
    if args.mode in ('plan','apply'):
        if exists: raise ValueError('existing transaction reconcile')
        helper=module(args.stage_root.parent/'source/scripts/stage_semantic_runtime_transition.py',
                      r['sourceHashes']['stage_semantic_runtime_transition.py'])
        helper.verify_intent(argparse.Namespace(intent_root=Path(r['intentRoot']),
            intent_source_commit=r['intentSourceCommit'],intent_source_sha256=r['intentSourceHash'],
            **r['executables']),g)
    elif not exists: raise ValueError('journal required')
    fd=g.lock(Path(c['lockFile']))
    try:
        independent(g,r,intent,roots,original,c)
        current=g.tables(c); current_hash=g.digest(g.encoded(g.stable(current,True)))
        old_shape=current_hash==intent['ownedTableHash']
        runtime_shape=g.footprint(current)==c['expectedFootprint'] and g.sets_empty(current)
        if not old_shape and not runtime_shape: raise ValueError('foreign/active owned rules')
        record={'schema':'ouf.semantic-runtime-transition.v1','transactionId':c['transactionId'],
            'configurationHash':r['configurationHash'],'stageReceiptHash':g.digest(g.private(args.stage_root/'runtime-stage-receipt.json')),
            'state':'PREPARING','startAuthorized':False,'providerCalls':0,'dockerRestarted':False,
            'notReleaseAcceptance':True,'realRebootProven':False}
        if exists:
            saved=g.read(journal_path)
            for k in ('schema','transactionId','configurationHash','stageReceiptHash','startAuthorized'):
                if saved.get(k)!=record[k]: raise ValueError('transaction journal drift')
            if saved.get('state') not in ('PREPARING','GATE_FILES_WRITTEN','GATE_LOADED','RULES_APPLIED',
                                         'RUNTIME_EMPTY','ROLLBACK_BLOCKED','ROLLED_BACK'):
                raise ValueError('unknown partial phase')
            record=saved
        if args.mode=='verify':
            if record['state']!='RUNTIME_EMPTY' or not runtime_shape or current_hash!=record.get('leaseStructureHash'):
                raise ValueError('runtime/lease binding requires reconciliation')
            for path,name in ((unit,'guard.service'),(drop,'docker-drop-in.conf')):
                if g.private(path)!=a[name]: raise ValueError('installed artifact drift')
            loaded(g,r,a,original,gu,unit,drop); return record
        for path,name in ((unit,'guard.service'),(drop,'docker-drop-in.conf')):
            if g.private(path) not in (old[name],a[name]): raise ValueError('foreign installed artifact')
        if args.mode=='plan':
            if not old_shape or g.private(unit)!=old['guard.service'] or g.private(drop)!=old['docker-drop-in.conf']:
                raise ValueError('initial custody drift')
            return record
        if args.mode=='rollback':
            record['state']='ROLLBACK_BLOCKED'; journal(g,journal_path,record)
            if not old_shape:
                old_conf=json.loads(old['boot-configuration.json'])
                g.run([c['nftPath'],'-f','-'],'delete table inet '+intent['tableName']+'\ndelete table bridge '+intent['tableName']+'\n'+old_conf['rules'])
            else: old_conf=json.loads(old['boot-configuration.json'])
            # The original boot footprint excludes handles; legacy custody hashes
            # do not. Record that distinction instead of claiming exact restoration.
            if g.footprint(g.tables(c))!=old_conf['expectedFootprint']: raise ValueError('deny rollback drift')
            for path,name in ((unit,'guard.service'),(drop,'docker-drop-in.conf')):
                replace(g,path,old[name],(old[name],a[name]))
            g.run([r['executables']['systemctl_path'],'daemon-reload'])
            old_loaded={**a,'guard.service':old['guard.service'],'docker-drop-in.conf':old['docker-drop-in.conf']}
            loaded(g,r,old_loaded,original,gu,unit,drop)
            independent(g,r,intent,roots,original,c)
            record.update(state='ROLLED_BACK',rollbackOwnedHash=g.digest(g.encoded(g.stable(g.tables(c),True))),
                          legacyCustodyReconciliationRequired=not old_shape)
            journal(g,journal_path,record); return record
        if record['state'] in ('ROLLBACK_BLOCKED','ROLLED_BACK'): raise ValueError('rolled-back transaction requires separate reconciliation')
        if not exists:
            if not old_shape: raise ValueError('initial ownership drift')
            journal(g,journal_path,record)
        # Persist the blocked state before publishing files, including recovery
        # from a prior completed journal. ExecStartPre refuses incomplete phases.
        record['state']='PREPARING'; journal(g,journal_path,record)
        for path,name in ((unit,'guard.service'),(drop,'docker-drop-in.conf')):
            replace(g,path,a[name],(old[name],a[name]))
        record['state']='GATE_FILES_WRITTEN'; journal(g,journal_path,record)
        g.run([args.analyze_path,'verify',str(unit),original['baseline']['FragmentPath']])
        g.run([r['executables']['systemctl_path'],'daemon-reload'])
        loaded(g,r,a,original,gu,unit,drop)
        independent(g,r,intent,roots,original,c)
        record['state']='GATE_LOADED'; journal(g,journal_path,record)
        current=g.tables(c)
        if g.digest(g.encoded(g.stable(current,True)))==intent['ownedTableHash']:
            g.run([c['nftPath'],'-f','-'],'delete table inet '+intent['tableName']+'\ndelete table bridge '+intent['tableName']+'\n'+g.rules(c))
        elif g.footprint(current)!=c['expectedFootprint'] or not g.sets_empty(current): raise ValueError('pre-mutation owned drift')
        record['state']='RULES_APPLIED'; journal(g,journal_path,record)
        current=g.tables(c)
        if g.footprint(current)!=c['expectedFootprint'] or not g.sets_empty(current): raise ValueError('native runtime readback drift')
        loaded(g,r,a,original,gu,unit,drop); independent(g,r,intent,roots,original,c)
        record.update(state='RUNTIME_EMPTY',leaseStructureHash=g.digest(g.encoded(g.stable(current,True))))
        journal(g,journal_path,record)
        return record
    finally: os.close(fd)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=('plan','apply','verify','reconcile','rollback'),required=True)
    p.add_argument('--stage-root',type=Path,required=True)
    p.add_argument('--stage-source-commit',required=True)
    p.add_argument('--analyze-path',required=True)
    args=p.parse_args(argv)
    try:
        record=operate(args)
        print('SEMANTIC_RUNTIME_TRANSITION=PASS MODE='+args.mode+' STATE='+record['state']+
              ' START_AUTHORIZED=false PROVIDER_CALLS=0 DOCKER_RESTARTED=false NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        return 0
    except Exception:
        print('SEMANTIC_RUNTIME_TRANSITION=BLOCKED PARTIAL_EVIDENCE_RETAINED=true DO_NOT_RERUN_APPLY=true NO_SECRETS_PRINTED=true'); return 1


if __name__=='__main__': raise SystemExit(main())
