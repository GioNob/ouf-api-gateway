#!/usr/bin/env python3
"""Install sealed boot guard without restarting Docker; retain a private journal."""
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
import uuid


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def directory(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe directory')
    for p in (path, *path.parents):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('unsafe directory ownership')


def private(path):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_nlink != 1 \
                or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > 131072:
            raise ValueError('unsafe file')
        return os.read(fd, 131073)
    finally: os.close(fd)


def write(path, raw):
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600); os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)


def journal(path, value):
    if path.exists(): private(path)
    temp = path.parent / ('.journal-'+uuid.uuid4().hex)
    write(temp, encoded(value)); os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    if result.returncode or len(result.stdout) > 2_000_000: raise ValueError('command failed')
    return result.stdout


PROPERTIES = ('LoadState','ActiveState','SubState','MainPID','FragmentPath','DropInPaths',
              'ExecStart','ExecStartPre','NeedDaemonReload','Requires','After','UnitFileState')


def show(systemctl, unit):
    result = subprocess.run([systemctl,'show','--all',unit,*['--property='+p for p in PROPERTIES]],
                            capture_output=True,text=True,timeout=15)
    if len(result.stdout) > 2_000_000: raise ValueError('output limit')
    value = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    if result.returncode and value.get('LoadState') != 'not-found': raise ValueError('unit query failed')
    return value


def stable(value):
    return {k: value[k] for k in ('MainPID','FragmentPath','ExecStart','UnitFileState')}


def identity(value, allow_reload=False):
    # Commands stay private in the journal; external output never contains their text.
    if value['LoadState'] != 'loaded' or value['ActiveState'] != 'active' or value['SubState'] != 'running' \
            or int(value['MainPID']) <= 0 or (not allow_reload and value['NeedDaemonReload'] != 'no'):
        raise ValueError('active dependent required')
    return stable(value)


def prepare(args):
    for path in (args.systemctl_path,args.analyze_path):
        if not re.fullmatch('/[A-Za-z0-9_./-]+',path) or '..' in Path(path).parts:
            raise ValueError('explicit executable path required')
    directory(args.snapshot_root); directory(args.unit_root)
    if stat.S_IMODE(args.snapshot_root.stat().st_mode) != 0o700: raise ValueError('private journal root required')
    raw = private(args.stage_root/'boot-stage-receipt.json'); receipt = json.loads(raw)
    if receipt['schema'] != 'ouf.semantic-boot-guard-stage.v1' or receipt['sourceCommit'] != args.stage_commit \
            or receipt['notReleaseAcceptance'] is not True: raise ValueError('stage binding invalid')
    if set(receipt['artifactHashes']) != {'boot-configuration.json','guard.service','docker-drop-in.conf'} \
            or set(receipt['sourceHashes']) != {'restore_semantic_boot_guard.py','stage_semantic_boot_guard.py'}:
        raise ValueError('stage cohort invalid')
    artifacts = {}
    for name, expected in receipt['artifactHashes'].items():
        artifacts[name] = private(args.stage_root/name)
        if digest(artifacts[name]) != expected: raise ValueError('artifact drift')
    for name, expected in receipt['sourceHashes'].items():
        if digest(private(args.stage_root/'source/scripts'/name)) != expected: raise ValueError('source drift')
    profile = receipt['profile']; guard = profile['guardUnit']+'.service'; dependent = profile['dockerUnit']
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}',profile['guardUnit']) \
            or not re.fullmatch(r'[A-Za-z0-9_-]+\.service',dependent) or guard == dependent:
        raise ValueError('unit binding invalid')
    if profile['root'] != str(args.stage_root) or profile['scriptPath'] != str(args.stage_root/'source/scripts/restore_semantic_boot_guard.py'):
        raise ValueError('stage path drift')
    # Import only the verified private restore module for canonical read-only nft ownership checks.
    spec = importlib.util.spec_from_file_location('sealed_boot_restore', profile['scriptPath'])
    restore = importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)
    config = json.loads(artifacts['boot-configuration.json'])
    current = restore.observed(config['nftPath'],config['tableName'])
    if restore.footprint(current) != config['expectedFootprint']: raise ValueError('current guard drift')
    unit = args.unit_root/guard; dropdir = args.unit_root/(dependent+'.d')
    drop = dropdir/('90-'+profile['guardUnit']+'.conf')
    return receipt, artifacts, guard, dependent, unit, dropdir, drop


def check_loaded(args, baseline, guard, dependent, unit, drop, artifacts):
    docker = show(args.systemctl_path,dependent)
    if identity(docker) != stable(baseline): raise ValueError('dependent identity changed')
    if docker['DropInPaths'].split() != [str(drop)]: raise ValueError('drop-in not loaded exclusively')
    for key in ('Requires','After'):
        if set(docker[key].split()) != set(baseline[key].split()) | {guard}:
            raise ValueError('dependency drift')
    command = next(line[len('ExecStartPre='):] for line in artifacts['docker-drop-in.conf'].decode().splitlines()
                   if line.startswith('ExecStartPre='))
    if docker['ExecStartPre'].count('argv[]=') != 1 or 'argv[]='+command+' ;' not in docker['ExecStartPre']:
        raise ValueError('pre-start guard not loaded')
    observed = show(args.systemctl_path,guard)
    if observed['FragmentPath'] != str(unit) or observed['DropInPaths'] or observed['NeedDaemonReload'] != 'no' \
            or observed['ActiveState'] != 'active' or observed['SubState'] != 'exited':
        raise ValueError('guard not active as expected')
    return {'dependentMainPID':docker['MainPID'],'dependentExecStartFingerprint':digest(docker['ExecStart'].encode()),
            'dependentExecStartPreFingerprint':digest(docker['ExecStartPre'].encode()),'guardActive':True}


def operate(args):
    if os.geteuid() != 0: raise ValueError('root required')
    if not re.fullmatch('[0-9a-f]{40}',args.stage_commit): raise ValueError('commit binding required')
    receipt,artifacts,guard,dependent,unit,dropdir,drop = prepare(args)
    journal_path = args.snapshot_root/'install-journal.json'
    if args.mode in ('verify','rollback'):
        record = json.loads(private(journal_path))
        if record['stageReceiptHash'] != digest(private(args.stage_root/'boot-stage-receipt.json')) \
                or record['unitRoot'] != str(args.unit_root) or record['stageRoot'] != str(args.stage_root):
            raise ValueError('installation journal drift')
        baseline = record['baseline']
        if args.mode == 'verify':
            if record['state'] != 'installed': raise ValueError('installation incomplete')
            for path,name in ((unit,'guard.service'),(drop,'docker-drop-in.conf')):
                if private(path) != artifacts[name]: raise ValueError('installed file drift')
            check_loaded(args,baseline,guard,dependent,unit,drop,artifacts)
            return record
        # No table removal and no dependent stop/restart. Only owned files may be removed.
        if identity(show(args.systemctl_path,dependent),allow_reload=True) != stable(baseline): raise ValueError('dependent changed')
        for path,name in ((unit,'guard.service'),(drop,'docker-drop-in.conf')):
            if os.path.lexists(path) and private(path) != artifacts[name]: raise ValueError('foreign installed file')
        record['state']='rollback-started'; journal(journal_path,record)
        if os.path.lexists(drop): drop.unlink()
        if os.path.lexists(unit): unit.unlink()
        if record['dropDirectoryCreated'] and dropdir.exists(): dropdir.rmdir()
        run([args.systemctl_path,'daemon-reload'])
        if show(args.systemctl_path,guard)['ActiveState'] != 'inactive':
            run([args.systemctl_path,'stop',guard])
        value = show(args.systemctl_path,dependent)
        if identity(value) != stable(baseline) or value['ExecStartPre'] != baseline['ExecStartPre'] \
                or value['DropInPaths'] != baseline['DropInPaths']: raise ValueError('rollback unproven')
        record['state']='rolled-back'; journal(journal_path,record)
        return record
    baseline = show(args.systemctl_path,dependent); identity(baseline)
    if baseline['DropInPaths'] or baseline['ExecStartPre']: raise ValueError('inventory changed; reconcile existing settings')
    if show(args.systemctl_path,guard)['LoadState'] != 'not-found': raise ValueError('guard unit already exists')
    if os.path.lexists(unit) or os.path.lexists(drop) or os.path.lexists(journal_path): raise ValueError('collision reconcile')
    if dropdir.exists(): directory(dropdir)
    record = {'schema':'ouf.semantic-boot-guard-install.v1','state':'planned',
        'stageReceiptHash':digest(private(args.stage_root/'boot-stage-receipt.json')),
        'stageRoot':str(args.stage_root),'unitRoot':str(args.unit_root),'baseline':baseline,
        'dropDirectoryCreated':not dropdir.exists(),'providerCalls':0,'dockerRestarted':False,
        'rulesChanged':False,'realRebootProven':False,'notReleaseAcceptance':True}
    if args.mode == 'plan': return record
    record['state']='started'; journal(journal_path,record)
    if not dropdir.exists(): dropdir.mkdir(mode=0o755)
    write(unit,artifacts['guard.service']); write(drop,artifacts['docker-drop-in.conf'])
    # Verify the installed dependency graph before publishing it to the manager.
    run([args.analyze_path,'verify',str(unit),baseline['FragmentPath']])
    run([args.systemctl_path,'daemon-reload'])
    # Only the existing deny-only guard runs; the dependent stays running.
    run([args.systemctl_path,'start',guard])
    proof = check_loaded(args,baseline,guard,dependent,unit,drop,artifacts)
    # Require the deny tables to remain semantically identical after guard startup.
    prepare(args)
    record.update(state='installed',proof=proof); journal(journal_path,record)
    return record


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',required=True,choices=('plan','apply','verify','rollback'))
    for name in ('stage-root','snapshot-root','unit-root'): parser.add_argument('--'+name,type=Path,required=True)
    for name in ('stage-commit','systemctl-path','analyze-path'): parser.add_argument('--'+name,required=True)
    args=parser.parse_args(argv); fd=None
    try:
        directory(args.snapshot_root)
        # plan is strictly read-only; apply/verify/rollback serialize all mutations.
        if args.mode != 'plan':
            lock=args.snapshot_root/'install.lock'
            fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_nlink != 1 \
                    or stat.S_IMODE(s.st_mode) != 0o600: raise ValueError('unsafe lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        record=operate(args)
        print('SEMANTIC_BOOT_INSTALL=PASS MODE='+args.mode+' DOCKER_RESTARTED=false RULES_CHANGED=false'
              ' PROVIDER_CALLS=0 REAL_REBOOT_NOT_PROVEN=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_BOOT_INSTALL_JOURNAL='+str(args.snapshot_root/'install-journal.json')+' PRIVATE=true')
        return 0
    except Exception:
        print('SEMANTIC_BOOT_INSTALL=BLOCKED DO_NOT_RERUN_BLINDLY=true PRIVATE_JOURNAL_RECONCILIATION_REQUIRED=true NO_SECRETS_PRINTED=true')
        return 1
    finally:
        if fd is not None: os.close(fd)


if __name__ == '__main__': raise SystemExit(main())
