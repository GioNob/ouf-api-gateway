import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from scripts import stage_semantic_boot_guard as staging
from scripts import install_semantic_boot_guard as installation
from scripts import stage_semantic_lease_package as package

from scripts import restore_semantic_boot_guard as guard
from scripts.stage_semantic_boot_guard import service
from tools.materialize_southbound_kernel import materialize


class BootProfileTest(unittest.TestCase):
    def test_handles_and_counters_are_not_authority_and_rules_are(self):
        self.assertEqual(guard.footprint({'handle':1,'counter':{'packets':8,'bytes':90},'verdict':'drop'}),
                         guard.footprint({'handle':2,'counter':{'packets':9,'bytes':99},'verdict':'drop'}))
        self.assertNotEqual(guard.footprint({'verdict':'drop'}),guard.footprint({'verdict':'accept'}))
    def test_reload_metadata_is_not_command_authority(self):
        first='{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 180 ; ignore_errors=no ; pid=123 ; start_time=old ; }'
        second=first.replace('pid=123','pid=0').replace('start_time=old','start_time=new')
        self.assertEqual(installation.command_definition(first),installation.command_definition(second))
        self.assertNotEqual(installation.command_definition(first),installation.command_definition(second.replace('sleep 180','sleep 90')))
        with self.assertRaises(ValueError): installation.command_definition('')
    def test_unit_profile_injection_rejected(self):
        profile = dict(guardUnit='guard',dockerUnit='docker.service',runtimeDirectory='guard',
            pythonPath='/usr/bin/python3',scriptPath='/etc/guard/restore.py',root='/etc/guard')
        unit,drop = service(profile,Path('/etc/guard/config.json'),'a'*64)
        self.assertIn('Before=docker.service',unit); self.assertIn('ExecStartPre=',drop)
        profile['dockerUnit'] = 'docker.service\nExecStart=/bin/sh'
        with self.assertRaises(ValueError): service(profile,Path('/etc/guard/config.json'),'a'*64)


@unittest.skipUnless(os.environ.get('OUF_BOOT_SYSTEMD_TEST') == '1','real root systemd/nft boot simulation is opt-in')
class RealBootOrderingTest(unittest.TestCase):
    def test_reconstruct_before_dependent_and_recheck_on_each_start(self):
        self.assertEqual(os.geteuid(),0)
        self.assertEqual(Path('/proc/1/comm').read_text().strip(),'systemd')
        suffix = uuid.uuid4().hex[:8]; name='ouf-boot-fixture-'+suffix; dependent=name+'-dependent'
        table='ouf_boot_'+suffix
        root=Path(tempfile.mkdtemp(prefix=name+'-',dir='/etc')); os.chmod(root,0o700)
        unit=Path('/run/systemd/system')/(name+'.service'); dep=unit.parent/(dependent+'.service')
        dropdir=unit.parent/(dependent+'.service.d'); dropdir.mkdir(mode=0o700)
        nft=shutil.which('nft'); created=False; nets=[]
        internal='ouf-boot-int-'+suffix; egress='ouf-boot-eg-'+suffix
        bridges=['obi-'+suffix,'obe-'+suffix]
        def run(*args,raw=None):
            return subprocess.run(args,input=raw,text=True,capture_output=True,timeout=30,check=True).stdout
        def erase():
            existing=json.loads(run(nft,'-j','list','tables'))
            for item in existing['nftables']:
                obj=item.get('table')
                if obj and obj['name']==table and obj['family'] in ('inet','bridge'):
                    run(nft,'delete','table',obj['family'],table)
        try:
            cfg={'tableName':table,'guardedInterfaces':bridges,'existingInterfaces':[], 'staticFlows':[],'providerFlows':[]}
            rules='create table inet '+table+'\ncreate table bridge '+table+'\n'+materialize(cfg)['nftRules']
            run(nft,'-f','-',raw=rules); created=True
            value={'schema':'ouf.semantic-deny-boot-guard.v1','nftPath':nft,'tableName':table,'rules':rules,
                   'expectedFootprint':guard.footprint(guard.observed(nft,table))}
            self.assertFalse(guard.restore(value))
            for net,bridge,inside in ((internal,bridges[0],True),(egress,bridges[1],False)):
                command=['docker','network','create','--driver','bridge','--opt','com.docker.network.bridge.name='+bridge]
                if inside: command.append('--internal')
                run(*command,net); nets.append(net)
            cold=root/'cold'; cold.mkdir(mode=0o700)
            cold_value={'schema':'ouf.semantic-provider-cold-networks.v1','notReleaseAcceptance':True,
                'binding':{'table_name':table,'internal_network':internal,'egress_network':egress,
                           'internal_bridge':bridges[0],'egress_bridge':bridges[1]},
                'networkIds':{role:json.loads(run('docker','network','inspect',net))[0]['Id']
                              for role,net in (('internal',internal),('egress',egress))},
                'guardHash':staging.digest(staging.encoded(staging.legacy(guard.observed(nft,table))))}
            for filename,content in (('network-receipt.json',json.dumps(cold_value).encode()),('deny-only.nft',rules.encode())):
                (cold/filename).write_bytes(content); os.chmod(cold/filename,0o600)
            lease=root/'lease'; lease.mkdir(mode=0o700); (lease/'source').mkdir(mode=0o700)
            for directory in ('scripts','tools'): (lease/'source'/directory).mkdir(mode=0o700)
            repo=Path(__file__).resolve().parents[1]
            for filename in package.FILES:
                (lease/'source'/filename).write_bytes((repo/filename).read_bytes()); os.chmod(lease/'source'/filename,0o600)
            package.operate(SimpleNamespace(mode='apply',package_root=lease,source_commit='a'*40))
            stage=root/'stage'; stage.mkdir(mode=0o700); (stage/'source').mkdir(mode=0o700)
            (stage/'source/scripts').mkdir(mode=0o700)
            for filename in ('restore_semantic_boot_guard.py','stage_semantic_boot_guard.py'):
                (stage/'source/scripts'/filename).write_bytes((repo/'scripts'/filename).read_bytes()); os.chmod(stage/'source/scripts'/filename,0o600)
            args=SimpleNamespace(mode='plan',source_commit='b'*40,lease_source_commit='a'*40,
                cold_root=cold,lease_package_root=lease,snapshot_root=stage,docker_path=shutil.which('docker'),
                nft_path=nft,python_path=shutil.which('python3'),guard_unit='ouf-stage-'+suffix,docker_unit=dependent+'.service',runtime_directory='obf-'+suffix)
            staging.operate(args); self.assertFalse((stage/'boot-stage-receipt.json').exists())
            args.mode='apply'; receipt=staging.operate(args)
            args.mode='verify'; self.assertEqual(staging.operate(args),receipt)
            artifact=stage/'guard.service'; original=artifact.read_bytes(); artifact.write_bytes(original+b'\n')
            with self.assertRaises(ValueError): staging.operate(args)
            artifact.write_bytes(original)
            # Install against an already running isolated dependent, never production Docker.
            dep.write_text('[Unit]\nDescription=Isolated install fixture\n[Service]\nType=simple\nExecStart=/usr/bin/sleep 180\n')
            run('systemctl','daemon-reload'); run('systemctl','start',dependent+'.service')
            install_root=root/'install'; install_root.mkdir(mode=0o700)
            install_args=SimpleNamespace(mode='plan',stage_root=stage,snapshot_root=install_root,
                stage_commit='b'*40,unit_root=unit.parent,systemctl_path=shutil.which('systemctl'),
                analyze_path=shutil.which('systemd-analyze'))
            planned=installation.operate(install_args)
            self.assertFalse((install_root/'install-journal.json').exists())
            install_args.mode='apply'; installed=installation.operate(install_args)
            self.assertEqual(installed['baseline']['MainPID'],planned['baseline']['MainPID'])
            install_args.mode='verify'; installation.operate(install_args)
            installed_drop=dropdir/('90-'+args.guard_unit+'.conf')
            saved_drop=installed_drop.read_bytes(); installed_drop.write_bytes(saved_drop+b'\n')
            with self.assertRaises(ValueError): installation.operate(install_args)
            install_args.mode='rollback'
            with self.assertRaises(ValueError): installation.operate(install_args)
            self.assertEqual(installed_drop.read_bytes(),saved_drop+b'\n')
            installed_drop.write_bytes(saved_drop)
            install_args.mode='rollback'; rolled=installation.operate(install_args)
            self.assertEqual(rolled['state'],'rolled-back')
            self.assertEqual(installation.show(install_args.systemctl_path,dependent+'.service')['MainPID'],planned['baseline']['MainPID'])
            self.assertFalse(installed_drop.exists())
            self.assertFalse((unit.parent/(args.guard_unit+'.service')).exists())
            # Failure after file creation but before daemon-reload must remain recoverable.
            interrupted=root/'interrupted'; interrupted.mkdir(mode=0o700)
            retry_args=SimpleNamespace(**{**install_args.__dict__,'mode':'apply','snapshot_root':interrupted,
                                         'analyze_path':'/usr/bin/false'})
            with self.assertRaises(ValueError): installation.operate(retry_args)
            self.assertEqual(json.loads((interrupted/'install-journal.json').read_bytes())['state'],'started')
            retry_args.mode='rollback'; installation.operate(retry_args)
            self.assertFalse(installed_drop.exists())
            self.assertEqual(installation.show(install_args.systemctl_path,dependent+'.service')['MainPID'],planned['baseline']['MainPID'])
            run('systemctl','stop',dependent+'.service')
            print('SEMANTIC_BOOT_INSTALL_CI=PASS REAL_SYSTEMD=true ACTIVE_DEPENDENT_PID_PRESERVED=true'
                  ' PLAN_READ_ONLY=true INSTALLED_GRAPH_VERIFIED=true FILE_TAMPERING_DENIED=true'
                  ' ROLLBACK_OWN_FILES_ONLY=true INTERRUPTED_INSTALL_RECOVERY=true REAL_DOCKER_RESTART_NOT_PERFORMED=true PROVIDER_CALLS=0')
            before=guard.footprint(json.loads(run(nft,'-j','list','ruleset')))
            erase(); self.assertTrue(guard.restore(value))
            self.assertEqual(guard.footprint(json.loads(run(nft,'-j','list','ruleset'))),before)
            config=root/'config.json'; raw=json.dumps(value).encode(); config.write_bytes(raw); os.chmod(config,0o600)
            script=root/'restore.py'; script.write_bytes(Path(guard.__file__).read_bytes()); os.chmod(script,0o600)
            compiled,drop=service(dict(guardUnit=name,dockerUnit=dependent+'.service',runtimeDirectory=name,
                pythonPath=shutil.which('python3'),scriptPath=str(script),root=str(root)),config,hashlib.sha256(raw).hexdigest())
            unit.write_text(compiled); os.chmod(unit,0o600)
            dep.write_text('[Unit]\nDescription=Isolated stand-in for Docker startup\n[Service]\nType=simple\nExecStart=/usr/bin/sleep 180\n')
            (dropdir/'10-guard.conf').write_text(drop)
            run('systemd-analyze','verify',str(unit),str(dep)); run('systemctl','daemon-reload')
            erase()  # Simulate lost kernel tables; do not reboot the CI runner.
            run('systemctl','start',dependent+'.service')
            self.assertEqual(guard.footprint(guard.observed(nft,table)),value['expectedFootprint'])
            run('systemctl','stop',dependent+'.service')
            # Guard remains active, but the dependent's ExecStartPre rechecks it.
            run(nft,'add','rule','inet',table,'governed_flows','counter','accept')
            failed=subprocess.run(['systemctl','start',dependent+'.service'],capture_output=True,timeout=30)
            self.assertNotEqual(failed.returncode,0)
            active=subprocess.run(['systemctl','is-active','--quiet',dependent+'.service'],capture_output=True,timeout=5)
            self.assertNotEqual(active.returncode,0)
            with self.assertRaises(ValueError): guard.restore(value)
            erase(); run(nft,'create','table','inet',table)
            with self.assertRaises(ValueError): guard.restore(value)
            print('SEMANTIC_BOOT_SYSTEMD_CI=PASS REAL_SYSTEMD_NFT=true LOST_TABLES_RECONSTRUCTED=true'
                  ' BEFORE_ISOLATED_DEPENDENT_START=true RECHECK_EVERY_DEPENDENT_START=true'
                  ' PRIVATE_STAGE_AND_TAMPERING_VERIFIED=true FOREIGN_OR_PARTIAL_OWNERSHIP_DENIED=true SHARED_RULES_PRESERVED=true'
                  ' REAL_REBOOT_NOT_PROVEN=true REAL_DOCKER_RESTART_NOT_PERFORMED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            for selected in (dependent,name,'ouf-stage-'+suffix):
                subprocess.run(['systemctl','stop',selected+'.service'],capture_output=True,timeout=30)
            for f in (unit,dep,unit.parent/('ouf-stage-'+suffix+'.service')):
                if f.exists(): f.unlink()
            shutil.rmtree(dropdir); run('systemctl','daemon-reload')
            for net in reversed(nets): run('docker','network','rm',net)
            if created: erase()
            shutil.rmtree(root)
            print('SEMANTIC_BOOT_SYSTEMD_CLEANUP=PASS OWNED_UNITS_TABLES_AND_FILES_REMOVED=true')
