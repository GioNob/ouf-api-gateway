"""Private-file regressions and opt-in real systemd/nft transition fixtures."""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from scripts import restore_semantic_runtime_boot_guard as g
from scripts import stage_semantic_runtime_transition as staging
from scripts import transition_semantic_runtime_guard as installation
from tools.materialize_southbound_kernel import materialize


@unittest.skipUnless(os.geteuid()==0 or os.environ.get('OUF_RUNTIME_TRANSITION_FULL_OWNER_TEST')=='1',
                     'root private-file fixtures have a dedicated CI job')
class RuntimeGuardTest(unittest.TestCase):
    def setUp(self):
        if os.environ.get('OUF_RUNTIME_TRANSITION_FULL_OWNER_TEST')=='1': self.assertEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_RUNTIME_TRANSITION_TEST_PARENT',str(Path.cwd())))
        self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.compiler=self.root/'compiler.py'
        self.compiler.write_bytes((Path(__file__).resolve().parents[1]/'tools/materialize_southbound_kernel.py').read_bytes())
        self.compiler.chmod(0o600)
        self.kernel={'tableName':'owned','guardedInterfaces':['inside','outside'],'existingInterfaces':['shared'],
            'staticFlows':[],'providerFlows':[{'endpointRef':'provider','endpoint':'https://provider.invalid/sparql',
                'source':'172.24.0.2','addresses':[],'leaseSeconds':30,'resolutionEvidenceRef':'fresh',
                'allowedPrivateAddresses':[]}]}
        self.tables={f:{'nftables':[{'metainfo':{'version':'fixture'}},
            {'table':{'family':f,'name':'owned','handle':1}},
            {'set':{'family':f,'table':'owned','name':'provider_0','type':'ipv4_addr','flags':['timeout'],'handle':2}}]}
            for f in ('inet','bridge')}
        self.conf={'schema':'ouf.semantic-runtime-boot-guard.v1','nftPath':'/bin/nft','kernel':self.kernel,
            'compilerFile':str(self.compiler),'compilerHash':g.digest(self.compiler.read_bytes()),
            'expectedFootprint':g.footprint(self.tables),'journalFile':str(self.root/'journal.json'),
            'transactionId':'a'*64,'lockFile':str(self.root/'guard.lock')}
        self.journal={'schema':'ouf.semantic-runtime-transition.v1','transactionId':'a'*64,'configurationHash':'b'*64,
            'state':'RUNTIME_EMPTY','startAuthorized':False,'leaseStructureHash':g.digest(g.encoded(g.stable(self.tables,True)))}
        self.save_journal(); self.present={'inet','bridge'}; self.commands=[]
        self.shared={'nftables':[{'table':{'family':'inet','name':'shared','handle':30}},
            {'set':{'family':'inet','table':'shared','name':'live','elem':[{'elem':{'val':'198.51.100.8','expires':9000}}]}}]}
        def run(command,raw=None):
            self.commands.append((command,raw))
            if command[1:]==['-j','list','tables']:
                return json.dumps({'nftables':[{'table':{'family':f,'name':'owned'}} for f in self.present]})
            if command[1:]==['-j','list','ruleset']: return json.dumps(self.shared)
            if command[1:4]==['-j','list','table']: return json.dumps(self.tables[command[4]])
            if command[1:]==['-f','-']: self.present={'inet','bridge'}; return ''
            raise AssertionError('unexpected command')
        self.addCleanup(patch.stopall); patch.object(g,'run',side_effect=run).start()

    def save_journal(self):
        p=Path(self.conf['journalFile']); p.write_bytes(g.encoded(self.journal)); p.chmod(0o600)

    def test_incomplete_journal_blocks_before_nft_operation(self):
        for state in ('PREPARING','GATE_FILES_WRITTEN','GATE_LOADED','RULES_APPLIED','ROLLBACK_BLOCKED','ROLLED_BACK'):
            self.journal['state']=state; self.save_journal()
            with self.assertRaises(ValueError): g.restore(self.conf,'b'*64)
        self.assertEqual(self.commands,[])

    def test_exact_empty_runtime_is_read_only_and_handle_binding_is_distinct(self):
        result=g.restore(self.conf,'b'*64)
        self.assertFalse(result['restored']); self.assertFalse(result['leaseStructureReconciliationRequired'])
        self.tables['inet']['nftables'][1]['table']['handle']=70
        result=g.restore(self.conf,'b'*64)
        self.assertTrue(result['leaseStructureReconciliationRequired'])
        self.assertFalse(any(c[0][1:]==['-f','-'] for c in self.commands))

    def test_absent_pair_restored_atomically_partial_pair_denied(self):
        self.present=set(); result=g.restore(self.conf,'b'*64)
        self.assertTrue(result['restored']); self.assertTrue(result['leaseStructureReconciliationRequired'])
        writes=[raw for cmd,raw in self.commands if cmd[1:]==['-f','-']]
        self.assertEqual(len(writes),1); self.assertIn('create table inet owned',writes[0]); self.assertIn('create table bridge owned',writes[0])
        self.assertNotIn('elements',writes[0]); self.commands.clear(); self.present={'inet'}
        with self.assertRaises(ValueError): g.restore(self.conf,'b'*64)
        self.assertFalse(any(c[0][1:]==['-f','-'] for c in self.commands))

    def test_foreign_rules_and_active_leases_are_not_adopted_or_flushed(self):
        extra={'rule':{'family':'inet','table':'owned','expr':[{'accept':None}]}}
        self.tables['inet']['nftables'].append(extra)
        with self.assertRaises(ValueError): g.restore(self.conf,'b'*64)
        self.tables['inet']['nftables'].pop()
        self.tables['bridge']['nftables'][2]['set']['elem']=[{'elem':{'val':'203.0.113.8','expires':30000}}]
        with self.assertRaises(ValueError): g.restore(self.conf,'b'*64)
        self.assertFalse(any(c[0][1:]==['-f','-'] for c in self.commands))

    def test_shared_elements_preserved_and_host_native_mode_refused(self):
        first=g.shared(self.shared,'owned'); self.shared['nftables'][1]['set']['elem'][0]['elem']['val']='198.51.100.9'
        self.assertNotEqual(first,g.shared(self.shared,'owned'))
        with patch.object(g.os,'stat',return_value=SimpleNamespace(st_ino=7)),self.assertRaises(ValueError):
            g.native_template({**self.conf,'parentNetworkNamespace':7})
        self.assertEqual(self.commands,[])

    def test_compiler_tamper_config_hash_and_journal_binding_denied(self):
        self.journal['configurationHash']='c'*64; self.save_journal()
        with self.assertRaises(ValueError): g.restore(self.conf,'b'*64)
        self.compiler.write_bytes(b'raise Exception("do-not-print")')
        with self.assertRaises(ValueError): g.validate(self.conf)

    def test_common_lock_contention_and_foreign_file_replace_refused(self):
        path=Path(self.conf['lockFile']); fd=g.lock(path,create=True)
        try:
            with self.assertRaises(BlockingIOError): g.lock(path)
        finally: os.close(fd)
        target=self.root/'unit'; target.write_bytes(b'foreign'); target.chmod(0o600)
        with self.assertRaises(ValueError): installation.replace(g,target,b'new',(b'old',b'new'))
        self.assertEqual(target.read_bytes(),b'foreign')

    def test_unit_injection_and_command_fingerprint_rules(self):
        profile={'guardUnit':'guard','runtimeDirectory':'guard','dockerUnit':'docker.service',
                 'pythonPath':'/usr/bin/python3','scriptPath':'/etc/guard.py','root':'/etc/stage'}
        unit,drop=staging.service(profile,Path('/etc/config.json'),'a'*64,Path('/run/guard/guard.lock'))
        self.assertIn(b'RuntimeDirectoryPreserve=yes',unit); self.assertIn(b'ExecStartPre=',drop)
        profile['dockerUnit']='docker.service\nExecStart=/bin/sh'
        with self.assertRaises(ValueError): staging.service(profile,Path('/etc/config.json'),'a'*64,Path('/run/guard/guard.lock'))
        a='{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 180 ; ignore_errors=no ; start_time=old ; }'
        self.assertEqual(installation.command_definition(a),installation.command_definition(a.replace('old','new')))
        self.assertNotEqual(installation.command_definition(a),installation.command_definition(a.replace('180','90')))


@unittest.skipUnless(os.environ.get('OUF_RUNTIME_TRANSITION_NATIVE_TEST')=='1','real systemd/nft/Docker stopped fixture opt-in')
class NativeRuntimeTransitionTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0); self.assertEqual(Path('/proc/1/comm').read_text().strip(),'systemd')
        self.repo=Path(__file__).resolve().parents[1]; self.suffix=uuid.uuid4().hex[:8]
        self.name='ouf-runtime-'+self.suffix; self.dependent=self.name+'-dependent.service'
        self.table='ouf_rt_'+self.suffix; self.units=Path('/run/systemd/system')
        self.root=Path(tempfile.mkdtemp(prefix=self.name+'-',dir='/etc')); self.root.chmod(0o700)
        self.nets=[]; self.containers=[]; self.guardunit=self.name+'.service'
        self.addCleanup(self.cleanup)
        self.nft=shutil.which('nft'); self.docker=shutil.which('docker'); self.systemctl=shutil.which('systemctl')
        self.python=shutil.which('python3'); self.unshare=shutil.which('unshare'); self.analyze=shutil.which('systemd-analyze')
        self.image=os.environ['OUF_RUNTIME_TRANSITION_TEST_IMAGE']
        for role,internal in (('internal',True),('egress',False),('backend',True)):
            name=self.name+'-'+role; bridge='ort'+role[:1]+self.suffix
            # Select a Docker-managed free subnet, then use an explicit fixture
            # subnet. This recreates ONLY an empty disposable fixture network.
            self.command(self.docker,'network','create',name); self.nets.append(name)
            initial=json.loads(self.command(self.docker,'network','inspect',name))[0]
            subnet=initial['IPAM']['Config'][0]['Subnet']
            self.command(self.docker,'network','rm',name); self.nets.remove(name)
            cmd=[self.docker,'network','create','--subnet',subnet,'--opt','com.docker.network.bridge.name='+bridge]
            if internal: cmd.append('--internal')
            self.command(*cmd,name); self.nets.append(name)
        self.networks={role:json.loads(self.command(self.docker,'network','inspect',self.name+'-'+role))[0]
                       for role in ('internal','egress','backend')}
        from scripts import stage_semantic_lease_package as package
        from scripts import stage_semantic_boot_guard as boot_stage
        from scripts import install_semantic_boot_guard as boot_install
        from scripts import restore_semantic_boot_guard as old_guard
        cold=self.root/'cold'; cold.mkdir(mode=0o700)
        self.old_kernel={'tableName':self.table,'guardedInterfaces':[self.networks[r]['Options']['com.docker.network.bridge.name']
            for r in ('internal','egress')],'existingInterfaces':[],'staticFlows':[],'providerFlows':[]}
        self.deny_rules='create table inet '+self.table+'\ncreate table bridge '+self.table+'\n'+materialize(self.old_kernel)['nftRules']
        self.command(self.nft,'-f','-',raw=self.deny_rules)
        current=old_guard.observed(self.nft,self.table)
        binding={'table_name':self.table,**{r+'_network':self.networks[r]['Name'] for r in ('internal','egress')},
                 **{r+'_bridge':self.networks[r]['Options']['com.docker.network.bridge.name'] for r in ('internal','egress')}}
        cold_value={'schema':'ouf.semantic-provider-cold-networks.v1','notReleaseAcceptance':True,'binding':binding,
                    'networkIds':{r:self.networks[r]['Id'] for r in ('internal','egress')},
                    'guardHash':g.digest(g.encoded(boot_stage.legacy(current)))}
        self.save(cold/'network-receipt.json',cold_value); self.save(cold/'deny-only.nft',self.deny_rules.encode())
        lease=self.root/'lease'; self.copy_sources(lease,package.FILES)
        package.operate(argparse.Namespace(mode='apply',package_root=lease,source_commit='a'*40))
        boot=self.root/'boot'; self.copy_sources(boot,['scripts/restore_semantic_boot_guard.py','scripts/stage_semantic_boot_guard.py'])
        boot_stage.operate(argparse.Namespace(mode='apply',cold_root=cold,lease_package_root=lease,snapshot_root=boot,
            source_commit='b'*40,lease_source_commit='a'*40,docker_path=self.docker,nft_path=self.nft,python_path=self.python,
            guard_unit=self.name,docker_unit=self.dependent,runtime_directory=self.name))
        depfile=self.units/self.dependent
        depfile.write_text('[Unit]\nDescription=Isolated runtime transition dependent\n[Service]\nType=simple\nExecStart=/usr/bin/sleep 600\n')
        self.command(self.systemctl,'daemon-reload'); self.command(self.systemctl,'start',self.dependent)
        install=self.root/'boot-install'; install.mkdir(mode=0o700)
        boot_install.operate(argparse.Namespace(mode='apply',stage_root=boot,snapshot_root=install,stage_commit='b'*40,
            unit_root=self.units,systemctl_path=self.systemctl,analyze_path=self.analyze))
        self.original_pid=boot_install.show(self.systemctl,self.dependent)['MainPID']
        manifest_root=self.root/'manifest'; manifest_root.mkdir(mode=0o700)
        creation_root=self.root/'creation'; creation_root.mkdir(mode=0o700)
        runtime=self.root/'runtime'; runtime.mkdir(mode=0o700)
        names=[self.name+'-south',self.name+'-adapter']; transaction='fixture-'+self.suffix
        import ipaddress
        def net_spec(role,index):
            net=self.networks[role]; subnet=ipaddress.ip_network(net['IPAM']['Config'][0]['Subnet'])
            return {'id':net['Id'],'name':net['Name'],'ipv4':str(subnet.network_address+index)}
        image=json.loads(self.command(self.docker,'image','inspect',self.image))[0]['Id']
        specs=[{'name':names[0],'image':image,'networks':[net_spec('backend',2),net_spec('internal',2),net_spec('egress',2)]},
               {'name':names[1],'image':image,'networks':[net_spec('internal',3),net_spec('egress',3)]}]
        manifest={'schema':'ouf.semantic-provider-stopped-manifest.v1','containers':specs,'startAuthorized':False,
            'networkReceiptHash':g.digest((cold/'network-receipt.json').read_bytes()),'guardHash':cold_value['guardHash']}
        mh=self.save(manifest_root/'stopped-manifest.json',manifest); ids={}
        for spec in specs:
            first=spec['networks'][0]
            cid=self.command(self.docker,'create','--name',spec['name'],'--network',first['name'],'--ip',first['ipv4'],
                '--restart','no','--label','ouf.semantic.candidate.transaction='+transaction,
                '--label','ouf.semantic.candidate.manifest='+mh,'--entrypoint','/bin/false',self.image).strip()
            self.containers.append(spec['name']); ids[spec['name']]=cid
            for net in spec['networks'][1:]: self.command(self.docker,'network','connect','--ip',net['ipv4'],net['name'],cid)
        jh=self.save(creation_root/'creation-journal.json',{'schema':'ouf.semantic-provider-stopped-create.v1',
            'sourceCommit':'c'*40,'state':'CREATED_STOPPED','manifestHash':mh,'candidateIds':ids,'transaction':transaction,'startAuthorized':False})
        binding={'tlsIdentities':{'southboundHostname':names[0],'adapterHostname':names[1]},
            'dns':{'networkIPVersion':4,'resolverPort':53,'resolvers':['192.0.2.53']},
            'adapter':{'listenPort':9443,'provider':{'endpoint':'https://provider.fixture.invalid:443/sparql','allowed_cidrs':[]}}}
        bh=self.save(runtime/'binding.json',binding); ph=self.save(runtime/'runtime-plan.json',{'installed':False})
        self.save(runtime/'stage-receipt.json',{'schema':'ouf.semantic-provider-runtime-stage.v1','bindingHash':bh,
            'planHash':ph,'notReleaseAcceptance':True,'providerCalls':0})
        intent_source=self.root/'intent-source'
        self.copy_sources(intent_source,['scripts/prepare_semantic_provider_transition_intent.py',
                                         'scripts/inventory_semantic_provider_guard_custody.py'])
        source=intent_source/'source/scripts/prepare_semantic_provider_transition_intent.py'
        intent_module=installation.module(source,g.digest(source.read_bytes()))
        self.intent=intent_source/'prepared'
        self.intent_source_hash=g.digest(source.read_bytes())
        intent_module.operate(argparse.Namespace(mode='apply',manifest_root=manifest_root,creation_root=creation_root,
            network_root=cold,boot_stage_root=boot,boot_install_root=install,runtime_root=runtime,lease_package_root=lease,
            snapshot_root=self.intent,boot_lock_file=Path('/run')/self.name/'guard.lock',source_commit='d'*40,
            lease_source_commit='a'*40,creation_source_commit='c'*40,
            custody_source_sha256=g.digest((intent_source/'source/scripts/inventory_semantic_provider_guard_custody.py').read_bytes()),
            expected_manifest_hash=mh,expected_creation_journal_hash=jh,
            expected_boot_install_journal_hash=g.digest((install/'install-journal.json').read_bytes()),
            docker_path=self.docker,nft_path=self.nft,systemctl_path=self.systemctl))
        source_root=self.root/'runtime-source'
        self.copy_sources(source_root,['scripts/restore_semantic_runtime_boot_guard.py','scripts/stage_semantic_runtime_transition.py',
                                       'scripts/transition_semantic_runtime_guard.py'])
        self.stage_root=source_root/'prepared'
        self.stage_module=installation.module(source_root/'source/scripts/stage_semantic_runtime_transition.py',
            g.digest((source_root/'source/scripts/stage_semantic_runtime_transition.py').read_bytes()))
        self.stage_args=argparse.Namespace(mode='plan',snapshot_root=self.stage_root,intent_root=self.intent,
            source_commit='e'*40,intent_source_commit='d'*40,intent_source_sha256=self.intent_source_hash,
            runtime_guard_sha256=g.digest((source_root/'source/scripts/restore_semantic_runtime_boot_guard.py').read_bytes()),
            docker_path=self.docker,nft_path=self.nft,systemctl_path=self.systemctl,unshare_path=self.unshare,
            python_path=self.python,provider_endpoint_ref='fixture-provider',resolution_evidence_ref='fresh-dns',lease_seconds=30)
        self.stage_module.operate(self.stage_args); self.assertFalse(self.stage_root.exists())
        self.stage_args.mode='apply'; self.stage_module.operate(self.stage_args)
        self.stage_args.mode='verify'; self.stage_module.operate(self.stage_args)
        source=source_root/'source/scripts/transition_semantic_runtime_guard.py'
        self.installer=installation.module(source,g.digest(source.read_bytes()))
        self.install_args=argparse.Namespace(mode='plan',stage_root=self.stage_root,stage_source_commit='e'*40,analyze_path=self.analyze)

    def command(self,*args,raw=None):
        return subprocess.run(args,input=raw,text=True,capture_output=True,timeout=40,check=True).stdout

    def save(self,path,value):
        raw=value if isinstance(value,bytes) else g.encoded(value)
        path.write_bytes(raw); path.chmod(0o600); return g.digest(raw)

    def copy_sources(self,root,names):
        root.mkdir(mode=0o700)
        for name in names:
            target=root/'source'/name; target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            self.save(target,(self.repo/name).read_bytes())

    def cleanup(self):
        for unit in (self.dependent,self.guardunit): subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=30)
        for name in self.containers:
            row=json.loads(self.command('docker','inspect',name))[0]
            self.assertFalse(row['State']['Running']); self.assertTrue(row['State']['StartedAt'].startswith('0001-01-01T'))
            self.command('docker','rm',name)
        for name in reversed(self.nets): self.command('docker','network','rm',name)
        for item in json.loads(self.command('nft','-j','list','tables'))['nftables']:
            table=item.get('table')
            if table and table['name']==self.table and table['family'] in ('inet','bridge'):
                self.command('nft','delete','table',table['family'],self.table)
        for path in (self.units/self.dependent,self.units/self.guardunit):
            if path.exists(): path.unlink()
        shutil.rmtree(self.units/(self.dependent+'.d'),ignore_errors=True)
        self.command('systemctl','daemon-reload'); shutil.rmtree(self.root)
        shutil.rmtree(Path('/run')/self.name,ignore_errors=True)

    def guard_command(self):
        r=g.read(self.stage_root/'runtime-stage-receipt.json'); c=g.read(self.stage_root/'runtime-configuration.json')
        return [self.python,'-B',r['profile']['scriptPath'],'--configuration',str(self.stage_root/'runtime-configuration.json'),
                '--configuration-sha256',r['configurationHash'],'--lock-file',c['lockFile']]

    def pid_unchanged(self):
        self.assertIn('MainPID='+self.original_pid,self.command(self.systemctl,'show',self.dependent,'--property=MainPID'))

    def test_native_apply_restore_reconciliation_foreign_partial_and_dependent_start(self):
        self.installer.operate(self.install_args); self.assertFalse((self.stage_root/'transition-journal.json').exists())
        self.install_args.mode='apply'; self.installer.operate(self.install_args)
        self.install_args.mode='verify'; self.installer.operate(self.install_args); self.pid_unchanged()
        self.assertIn('RESTORED=false',self.command(*self.guard_command()))
        for family in ('inet','bridge'): self.command(self.nft,'delete','table',family,self.table)
        output=self.command(*self.guard_command()); self.assertIn('RESTORED=true',output)
        self.assertIn('LEASE_RECONCILIATION_REQUIRED=true',output)
        with self.assertRaises(ValueError): self.installer.operate(self.install_args)
        self.install_args.mode='reconcile'; self.installer.operate(self.install_args)
        self.install_args.mode='verify'; self.installer.operate(self.install_args); self.pid_unchanged()
        # The production Docker service is never stopped/restarted. Exercise
        # a different, isolated dependent after installer PID checks are done.
        self.command(self.systemctl,'stop',self.dependent)
        for family in ('inet','bridge'): self.command(self.nft,'delete','table',family,self.table)
        self.command(self.systemctl,'start',self.dependent)
        self.command(self.systemctl,'stop',self.dependent)
        self.command(self.nft,'add','rule','inet',self.table,'governed_flows','counter','accept')
        denied=subprocess.run([self.systemctl,'start',self.dependent],capture_output=True,timeout=30)
        self.assertNotEqual(denied.returncode,0)
        for family in ('inet','bridge'): self.command(self.nft,'delete','table',family,self.table)
        self.command(self.nft,'create','table','inet',self.table)
        denied=subprocess.run(self.guard_command(),capture_output=True,timeout=30); self.assertNotEqual(denied.returncode,0)
        print('RUNTIME_TRANSITION_NATIVE=PASS APPLY_VERIFY=true RESTORE_EMPTY=true HANDLE_RECONCILIATION=true'
              ' FOREIGN_PARTIAL_DENIED=true ISOLATED_PRESTART_PROVEN=true PRODUCTION_DOCKER_RESTARTED=false PROVIDER_CALLS=0')

    def test_native_interrupted_reload_and_rule_apply_reconcile_then_rollback(self):
        prepared=self.installer.stage(self.install_args); runtime_guard=prepared[0]; real_run=runtime_guard.run
        calls=0
        def fail_reload(command,raw=None):
            nonlocal calls
            if command==[self.systemctl,'daemon-reload']:
                calls+=1
                if calls==1: raise ValueError('simulated reload interruption')
            return real_run(command,raw)
        self.install_args.mode='apply'
        with patch.object(self.installer,'stage',return_value=prepared),patch.object(runtime_guard,'run',side_effect=fail_reload):
            with self.assertRaises(ValueError): self.installer.operate(self.install_args)
        self.assertEqual(g.read(self.stage_root/'transition-journal.json')['state'],'GATE_FILES_WRITTEN')
        self.pid_unchanged()
        self.assertNotEqual(subprocess.run(self.guard_command(),capture_output=True,timeout=30).returncode,0)
        real_journal=self.installer.journal
        def fail_after_rules(guard,path,record):
            if record['state']=='RULES_APPLIED': raise ValueError('simulated journal interruption')
            return real_journal(guard,path,record)
        self.install_args.mode='reconcile'
        with patch.object(self.installer,'journal',side_effect=fail_after_rules):
            with self.assertRaises(ValueError): self.installer.operate(self.install_args)
        self.assertEqual(g.read(self.stage_root/'transition-journal.json')['state'],'GATE_LOADED')
        self.assertNotEqual(subprocess.run(self.guard_command(),capture_output=True,timeout=30).returncode,0)
        self.installer.operate(self.install_args); self.pid_unchanged()
        self.install_args.mode='verify'; self.installer.operate(self.install_args)
        self.install_args.mode='rollback'; record=self.installer.operate(self.install_args); self.pid_unchanged()
        self.assertTrue(record['legacyCustodyReconciliationRequired']); self.assertEqual(record['state'],'ROLLED_BACK')
        print('RUNTIME_TRANSITION_RECOVERY_NATIVE=PASS LOADED_GATE_DENIES_PARTIAL=true'
              ' POST_RULE_CRASH_RECOVERED=true OWNED_ROLLBACK=true ORIGINAL_PID_PRESERVED=true PROVIDER_CALLS=0')


if __name__=='__main__': unittest.main()
