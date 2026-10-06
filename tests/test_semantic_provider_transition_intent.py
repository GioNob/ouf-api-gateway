"""Real private-file/lock tests with readback fixtures, not VPS acceptance."""
import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_semantic_provider_transition_intent as m
from scripts import inventory_semantic_provider_guard_custody as g


@unittest.skipUnless(os.geteuid()==0 or os.environ.get('OUF_TRANSITION_FULL_OWNER_TEST')=='1',
                     'real root private-file/lock fixtures run in the dedicated CI job')
class IntentTest(unittest.TestCase):
    def setUp(self):
        if os.environ.get('OUF_TRANSITION_FULL_OWNER_TEST')=='1': self.assertEqual(os.geteuid(),0)
        # /tmp is intentionally forbidden by production ancestor checks.
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSITION_TEST_PARENT', str(Path.cwd())))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        os.chmod(self.root, 0o700)
        staged_source=self.root/'prepare.py'
        staged_source.write_bytes(Path(m.__file__).read_bytes()); staged_source.chmod(0o600)
        self.addCleanup(patch.stopall)
        patch.object(m,'__file__',str(staged_source)).start()
        roots = {}
        for name in ('manifest','creation','network','boot_stage','boot_install','runtime','lease_package'):
            roots[name] = self.root/name; roots[name].mkdir(mode=0o700)
        self.args = argparse.Namespace(mode='plan', **{k+'_root':v for k,v in roots.items()},
            snapshot_root=self.root/'prepared', boot_lock_file=Path('/run/transition-fixture/guard.lock'),
            source_commit='a'*40, lease_source_commit='b'*40, creation_source_commit='c'*40,
            custody_source_sha256='d'*64, expected_manifest_hash='e'*64,
            expected_creation_journal_hash='f'*64, expected_boot_install_journal_hash='1'*64,
            docker_path='/bin/docker', nft_path='/bin/nft', systemctl_path='/bin/systemctl')
        self.tables = {f:{'nftables':[{'metainfo':{'version':'fixture'}},
            {'table':{'name':'owned','family':f,'handle':7}}]} for f in ('inet','bridge')}
        self.shared = {'nftables':[{'metainfo':{'version':'fixture'}},
            {'table':{'family':'inet','name':'shared','handle':50}},
            {'rule':{'family':'inet','table':'shared','handle':51,'expr':[{'counter':{'packets':3,'bytes':7}}]}},
            {'table':{'family':'inet','name':'owned','handle':7}},
            {'rule':{'family':'inet','table':'owned','expr':[{'drop':None}]}}]}
        self.report = {'schema':'ouf.semantic-provider-guard-custody.v1',
            'manifestHash':'e'*64,'creationJournalHash':'f'*64,'bootInstallJournalHash':'1'*64,
            'candidateCount':2,'neverStarted':True,'bootProfile':'DENY_ONLY',
            'bootTransitionRequiredBeforeRuntimeRules':True,'startAuthorized':False,'kernelLeaseInstalled':False,
            'readOnly':True,'providerCalls':0,'notReleaseAcceptance':True,'noSecretsPrinted':True}
        self.save(roots['manifest']/'stopped-manifest.json', {'guardHash':m.digest(m.encoded(g.canonical(self.tables)))})
        self.save(roots['network']/'network-receipt.json', {'binding':{'internal_bridge':'br-inside','egress_bridge':'br-outside'}})
        conf={'tableName':'owned','expectedFootprint':m.digest(m.encoded(g.canonical(self.tables,True)))}
        self.save(roots['boot_stage']/'boot-configuration.json', conf)
        binding_hash = self.save(roots['runtime']/'binding.json', {'private':'do-not-print'})
        plan_hash = self.save(roots['runtime']/'runtime-plan.json', {'installed':False})
        self.save(roots['runtime']/'stage-receipt.json', {'schema':'ouf.semantic-provider-runtime-stage.v1',
            'bindingHash':binding_hash,'planHash':plan_hash,'notReleaseAcceptance':True,'providerCalls':0})
        hashes={}
        for name in m.LEASE_FILES:
            target=roots['lease_package']/'source'/name
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            hashes[name]=self.save(target, {'source':name})
        ph=self.save(roots['lease_package']/'source-package-receipt.json',
            {'schema':'ouf.semantic-lease-source-package.v1','sourceCommit':'b'*40,'sourceHashes':hashes,
             'daemonStarted':False,'systemdUnitInstalled':False,'rulesChanged':False,
             'providerCalls':0,'notReleaseAcceptance':True})
        self.save(roots['boot_stage']/'boot-stage-receipt.json',
            {'profile':{'runtimeDirectory':'transition-fixture'},'leasePackageReceiptHash':ph})
        self.actual_lock=self.root/'guard.lock'; self.actual_lock.touch(mode=0o600)
        real_lstat=Path.lstat
        def lstat(path): return real_lstat(self.actual_lock if path==self.args.boot_lock_file else path)
        self.addCleanup(patch.stopall)
        patch.object(Path,'lstat',lstat).start()
        self.real_lock=m.lock
        patch.object(m,'lock',side_effect=lambda path:self.real_lock(self.actual_lock)).start()
        self.commands=[]
        test=self
        class Custody:
            canonical=staticmethod(g.canonical)
            def operate(self,args): return copy.deepcopy(test.report)
            def run(self,command):
                test.commands.append(command)
                if command==['/bin/nft','-j','list','ruleset']: return json.dumps(test.shared)
                if command[:4]==['/bin/nft','-j','list','table'] and command[-1]=='owned':
                    return json.dumps(test.tables[command[4]])
                raise AssertionError('not a permitted read command')
        self.custody=Custody()

    def save(self,path,value):
        raw=m.encoded(value); path.write_bytes(raw); path.chmod(0o600); return m.digest(raw)

    def test_plan_apply_verify_private_and_no_activation(self):
        planned=m.operate(self.args,self.custody)
        self.assertFalse(self.args.snapshot_root.exists())
        self.args.mode='apply'; self.assertEqual(planned,m.operate(self.args,self.custody))
        self.args.mode='verify'; self.assertEqual(planned,m.operate(self.args,self.custody))
        self.assertEqual(self.args.snapshot_root.stat().st_mode&0o777,0o700)
        for p in self.args.snapshot_root.iterdir(): self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertFalse(planned['runtimeRulesApplied']); self.assertFalse(planned['startAuthorized'])
        self.assertFalse(planned['globalAtomicSnapshotProven'])
        self.assertNotIn('do-not-print',m.encoded(planned).decode())
        self.assertTrue(all(c[1:3]==['-j','list'] for c in self.commands))
        saved=json.loads((self.args.snapshot_root/'shared-before.json').read_bytes())
        self.assertNotIn('owned',json.dumps(saved)); self.assertIn('shared',json.dumps(saved))

    def test_custody_operator_hash_mismatch_blocks_before_snapshot(self):
        for key in ('manifestHash','creationJournalHash','bootInstallJournalHash'):
            old=self.report[key]; self.report[key]='0'*64
            with self.assertRaises(ValueError): m.operate(self.args,self.custody)
            self.report[key]=old
        self.assertFalse(self.args.snapshot_root.exists())

    def test_runtime_or_frozen_lease_drift_blocks(self):
        for target in (self.args.runtime_root/'binding.json',
                       self.args.lease_package_root/'source/scripts/run_semantic_provider_lease_owner.py'):
            original=target.read_bytes(); target.write_bytes(b'changed')
            with self.assertRaises(ValueError): m.operate(self.args,self.custody)
            target.write_bytes(original)
        self.assertFalse(self.args.snapshot_root.exists())

    def test_changed_guard_and_shared_structure_denied(self):
        self.tables['inet']['nftables'][1]['table']['handle']=9
        with self.assertRaises(ValueError): m.operate(self.args,self.custody)
        self.tables['inet']['nftables'][1]['table']['handle']=7
        original=self.custody.run; count=0
        def change(command):
            nonlocal count
            if command[-1]=='ruleset':
                count+=1
                if count==2: self.shared['nftables'][1]['table']['name']='other'
            return original(command)
        self.custody.run=change
        with self.assertRaises(ValueError): m.operate(self.args,self.custody)
        self.assertFalse(self.args.snapshot_root.exists())

    def test_foreign_existing_snapshot_and_saved_tampering_denied(self):
        self.args.mode='apply'; m.operate(self.args,self.custody)
        with self.assertRaises(ValueError): m.operate(self.args,self.custody)
        self.args.mode='verify'
        (self.args.snapshot_root/'transition-intent.json').write_bytes(b'foreign')
        with self.assertRaises(ValueError): m.operate(self.args,self.custody)
        self.assertEqual((self.args.snapshot_root/'transition-intent.json').read_bytes(),b'foreign')

    def test_exact_existing_boot_lock_and_contention(self):
        fd,_=self.real_lock(self.actual_lock)
        try:
            with self.assertRaises(BlockingIOError): m.operate(self.args,self.custody)
        finally: os.close(fd)
        with self.assertRaises(FileNotFoundError): self.real_lock(self.root/'absent.lock')
        symlink=self.root/'link.lock'; symlink.symlink_to(self.actual_lock)
        with self.assertRaises(OSError): self.real_lock(symlink)
        self.args.boot_lock_file=Path('/run/different/guard.lock')
        with self.assertRaises(ValueError): m.operate(self.args,self.custody)

    def test_partial_file_write_retained_and_cannot_reapply(self):
        self.args.mode='apply'; original=m.write; count=0
        def fail(path,raw):
            nonlocal count
            count+=1
            if count==2: raise OSError('interrupted')
            original(path,raw)
        with patch.object(m,'write',side_effect=fail), self.assertRaises(OSError): m.operate(self.args,self.custody)
        self.assertTrue((self.args.snapshot_root/'transition-intent.json').exists())
        with self.assertRaises(ValueError): m.operate(self.args,self.custody)
        self.args.mode='verify'
        with self.assertRaises(FileNotFoundError): m.operate(self.args,self.custody)

    def test_untrusted_dependency_is_not_imported_and_errors_are_redacted(self):
        self.args.custody_source_sha256='0'*64
        with patch.object(m,'private',return_value=b'raise Exception("secret-value")'), self.assertRaises(ValueError):
            m.load_custody(self.args)
        output=io.StringIO()
        with patch.object(m,'operate',side_effect=RuntimeError('secret-value')), contextlib.redirect_stdout(output):
            argv=[]
            for k,v in vars(self.args).items(): argv.extend(['--'+k.replace('_','-'),str(v)])
            self.assertEqual(m.main(argv),1)
        self.assertNotIn('secret-value',output.getvalue()); self.assertIn('BLOCKED',output.getvalue())


if __name__=='__main__': unittest.main()
