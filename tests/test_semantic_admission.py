import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from tools.semantic_provider_admission import authority,isolated_template,live_profile,mirrors,application_hash
from tools.semantic_provider_preexec import PreexecDenied,digest
from scripts.semantic_provider_admission_preparer import signature
from tests import test_semantic_preexec as fixture
profile = fixture.profile


class AdmissionTest(unittest.TestCase):
    def setUp(self):
        self.scope = {k:'a'*64 for k in ('containerId','transactionId','applicationHash','transportHash','creationAcceptanceHash')}
        self.scope.update(issuerRef='deployment-issuer',installationRef='installation',entityRef='entity',approvalRef='approval')
        self.receipt = {'schema':'ouf.semantic-deployment-admission-approval.v1',**self.scope,'issuedAt':100,'expiresAt':200,
            'state':'ACTIVE','infrastructureAuthorized':True,'applicationStartAuthorized':True}
    def encoded(self): return json.dumps(self.receipt).encode()
    def binding(self): return {'path':'/sealed/approval','sha256':hashlib.sha256(self.encoded()).hexdigest(),'issuedAt':100,'expiresAt':200}
    def test_read_metadata_ignores_atime_but_retains_content_and_owner_changes(self):
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        original = dict.fromkeys(fields,1); first = SimpleNamespace(**original,st_atime_ns=1)
        self.assertEqual(signature(first),signature(SimpleNamespace(**original,st_atime_ns=2)))
        for key in fields:
            self.assertNotEqual(signature(first),signature(SimpleNamespace(**{**original,key:2},st_atime_ns=1)))
    def test_authority_requires_exact_scope_freshness_and_sealed_content(self):
        b = self.binding(); authority(b,self.scope,lambda p:self.encoded(),lambda:150)
        for t in (99,200,201):
            with self.assertRaises(PreexecDenied): authority(b,self.scope,lambda p:self.encoded(),lambda:t)
        changed = dict(self.scope,entityRef='other')
        with self.assertRaises(PreexecDenied): authority(b,changed,lambda p:self.encoded(),lambda:150)
        with self.assertRaises(PreexecDenied): authority(b,{},lambda p:self.encoded(),lambda:150)
        self.receipt['state'] = 'REVOKED'
        with self.assertRaises(PreexecDenied): authority(b,self.scope,lambda p:self.encoded(),lambda:150)
        with self.assertRaises(PreexecDenied): authority(self.binding(),self.scope,lambda p:self.encoded(),lambda:150)
    def test_template_requires_isolation_and_exact_mirror_before_native_write(self):
        p = profile(); links = mirrors(p,[{'ifindex':8,'ifname':'peer'}]); run = Mock()
        with self.assertRaises(PreexecDenied): isolated_template(p,links,42,42,run)
        run.assert_not_called()
        with self.assertRaises(PreexecDenied): isolated_template(p,links+links,42,43,run)
        run.assert_not_called()
        p['policy']['attachments'][0]['ifindex'] = 1
        with self.assertRaises(PreexecDenied): mirrors(p,[{'ifindex':8,'ifname':'peer'}])
    def test_application_acceptance_covers_caps_env_root_mount_and_hooks(self):
        original = {'process':{'args':['app'],'capabilities':{},'env':[]},'root':{'path':'rootfs'},'mounts':[]}
        for key,value in [('process',{'args':['app'],'capabilities':{'effective':['CAP_NET_ADMIN']}}),
                          ('root',{'path':'foreign'}),('mounts',[{'destination':'/etc'}]),('hooks',{'poststart':[]}),
                          ('linux',{'devices':[{'path':'/dev/mem'}]}),('annotations',{'changed':'yes'})]:
            altered = copy.deepcopy(original); altered[key] = value
            self.assertNotEqual(application_hash(original),application_hash(altered))
    def test_live_binding_refuses_unapproved_nic_mac_ip_and_bridge(self):
        bundle = {'linux':{'namespaces':[{'type':'network'}]},'process':{'args':['app']}}
        intent = {'containerId':'a'*64,'transactionId':'b'*64,'bundlePath':'/sealed/bundle',
            'applicationHash':application_hash(bundle),'tableName':'owned','transport':profile()['policy']['flows'],
            'networkBindings':[{'interface':'eth0','bridge':'shared0','mac':'02:00:00:00:00:02','ipv4':'10.77.0.2',
                'workloadRef':'workload','bindingRef':'binding'}]}
        child = {'ifname':'eth0','ifindex':2,'link_index':7,'address':'02:00:00:00:00:02',
                 'addr_info':[{'family':'inet','local':'10.77.0.2'}]}
        host = {'ifname':'guardport','ifindex':7,'link_index':2,'master':'shared0'}
        result = live_profile(intent,bundle,'/sealed/netns',42,[child],[host])
        self.assertEqual(result['namespaceOrigin'],'OCI_CREATED')
        for children,hosts in [([child,child],[host]),([dict(child,address='02:00:00:00:00:09')],[host]),
                               ([dict(child,addr_info=[])],[host]),([child],[dict(host,master='foreign')])]:
            with self.assertRaises(PreexecDenied): live_profile(intent,bundle,'/sealed/netns',42,children,hosts)


class AuthorityFenceTest(unittest.TestCase):
    def setUp(self):
        self.h = fixture.PreexecTest(); self.h.setUp()
    def test_revocation_between_binding_check_and_fifo_release_is_denied_under_lock(self):
        h = self.h; h.enable_fixture_start(); h.gate.operate('apply'); h.state['status'] = 'created'
        calls = []; started = []
        def fence():
            self.assertTrue(h.held); calls.append(1)
            if len(calls) == 2: raise PreexecDenied('AUTHORITY_REVOKED_OR_CHANGED')
        with self.assertRaises(PreexecDenied): h.gate.before_process(h.state,lambda:started.append(1),fence)
        self.assertEqual(len(calls),2); self.assertEqual(started,[]); self.assertFalse(h.held)
    def test_expired_authority_does_not_prevent_owned_rollback(self):
        h = self.h; h.gate.operate('apply')
        def denied(): raise PreexecDenied('EXPIRED')
        with self.assertRaises(PreexecDenied): h.gate.operate('verify',denied)
        self.assertEqual(h.gate.operate('rollback',denied)['state'],'ROLLED_BACK')


class AdmissionPackageTest(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0,'root-private source package')
    def test_fifteen_source_files_sealed_without_installation_and_replay_denied(self):
        from scripts.semantic_provider_preexec_hook import MODULES,SELF
        names = ['scripts/stage_semantic_admission_package.py','scripts/stage_semantic_preexec_package.py',
                 'scripts/semantic_provider_docker_runtime.py',SELF,'scripts/semantic_provider_admission_preparer.py',
                 *('tools/'+n+'.py' for n in MODULES),'tools/semantic_provider_admission.py']
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))) as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700); source = root/'source'; source.mkdir(mode=0o700)
            for name in names:
                p = source/name; p.parent.mkdir(mode=0o700,exist_ok=True); p.write_bytes((repository/name).read_bytes()); p.chmod(0o600)
            sha = hashlib.sha256((source/SELF).read_bytes()).hexdigest()
            def call(mode):
                return subprocess.run([sys.executable,'-I','-B',str(source/names[0]),'--mode',mode,
                    '--package-root',str(root),'--source-commit','a'*40,'--hook-source-sha256',sha],
                    capture_output=True,text=True,timeout=10)
            self.assertEqual(call('plan').returncode,0); self.assertFalse((root/'source-package-receipt.json').exists())
            result = call('apply'); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            receipt = json.loads((root/'source-package-receipt.json').read_bytes())
            self.assertEqual(receipt['schema'],'ouf.semantic-admission-source-package.v3')
            self.assertEqual(len(receipt['sourceHashes']),15)
            for key in ('runtimeAdapterInstalled','admissionPreparerInstalled','runtimeRegistered','startAuthorized',
                        'rulesChanged','unitsChanged','containersChanged'): self.assertIs(receipt[key],False)
            self.assertEqual(call('verify').returncode,0); self.assertNotEqual(call('apply').returncode,0)
            p = source/'tools/semantic_provider_admission.py'; p.write_bytes(p.read_bytes()+b'\n# drift\n')
            self.assertNotEqual(call('verify').returncode,0)


if __name__ == '__main__': unittest.main()
