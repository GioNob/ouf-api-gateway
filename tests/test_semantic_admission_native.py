"""Actual sealed preparer + isolated template + runc, with CI-only approvals."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from tests import test_semantic_shared_coordination_native as fixture
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from tools.semantic_provider_deployment_admission import application_hash,transport_hash
from tools.semantic_provider_preexec import digest
from scripts import semantic_provider_admission_preparer as preparer


@unittest.skipUnless(os.environ.get('OUF_ADMISSION_NATIVE_TEST') == '1','isolated native admission opt-in')
class AdmissionNativeTest(unittest.TestCase):
    setUp = fixture.NativeTest.setUp
    command = fixture.NativeTest.command
    cleanup = fixture.NativeTest.cleanup
    peer = fixture.NativeTest.peer
    kernel = fixture.NativeTest.kernel

    def test_prepared_namespace_admission(self): self.exercise('PREPARED')

    def test_oci_created_namespace_admission_and_owned_anchor_cleanup(self): self.exercise('OCI_CREATED')

    def exercise(self, origin):
        bridge = 'bradmit'; self.command('ip','link','add',bridge,'type','bridge'); self.links.append(bridge)
        self.command('ip','link','set',bridge,'up')
        namespace,host,index = self.peer('admit','10.77.0.2/24','02:00:00:00:00:02',bridge)
        cfg_kernel = self.kernel(); self.command('nft','-f','-',raw=materialize(cfg_kernel,empty_provider_sets=True)['nftRules'])
        self.tables += [(f,'lease_owned') for f in ('inet','bridge')]
        lease_hash = structure_hash({f:json.loads(self.command('nft','-j','list','table',f,'lease_owned')) for f in ('inet','bridge')})
        temp = self.enterContext(tempfile.TemporaryDirectory(dir='/root',prefix='ouf-admission-'))
        root = Path(temp); root.chmod(0o700); source = root/'source'; source.mkdir(mode=0o700)
        registry = root/'candidate'; registry.mkdir(mode=0o700); bundle = registry/'bundle'; bundle.mkdir(mode=0o700)
        repository = Path(__file__).resolve().parents[1]; hashes = {}
        for relative in [preparer.SELF,preparer.DRIVER,*('tools/'+m+'.py' for m in preparer.MODULES)]:
            target = source/relative; target.parent.mkdir(mode=0o700,exist_ok=True)
            target.write_bytes((repository/relative).read_bytes()); target.chmod(0o600)
            hashes[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
        def private(path,value): path.write_text(json.dumps(value)); path.chmod(0o600)
        def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
        python = str(Path('/usr/bin/python3').resolve()); runc = str(Path(shutil.which('runc')).resolve())
        commands = {n:str(Path(shutil.which(n)).resolve()) for n in ('nft','ip','nsenter','unshare','mount','umount')}
        cid = 'a'*64; runtime = root/'runtime'; lock = root/'guard.lock'; lock.touch(mode=0o600)
        fs = bundle/'rootfs'; (fs/'bin').mkdir(parents=True); (fs/'proof').mkdir()
        (fs/'proc').mkdir(); (fs/'dev').mkdir()
        shutil.copyfile(shutil.which('busybox'),fs/'bin/busybox'); (fs/'bin/busybox').chmod(0o755)
        (fs/'bin/sh').symlink_to('busybox'); marker = fs/'proof/started'
        oci = {'ociVersion':'1.0.2','root':{'path':str(fs),'readonly':False},
            'process':{'terminal':False,'user':{'uid':0,'gid':0},'cwd':'/',
            'args':['/bin/sh','-c','echo APP > /proof/started; /bin/busybox sleep 2'],
            'env':['PATH=/bin'],'noNewPrivileges':True,
            'capabilities':{k:[] for k in ('bounding','effective','inheritable','permitted','ambient')}},
            'mounts':[{'destination':'/proc','type':'proc','source':'proc','options':['nosuid','noexec','nodev']},
                {'destination':'/dev','type':'tmpfs','source':'tmpfs','options':['nosuid','strictatime','mode=755']}],
            'linux':{'cgroupsPath':'/ouf-admission-'+self.suffix,'namespaces':[
                {'type':'mount'},{'type':'pid'},{'type':'ipc'},{'type':'uts'},
                ({'type':'network','path':'/run/netns/'+namespace} if origin == 'PREPARED' else {'type':'network'})]}}
        private(bundle/'config.json',oci)
        candidate = {'containerId':cid,'transactionId':'b'*64,'bundlePath':str(bundle),
            'applicationHash':application_hash(oci),'tableName':'admission_owned',
            'networkBindings':[{'interface':'eth0','bridge':bridge,'mac':'02:00:00:00:00:02','ipv4':'10.77.0.2',
                'workloadRef':'workload','bindingRef':'binding'}],
            'transport':[{'purpose':'WORKLOAD_GATEWAY','authorityRef':'infra-authority',
                'source':'10.77.0.1','destination':'10.77.0.2','protocol':'tcp','port':9443,
                'peerIngress':{'kind':'HOST','ifindex':0}}],
            'runtimeBinding':{'path':runc,'sha256':sha(runc),'root':str(runtime)}}
        creation = root/'creation.json'
        private(creation,{'schema':'ouf.semantic-container-creation-acceptance.v1','containerId':cid,
            'applicationHash':candidate['applicationHash'],'transportHash':transport_hash(candidate),'accepted':True})
        candidate['creationAcceptance'] = {'path':str(creation),'sha256':sha(creation)}
        now = int(time.time()); approval_path = root/'approval.json'
        scope = {'issuerRef':'ci-synthetic','installationRef':'ci','entityRef':'ci-entity','approvalRef':'ci-approval',
            'containerId':cid,'transactionId':candidate['transactionId'],'applicationHash':candidate['applicationHash'],
            'transportHash':transport_hash(candidate),'creationAcceptanceHash':sha(creation)}
        approval = {'schema':'ouf.semantic-deployment-admission-approval.v1',**scope,'issuedAt':now,'expiresAt':now+180,
            'state':'ACTIVE','infrastructureAuthorized':True,'applicationStartAuthorized':True}
        private(approval_path,approval)
        candidate['authorityBinding'] = {'path':str(approval_path),'sha256':sha(approval_path),'issuedAt':now,'expiresAt':now+180}
        candidate['authorityScope'] = scope
        binding = {'transactionId':'b'*64,'configurationHash':digest(cfg_kernel),'leaseStructureHash':lease_hash}
        coordination = root/'coordination.json'
        private(coordination,{'schema':'ouf.semantic-lease-coordination.v1',**binding,'state':'QUIESCED',
            'leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]})
        cfg = {'schema':'ouf.semantic-admission-preparer.v1','sourceRoot':str(source),'sourceHashes':hashes,
            'pythonPath':python,'pythonHash':sha(python),'commands':commands,'commandHashes':{k:sha(v) for k,v in commands.items()},
            'candidate':candidate,'kernel':cfg_kernel,'dns':{'resolvers':['127.0.0.1'],'resolverPort':53,
            'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1},'coordinationBinding':binding,
            'coordinationJournal':str(coordination),'lockFile':str(lock),'budgetSeconds':5}
        config = root/'preparer.json'; private(config,cfg)
        private(registry/'admission.json',{'schema':'ouf.semantic-admission-journal.v1','transactionId':'b'*64,
            'configurationHash':sha(config),'state':'STAGED','driverHash':None,'namespaceOwned':False,
            'namespaceInode':None,'containerGeneration':None})
        # Compile in a child network namespace before any host shared table exists.
        from tests.test_semantic_preexec import profile as basic_profile
        p = basic_profile(); p['policy']['attachments'][0].update(interface=host,ifindex=index,bridge=bridge)
        p['policy']['flows'][0]['peerIngress'] = {'kind':'HOST','ifindex':0}
        packet = {'profile':p,'mirrors':[{'interface':host,'ifindex':index}],
                  'parentNamespace':os.stat('/proc/self/ns/net').st_ino}
        argv = [*([python,'-I','-B']),str(source/preparer.SELF),'--configuration',str(config),
            '--container-id',cid,'--bundle',str(bundle),'--runtime-root',str(runtime)]
        before = self.command('nft','-j','list','ruleset')
        result = subprocess.run([commands['unshare'],'--net','--fork',*argv,'--mode','template'],
            input=json.dumps(packet),text=True,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr); template = json.loads(result.stdout)
        self.assertTrue(template['isolated']); self.assertEqual(before,self.command('nft','-j','list','ruleset'))
        # Sealed source substitution is refused before a native worker can write.
        target = source/'tools/semantic_provider_deployment_admission.py'; original = target.read_bytes()
        target.write_bytes(original+b'\n# altered\n')
        denied = subprocess.run([commands['unshare'],'--net','--fork',*argv,'--mode','template'],
            input=json.dumps(packet),text=True,capture_output=True,timeout=20)
        self.assertNotEqual(denied.returncode,0); self.assertIn('SOURCE_PACKAGE_DRIFT',denied.stderr); target.write_bytes(original)
        runc_args = [runc,'--root',str(runtime)]
        self.addCleanup(lambda:subprocess.run([*runc_args,'delete','--force',cid],capture_output=True,timeout=10))
        with tempfile.TemporaryFile() as output:
            created = subprocess.run([*runc_args,'create','--bundle',str(bundle),cid],stdout=output,stderr=output,timeout=15)
            output.seek(0); self.assertEqual(created.returncode,0,output.read().decode())
        state = json.loads(self.command(*runc_args,'state',cid)); self.assertFalse(marker.exists())
        if origin == 'OCI_CREATED':
            # Model Docker initializeCreatedTask after runc create: attach the
            # preapproved peer before calling the production preparer/start.
            self.command('ip','-n',namespace,'link','set','eth0','netns',str(state['pid']))
            ns = ['nsenter','--net=/proc/'+str(state['pid'])+'/ns/net','ip']
            self.command(*ns,'addr','replace','10.77.0.2/24','dev','eth0')
            self.command(*ns,'link','set','eth0','up')
        result = subprocess.run([*argv,'--mode','prepare'],input=json.dumps(state),text=True,capture_output=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stderr)
        self.tables += [(f,'admission_owned') for f in ('inet','bridge')]
        def driver(mode): return subprocess.run([python,'-I','-B',str(source/preparer.DRIVER),'--configuration',
            str(registry/'driver.json'),'--mode',mode],capture_output=True,text=True,timeout=15)
        # A changed approval remains revoked even while the old config is sealed.
        private(approval_path,{**approval,'state':'REVOKED'})
        denied = driver('start'); self.assertNotEqual(denied.returncode,0)
        self.assertIn('AUTHORITY_REVOKED_OR_CHANGED',denied.stdout); self.assertFalse(marker.exists())
        private(approval_path,approval)
        accepted = driver('start'); self.assertEqual(accepted.returncode,0,accepted.stdout+accepted.stderr)
        until = time.monotonic()+3
        while not marker.exists() and time.monotonic() < until: time.sleep(.02)
        self.assertEqual(marker.read_text().strip(),'APP')
        self.assertNotEqual(driver('rollback').returncode,0)
        self.command(*runc_args,'delete','--force',cid)
        rollback = driver('rollback'); self.assertEqual(rollback.returncode,0,rollback.stdout)
        cleaned = subprocess.run([*argv,'--mode','cleanup'],capture_output=True,text=True,timeout=15)
        self.assertEqual(cleaned.returncode,0,cleaned.stderr)
        self.assertEqual(json.loads((registry/'admission.json').read_bytes())['state'],'CLEANED')
        self.assertFalse((registry/'netns').exists())
        print('SEMANTIC_ADMISSION_NATIVE=PASS ISOLATED_TEMPLATE_HOST_UNCHANGED=true'
            ' SEALED_PREPARER=true REAL_RUNC_NFT=true REVOCATION_BEFORE_START_DENIED=true'
            ' LIVE_ROLLBACK_DENIED=true OWNED_CLEANUP=true SYNTHETIC_CI_AUTHORITY=true TARGET_START_AUTHORIZED=false')


if __name__ == '__main__': unittest.main()
