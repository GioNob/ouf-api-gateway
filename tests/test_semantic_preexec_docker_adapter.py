import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
from scripts import semantic_provider_docker_runtime as adapter
from scripts.semantic_provider_preexec_hook import SELF, MODULES
from scripts import semantic_provider_admission_preparer as preparer
from tools.semantic_provider_deployment_admission import transport_hash
from tools.semantic_provider_preexec import digest
from tests import test_semantic_shared_coordination_native as native_fixture


class AdapterContractTest(unittest.TestCase):
    def test_no_exec_run_restore_or_ambiguous_runtime_arguments(self):
        cid = 'a'*64
        for args in [['--root','/run/test','run',cid], ['--root','/run/test','exec',cid],
                     ['--root','/run/test','restore',cid], ['--root','/run/test','create','--bundle','/b','-b','/c',cid],
                     ['--root','/run/test','create','--bundle','/b','--preserve-fds','1',cid],
                     ['--root','/run/test','start',cid,'foreign']]:
            with self.assertRaises(adapter.Denied): adapter.arguments(args)
        self.assertEqual(adapter.arguments(['--root','/run/test','create','--bundle','/b',cid])[0], 'create')

    def test_duplicate_json_and_candidate_independent_binding(self):
        with self.assertRaises(adapter.Denied): adapter.parse('{"a":1,"a":2}')
        cfg = {'runtimePath':'/runc','candidates':{'a':{'approvalRef':'one'}}}
        original = adapter.binding(cfg, 'a'); cfg['candidates']['b'] = {'approvalRef':'two'}
        self.assertEqual(adapter.binding(cfg, 'a'), original)
        cfg['runtimePath'] = '/foreign'; self.assertNotEqual(adapter.binding(cfg, 'a'), original)

    def test_per_candidate_admission_configuration_does_not_rebind_another_cohort(self):
        cfg = {'schema':'ouf.semantic-docker-runtime-adapter.v2','runtimePath':'/runc',
            'candidates':{'a':{'approvalRef':'a'*64,'bundleParents':['/bundles'],
                'admissionConfiguration':'/entity-a/admission.json','admissionConfigurationHash':'b'*64}}}
        original = adapter.binding(cfg,'a')
        cfg['candidates']['b'] = {'approvalRef':'c'*64,'bundleParents':['/other'],
            'admissionConfiguration':'/entity-b/admission.json','admissionConfigurationHash':'d'*64}
        self.assertEqual(adapter.binding(cfg,'a'),original)
        cfg['candidates']['a']['admissionConfigurationHash'] = 'e'*64
        self.assertNotEqual(adapter.binding(cfg,'a'),original)


@unittest.skipUnless(os.environ.get('OUF_DOCKER_ADAPTER_NATIVE_TEST') == '1', 'real named Docker adapter opt-in')
class DockerAdapterTest(unittest.TestCase):
    def test_named_docker_runtime_gate_and_default_preserved(self):
        self.exercise()

    def test_two_phase_adapter_v3_real_preparer_v2_and_consumed_v4_start(self):
        self.exercise(two_phase=True)

    def test_authenticated_adapter_v4_preparer_v3_and_driver_v5(self):
        self.exercise(two_phase=True, authenticated=True)

    def exercise(self,two_phase=False,authenticated=False):
        self.assertEqual(os.geteuid(), 0)
        docker = shutil.which('docker'); runc = str(Path(shutil.which('runc')).resolve())
        # setup-python's cache can be owned by the runner user. The deployed
        # adapter requires a root-owned interpreter and ancestor chain.
        python = str(Path('/usr/bin/python3').resolve()); repository = Path(__file__).resolve().parents[1]
        suffix = uuid.uuid4().hex[:8]; name = 'ouf-gate-'+suffix; bridge = 'dg'+suffix
        daemon_path = Path('/etc/docker/daemon.json'); old = daemon_path.read_bytes() if daemon_path.exists() else None
        def run(*argv, check=True, payload=None):
            result = subprocess.run(argv, input=payload, capture_output=True, timeout=30)
            if check: self.assertEqual(result.returncode, 0, 'CI fixture command failed: '+argv[0])
            return result
        def dock(*argv, **kw): return run(docker, *argv, **kw)
        default = dock('info','--format','{{.DefaultRuntime}}').stdout
        image = None; network = None; cids = []; tables = []; modified = False
        with tempfile.TemporaryDirectory(dir='/root', prefix='ouf-docker-adapter-') as tmp:
            root = Path(tmp); root.chmod(0o700); source = root/'source'; source.mkdir(mode=0o700)
            names=[SELF, 'scripts/semantic_provider_docker_runtime.py', *('tools/'+v+'.py' for v in MODULES)]
            if two_phase: names += [preparer.SELF,'tools/semantic_provider_deployment_admission.py',
                                   'tools/semantic_provider_deployment_protocol.py','tools/semantic_provider_deployment_consumption.py']
            if authenticated: names += ['tools/semantic_provider_deployment_authentication.py','tools/semantic_provider_deployment_reauthorization.py']
            for relative in names:
                target = source/relative; target.parent.mkdir(mode=0o700, exist_ok=True)
                target.write_bytes((repository/relative).read_bytes()); target.chmod(0o600)
            def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
            broker = root/'admission.py'
            fixture='semantic_docker_two_phase_fixture.py' if two_phase else 'semantic_docker_admission_fixture.py'
            broker.write_bytes((repository/'tests/fixtures'/fixture).read_bytes()); broker.chmod(0o600)
            registry = root/'registry'; registry.mkdir(mode=0o700)
            admission_path = root/'admission.json'; config_path = root/'adapter.json'
            def private(path, value): path.write_text(json.dumps(value)); path.chmod(0o600)
            commands = {k:str(Path(shutil.which(k)).resolve()) for k in ('nft','ip','nsenter')}
            if two_phase: commands['unshare']=str(Path(shutil.which('unshare')).resolve())
            common_lock=root/'guard.lock'; common_lock.touch(mode=0o600)
            admission = {'repository':str(repository),'source':str(source),'python':python,'commands':commands,
                         'runc':runc,'runcHash':sha(runc),'approved':{},
                         'mountCommands':{k:str(Path(shutil.which(k)).resolve()) for k in ('mount','umount')}}
            private(admission_path, admission)
            cfg = {'schema':'ouf.semantic-docker-runtime-adapter.v1','sourceHash':sha(source/'scripts/semantic_provider_docker_runtime.py'),
                'runtimePath':runc,'runtimeSha256':sha(runc),'pythonPath':python,'pythonSha256':sha(python),
                'driverPath':str(source/SELF),'driverSha256':sha(source/SELF),'admissionPath':str(broker),
                'admissionSha256':sha(broker),'admissionConfiguration':str(admission_path),
                'admissionConfigurationHash':sha(admission_path),'registryRoot':str(registry),
                'runtimeStateRoot':'/run','candidates':{}}
            private(config_path, cfg)
            if two_phase:
                cfg['schema']='ouf.semantic-docker-runtime-adapter.v4' if authenticated else 'ouf.semantic-docker-runtime-adapter.v3'
                cfg.pop('admissionConfiguration'); cfg.pop('admissionConfigurationHash'); private(config_path,cfg)
            try:
                daemon = json.loads(old) if old else {}; daemon.setdefault('runtimes', {})
                self.assertNotIn(name, daemon['runtimes'])
                daemon['runtimes'][name] = {'path':python,'runtimeArgs':['-I','-B',str(source/'scripts/semantic_provider_docker_runtime.py'),
                                           '--configuration',str(config_path)]}
                daemon_path.parent.mkdir(exist_ok=True); daemon_path.write_text(json.dumps(daemon)); modified = True
                run('systemctl','reload','docker'); self.assertEqual(dock('info','--format','{{.DefaultRuntime}}').stdout, default)
                archive = io.BytesIO()
                with tarfile.open(fileobj=archive, mode='w') as tar:
                    for directory in ('bin','proof'):
                        item = tarfile.TarInfo(directory); item.type = tarfile.DIRTYPE; item.mode = 0o755; tar.addfile(item)
                    busybox = Path(shutil.which('busybox')).read_bytes(); item = tarfile.TarInfo('bin/busybox')
                    item.size = len(busybox); item.mode = 0o755; tar.addfile(item, io.BytesIO(busybox))
                    item = tarfile.TarInfo('bin/sh'); item.type = tarfile.SYMTYPE; item.linkname = 'busybox'; tar.addfile(item)
                image = dock('image','import','-',payload=archive.getvalue()).stdout.decode().strip()
                network = dock('network','create','--internal','--subnet','10.77.0.0/24',
                               '--opt','com.docker.network.bridge.name='+bridge, name).stdout.decode().strip()
                parents = ['/run/containerd/io.containerd.runtime.v2.task/moby',
                           '/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby']
                cases=[(True,True),(True,False)] if two_phase else [(False,False),(True,True),(True,False)]
                if authenticated: cases=[(True,True),(True,False),(True,False)]
                for index, (authorized, drift) in enumerate(cases):
                    signature_drift=authenticated and index==1
                    proof = root/('proof'+str(index)); proof.mkdir(); marker = proof/'started'
                    command = ['/bin/sh','-c','echo APP > /proof/started; /bin/busybox sleep 2']
                    cid = dock('create','--runtime',name,'--network',network,'--ip','10.77.0.'+str(index+2),
                        *(['--mac-address','02:00:00:00:00:'+format(index+2,'02x')] if two_phase else []),
                        '--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=bind,source='+str(proof)+',target=/proof',
                        image, *command).stdout.decode().strip(); cids.append(cid)
                    directory = registry/cid; directory.mkdir(mode=0o700); (directory/'operation.lock').touch(mode=0o600)
                    shared, lease = 'ds_'+suffix+str(index), 'dl_'+suffix+str(index); tables.extend([shared,lease])
                    admission['approved'][cid] = {'authority':True,'startAuthorized':authorized,'leaseDrift':drift,
                        'command':command,'proof':str(proof),'ipv4':'10.77.0.'+str(index+2),'bridge':bridge,
                        'sharedTable':shared,'leaseTable':lease,'signatureDrift':signature_drift}
                    private(admission_path, admission); cfg['admissionConfigurationHash'] = sha(admission_path)
                    cfg['candidates'][cid] = {'approvalRef':sha(admission_path),'bundleParents':parents}
                    if two_phase:
                        cfg.pop('admissionConfigurationHash')
                        entry_config=directory/'broker.json'; datum=admission['approved'][cid]
                        networks=[{'interface':'eth0','bridge':bridge,'mac':'02:00:00:00:00:'+format(index+2,'02x'),
                            'ipv4':datum['ipv4'],'workloadRef':'ci-workload','bindingRef':'ci-binding'}]
                        transport=[{'purpose':'WORKLOAD_GATEWAY','authorityRef':'ci-infrastructure',
                            'source':'10.77.0.1','destination':datum['ipv4'],'protocol':'tcp','port':9443,
                            'peerIngress':{'kind':'HOST','ifindex':0}}]
                        now=int(time.time())
                        intent={'schema':'ouf.semantic-deployment-intent.v1','issuerRef':'ci-installer',
                            'installationRef':'ci-installation','entityRef':'ci-entity','containerId':cid,
                            'transactionId':hashlib.sha256(cid.encode()).hexdigest(),'artifactHash':image.split(':')[-1],
                            'deploymentConstraintsHash':digest(datum),'transportHash':transport_hash({
                                'networkBindings':networks,'transport':transport,'tableName':shared}),
                            'runtimeExecutableHash':sha(runc),'issuedAt':now,'expiresAt':now+240,
                            'infrastructureAuthorized':True,'creationAuthorized':True,'applicationStartAuthorized':False}
                        kernel=native_fixture.NativeTest.kernel(None); kernel['tableName']=lease
                        kernel['guardedInterfaces']=[bridge]; kernel['providerFlows'][0]['source']=datum['ipv4']
                        broker_cfg={**admission,'approved':{cid:datum},'intent':intent,'lock':str(common_lock),
                            'kernel':kernel,'networkBindings':networks,'transport':transport,'busyboxHash':sha(shutil.which('busybox'))}
                        if authenticated:
                            signatures=directory/'signatures';signatures.mkdir(mode=0o700)
                            keys={};grants=[];openssl=str(Path(shutil.which('openssl')).resolve())
                            for ref,issuer,roles in [('installer-key','ci-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),
                                    ('verifier-key','ci-node-verifier',['CREATION_ATTESTATION'])]:
                                key=directory/(ref+'.pem');run(openssl,'genpkey','-algorithm','ED25519','-out',str(key));key.chmod(0o600)
                                public=run(openssl,'pkey','-in',str(key),'-pubout','-outform','DER').stdout
                                self.assertEqual(public[:12],bytes.fromhex('302a300506032b6570032100'))
                                keys[ref]=str(key);grants.append({'keyRef':ref,'issuerRef':issuer,'roles':roles,
                                    'publicKey':public[12:].hex(),'notBefore':now-30,'expiresAt':now+300,'state':'ACTIVE'})
                            policy=directory/'trust.json';private(policy,{'schema':'ouf.semantic-deployment-trust-policy.v1',
                                'installationRef':'ci-installation','entityRef':'ci-entity','keys':grants})
                            version=run(openssl,'version').stdout.decode().split()[1]
                            broker_cfg['crypto']={'policyBinding':{'path':str(policy),'sha256':sha(policy)},
                                'signatureDirectory':str(signatures),'opensslBinding':{'path':openssl,'sha256':sha(openssl),'version':version},
                                'privateKeys':keys}
                        private(entry_config,broker_cfg)
                        binding={k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId')}
                        binding.update(intentHash=digest(intent),configurationHash=sha(entry_config))
                        private(directory/'deployment.json',{'schema':'ouf.semantic-deployment-consumption.v1',**binding,
                            'state':'STAGED','bundleHash':None,'generation':None,'evidenceHash':None,'approvalHash':None,'driverHash':None})
                        cfg['candidates'][cid]={'intentRef':digest(intent),'bundleParents':parents,
                            'admissionConfiguration':str(entry_config),'admissionConfigurationHash':sha(entry_config)}
                    private(config_path, cfg)
                    private(directory/'adapter.json', {'schema':'ouf.semantic-docker-runtime-journal.v1','containerId':cid,
                        'configurationHash':adapter.binding(cfg,cid),'state':'STAGED','runtimeRoot':None,'bundleHash':None,'driverHash':None})
                    result = dock('start',cid,check=False)
                    if not authorized or drift or signature_drift:
                        self.assertNotEqual(result.returncode, 0); self.assertFalse(marker.exists())
                        self.assertEqual(dock('inspect','--format','{{.State.Running}}',cid).stdout.strip(), b'false')
                        self.assertFalse((directory/'fixture-failure.json').exists(), 'negative case failed before its intended gate')
                        grant = json.loads((directory/'driver.json').read_bytes())
                        self.assertEqual(grant['profile']['applicationStartAuthorized'], authorized)
                        value = json.loads((directory/'preexec.json').read_bytes())
                        self.assertEqual(value['state'], 'PROTECTED'); self.assertIsNone(value['containerGeneration'])
                        coordination = json.loads((directory/'coordination.json').read_bytes())
                        self.assertEqual(coordination['state'], 'QUIESCING' if drift else 'QUIESCED')
                        if two_phase: self.assertEqual(json.loads((directory/'deployment.json').read_bytes())['state'],'READY')
                    else:
                        diagnostic = {}
                        for filename in ('adapter.json','preexec.json','coordination.json','fixture-failure.json'):
                            path = directory/filename
                            if path.exists():
                                value = json.loads(path.read_bytes())
                                diagnostic[filename] = {k:v for k,v in value.items() if k in ('state','type','lines')}
                        self.assertEqual(result.returncode, 0, result.stderr.decode()+' CI fixture states: '+json.dumps(diagnostic))
                        until = time.monotonic()+5
                        while not marker.exists() and time.monotonic() < until: time.sleep(.02)
                        self.assertEqual(marker.read_text().strip(), 'APP')
                        value = json.loads((directory/'preexec.json').read_bytes()); self.assertIsNotNone(value['containerGeneration'])
                        if two_phase:
                            self.assertEqual(json.loads((directory/'driver.json').read_bytes())['schema'],'ouf.semantic-preexec-driver.v5' if authenticated else 'ouf.semantic-preexec-driver.v4')
                            self.assertEqual(json.loads((directory/'deployment.json').read_bytes())['state'],'STARTED')
                        dock('wait',cid); self.assertEqual(dock('info','--format','{{.DefaultRuntime}}').stdout, default)
                    dock('rm','--force',cid,check=False); cids.remove(cid)
                    if authorized and not drift and not signature_drift:
                        self.assertEqual(json.loads((directory/'adapter.json').read_bytes())['state'], 'DELETED')
                        self.assertEqual(json.loads((directory/'preexec.json').read_bytes())['state'], 'ROLLED_BACK')
                        self.assertFalse((directory/'netns').exists())
                    # Teardown only unique fixture tables, including deliberate incomplete cases.
                    for table in (shared,lease):
                        for family in ('inet','bridge'): run(commands['nft'],'delete','table',family,table,check=False)
                print('DOCKER_PREEXEC_ADAPTER_NATIVE=PASS REAL_DOCKER_NAMED_RUNTIME=true REAL_RUNC_NFT_GATE=true'
                      ' AUTHORITY_AND_LEASE_DRIFT_NO_APPLICATION=true GUARDED_START=true DEFAULT_PRESERVED=true'
                      ' TARGET_RUNTIME_REGISTERED=false TARGET_START_AUTHORIZED=false NOT_RELEASE_ACCEPTANCE=true')
                if authenticated: print('DOCKER_AUTHENTICATED_NATIVE=PASS ADAPTER_V4=true PREPARER_V3=true DRIVER_V5=true REAL_ED25519=true SIGNATURE_DRIFT_NO_APPLICATION=true CI_KEYS_ONLY=true')
                if two_phase and not authenticated: print('DOCKER_TWO_PHASE_NATIVE=PASS ADAPTER_V3=true REAL_PREPARER_V2=true DRIVER_V4=true'
                    ' CREATED_BEFORE_FINAL_APPROVAL=true DURABLE_CLAIM_BEFORE_FIFO=true SYNTHETIC_CI_AUTHORITY=true')
            finally:
                for cid in cids: dock('rm','--force',cid,check=False)
                for namespace in registry.glob('*/netns'):
                    run(admission['mountCommands']['umount'], str(namespace), check=False)
                for table in tables:
                    for family in ('inet','bridge'): run(commands['nft'],'delete','table',family,table,check=False)
                if network: dock('network','rm',network,check=False)
                if image: dock('image','rm',image,check=False)
                if modified:
                    if old is None: daemon_path.unlink()
                    else: daemon_path.write_bytes(old)
                    run('systemctl','reload','docker')


if __name__ == '__main__': unittest.main()
