"""Opt-in real created runc, namespace observation and live mandate CLI.

Authority/keys are ephemeral CI-only fixtures; no observation or command mock.
The exact OCI is accepted after fixture create and before pinning producer
configuration. This does not prove Docker's immutable pre-create binding path.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from tests import test_semantic_shared_coordination_native as network_fixture
from tests import test_semantic_node_live_mandate as crypto_fixture
from tools.semantic_provider_deployment_admission import application_hash,transport_hash
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_preexec import PreexecDenied,digest
from tools.semantic_provider_deployment_protocol import validate_final
from tools.semantic_provider_deployment_reauthorization import LateAuthenticatedEvidence
from tools.semantic_provider_preexec_native import NativeBackend


@unittest.skipUnless(os.environ.get('OUF_NODE_LIVE_NATIVE_TEST')=='1','isolated real runc live mandate opt-in')
class NodeLiveNativeTest(unittest.TestCase):
    setUp=network_fixture.NativeTest.setUp
    command=network_fixture.NativeTest.command
    cleanup=network_fixture.NativeTest.cleanup
    peer=network_fixture.NativeTest.peer

    def test_real_created_generation_rootfs_and_producer_cli_before_application_start(self):
        self.exercise()

    def test_real_rootfs_drift_denies_before_node_claim_or_mandate(self):
        self.exercise('rootfs')

    def test_real_full_oci_drift_denies_before_node_claim_or_mandate(self):
        self.exercise('oci')

    def test_v4_real_source_bytes_mounts_and_signed_authorization_without_application_start(self):
        self.exercise(fresh=True)

    def test_v4_real_bind_byte_drift_denies_before_node_claim_or_mandate(self):
        self.exercise('bind',fresh=True)

    def test_v4_same_byte_source_inode_replacement_denies_before_node_claim_or_mandate(self):
        self.exercise('inode',fresh=True)

    def exercise(self,drift=None,fresh=False):
        fixture=crypto_fixture.LiveMandateTest();fixture.setUp();self.addCleanup(fixture.doCleanups)
        node=fixture.f;f=node.f;root=node.root
        bridge='brnode';self.command('ip','link','add',bridge,'type','bridge');self.links.append(bridge)
        self.command('ip','link','set',bridge,'up')
        ns,_,_=self.peer('node','10.77.0.2/24','02:00:00:00:00:02',bridge)
        bundle=root/'native-bundle';bundle.mkdir(mode=0o700)
        fs=root/'rootfs'
        for name in ('bin','proc','dev','proof'):(fs/name).mkdir()
        shutil.copyfile(shutil.which('busybox'),fs/'bin/busybox');(fs/'bin/busybox').chmod(0o755)
        (fs/'bin/sh').symlink_to('busybox');marker=fs/'proof/started'
        cid=node.facts['containerId'];runtime=root/'runtime'
        runc=str(Path(shutil.which('runc')).resolve());runc_args=[runc,'--root',str(runtime)]
        oci={'ociVersion':'1.0.2','root':{'path':str(fs),'readonly':False},
            'process':{'terminal':False,'user':{'uid':0,'gid':0},'cwd':'/',
                'args':['/bin/sh','-c','echo APP > /proof/started'],
                'env':['PATH=/bin'],'noNewPrivileges':True,
                'capabilities':{k:[] for k in ('bounding','effective','inheritable','permitted','ambient')}},
            'mounts':[{'destination':'/proc','type':'proc','source':'proc','options':['nosuid','noexec','nodev']},
                {'destination':'/dev','type':'tmpfs','source':'tmpfs','options':['nosuid','strictatime','mode=755']}],
            'linux':{'cgroupsPath':'/ouf-node-'+self.suffix,'namespaces':[
                {'type':'mount'},{'type':'pid'},{'type':'ipc'},{'type':'uts'},
                {'type':'network','path':'/run/netns/'+ns}]}}
        if fresh:
            fs.chmod(0o755);os.chown(fs/'proof',10006,10006)
            oci['process']['user']={'uid':10006,'gid':10006}
            source=root/'bind-source';source.write_bytes(b'CI_PRIVATE_BIND');source.chmod(0o600);os.chown(source,10006,10006)
            bind={'source':str(source),'target':'/approved-bind','readOnly':True}
            oci['mounts'].append({'source':str(source),'destination':bind['target'],'type':'bind','options':['rbind','rprivate','ro']})
            oci['linux']['namespaces'].append({'type':'cgroup'})
            oci['linux'].update(maskedPaths=['/proc/kcore'],readonlyPaths=['/proc/sys'],
                resources={'memory':{'limit':201326592,'swap':201326592},'pids':{'limit':32}},
                seccomp={'defaultAction':'SCMP_ACT_ERRNO','defaultErrnoRet':1,'architectures':['SCMP_ARCH_X86_64'],
                        'syscalls':[{'names':["read","write","close","exit","exit_group","rt_sigreturn","rt_sigprocmask","prctl","futex","open","openat","readlink","readlinkat","fstat","newfstatat","statx","fcntl","close_range","getpid","gettid","getppid","getuid","geteuid","getgid","getegid","setgroups","setgid","setuid","getcwd","chdir","fchdir","rt_sigaction","sigaltstack","sched_yield","sched_getaffinity","clock_gettime","nanosleep","mmap","mprotect","munmap","brk","arch_prctl","set_tid_address","set_robust_list","rseq","dup","dup2","dup3","pipe","pipe2","poll","ppoll","readv","writev","pread64","pwrite64","lseek","openat2","fstatfs","statfs","access","faccessat","faccessat2"],
                        'action':'SCMP_ACT_ALLOW'}]})
            frame_policy={'schema':'ouf.semantic-configured-creation-frame-policy.v1','expectedOci':oci,
                'manifest':{'user':'10006:10006','readOnlyRoot':False,'memoryBytes':201326592,'pidsLimit':32,'mounts':[bind]},
                'startup':{'uid':10006,'gid':10006,'umask':None,'cwd':'/','args':oci['process']['args'],'env':['PATH=/bin']},
                'approvedHooks':{},'sources':[{**bind,'uid':10006,'gid':10006,'mode':0o600,'maxBytes':131072,
                    'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]}
            policy_path=root/'frame-policy.json';f.write(policy_path,frame_policy)
            helper_source=Path(os.environ['OUF_CREATION_FRAME_OBSERVER_SOURCE'])
            helper=root/'frame-observer.py';shutil.copyfile(helper_source,helper);helper.chmod(0o600)
            self.assertEqual(f.sha(helper),os.environ['OUF_CREATION_FRAME_OBSERVER_SHA256'])
            node.cfg['schema']='ouf.semantic-node-attestor.v4'
            node.cfg.pop('liveAcceptanceAuthorizationBinding')
            node.cfg['liveAcceptanceAuthorizationPath']=str(fixture.authpath)
            node.cfg['creationFrameObserverBinding']={'python':node.cfg['pythonBinding'],
                'source':f.bind(helper),'configuration':f.bind(policy_path)}
            node.facts['artifactHash']=f.sha(policy_path);f.p.intent['artifactHash']=node.facts['artifactHash']
        f.write(bundle/'config.json',oci)
        self.addCleanup(lambda:subprocess.run([*runc_args,'delete','--force',cid],capture_output=True,timeout=10))
        with tempfile.TemporaryFile() as output:
            create=subprocess.run([*runc_args,'create','--bundle',str(bundle),cid],stdin=subprocess.DEVNULL,
                stdout=output,stderr=output,timeout=20)
            output.seek(0);self.assertEqual(create.returncode,0,output.read(131072).decode())
        state=json.loads(self.command(*runc_args,'state',cid));self.assertEqual(state['status'],'created')
        self.assertFalse(marker.exists())
        real_generation=NativeBackend.generation(None,state['pid'])
        node.cfg['runtimeBinding']={'path':runc,'sha256':f.sha(runc)}
        node.cfg['commands']={k:{'path':str(Path(shutil.which(k)).resolve()),
            'sha256':f.sha(Path(shutil.which(k)).resolve())} for k in ('ip','nsenter')}
        node.cfg['candidate']={'networkBindings':[{'interface':'eth0','bridge':bridge,'mac':'02:00:00:00:00:02',
                'ipv4':'10.77.0.2','workloadRef':'ci-workload','bindingRef':'ci-binding'}],
            'transport':[{'purpose':'WORKLOAD_GATEWAY','authorityRef':'ci-infrastructure','source':'10.77.0.1',
                'destination':'10.77.0.2','protocol':'tcp','port':9443,'peerIngress':{'kind':'HOST','ifindex':0}}],
            'tableName':'node_live_ci'}
        node.cfg['rootfsLimits']={'maxEntries':1000,'maxBytes':16777216,'maxDepth':16}
        node.seal=rootfs_seal(fs,node.cfg['rootfsLimits'],VerificationBudget(12))
        node.facts.update(applicationHash=application_hash(oci),transportHash=transport_hash(node.cfg['candidate']),
            runtimeExecutableHash=f.sha(runc),generation=real_generation)
        for key in ('containerId','transportHash','runtimeExecutableHash'):f.p.intent[key]=node.facts[key]
        f.write(root/'intent.json',f.p.intent)
        f.crypto.sign(encoded(f.p.intent),'DEPLOYMENT_INTENT','installer-a','installer-key')
        node.cfg['intentBinding']=f.bind(root/'intent.json');node.facts['intentHash']=node.cfg['intentBinding']['sha256']
        fixture.authorization.update({k:v for k,v in node.facts.items() if k!='generation'})
        fixture.authorization['rootfsSeal']=node.seal;fixture.resign()
        if fresh:
            node.cfg.pop('liveAcceptanceAuthorizationBinding');node.refresh()
        self.assertFalse(Path(node.cfg['acceptanceMandatePath']).exists())
        if drift:
            if drift=='rootfs':
                path=fs/'bin/busybox';path.write_bytes(path.read_bytes()+b'CI-ROOTFS-DRIFT')
            elif drift=='oci':
                oci['process']['args']=['/bin/sh','-c','echo FOREIGN > /proof/started']
                f.write(bundle/'config.json',oci)
            elif drift=='bind':source.write_bytes(b'CI_PRIVATE_CHANGED_BIND')
            else:
                replacement=root/'replacement-bind';replacement.write_bytes(source.read_bytes());replacement.chmod(0o600)
                os.chown(replacement,10006,10006);os.replace(replacement,source)
            with self.assertRaises(PreexecDenied):node.producer.emit('CREATION_ATTESTATION',node.facts)
            self.assertFalse(Path(node.cfg['issuanceClaimPath']).exists())
            self.assertFalse(Path(node.cfg['acceptanceMandatePath']).exists())
            self.assertEqual(json.loads(self.command(*runc_args,'state',cid))['status'],'created')
            self.assertFalse(marker.exists())
            print('NODE_LIVE_NATIVE_DENIAL=PASS DRIFT='+drift.upper()+
                  ' NODE_CLAIM_CREATED=false MANDATE_PUBLISHED=false APPLICATION_NOT_STARTED=true CI_ONLY=true')
            return
        started=time.monotonic()
        reply=node.producer.emit('CREATION_ATTESTATION',node.facts)
        elapsed=time.monotonic()-started
        record=json.loads(reply['record'])
        self.assertLess(elapsed,5,'fixture live invocation must stay in unchanged producer deadline')
        self.assertEqual(record['generation'],real_generation)
        mandate_raw=Path(node.cfg['acceptanceMandatePath']).read_bytes();mandate=json.loads(mandate_raw)
        self.assertEqual(mandate['generation'],real_generation);self.assertEqual(mandate['rootfsSeal'],node.seal)
        self.assertTrue(f.crypto.verifier(mandate_raw,'CREATION_ATTESTATION','verifier-a','installation-a','entity-a'))
        self.assertEqual(json.loads(self.command(*runc_args,'state',cid))['status'],'created')
        self.assertFalse(marker.exists(),'mandate issuance cannot execute application')
        print('NODE_LIVE_NATIVE=PASS REAL_RUNC_CREATED=true REAL_NAMESPACE_ROOTFS_OBSERVATIONS=true'
              ' REAL_SOURCE_SEALED_PRODUCER_CLI=true REAL_ED25519=true APPLICATION_NOT_STARTED=true'
              ' EXACT_OCI_ACCEPTED_BEFORE_PRODUCER_PIN=true DOCKER_PRECREATE_PIN_PATH_PROVEN=false'
              ' CI_KEYS_ONLY=true TARGET_START_AUTHORIZED=false NOT_RELEASE_ACCEPTANCE=true'
              ' INVOCATION_SECONDS='+format(elapsed,'.3f'))
        if fresh:
            self.assertEqual(record['schema'],'ouf.semantic-created-candidate-attestation.v2')
            attestation=root/'fresh-attestation.json';attestation.write_bytes(reply['record']);attestation.chmod(0o600)
            sigpath=f.crypto.filename(reply['record'],'CREATION_ATTESTATION')
            sigpath.write_bytes(reply['recordSignature']);sigpath.chmod(0o600)
            approval=dict(f.p.approval)
            approval.update({k:record[k] for k in ('containerId','transactionId','applicationHash','transportHash')})
            approval.update(creationAcceptanceHash=digest(record['creationAcceptance']),issuedAt=int(time.time()),
                expiresAt=f.p.intent['expiresAt'])
            approval_path=root/'fresh-approval.json';f.write(approval_path,approval)
            f.crypto.sign(encoded(approval),'FINAL_DEPLOYMENT_APPROVAL','installer-a','installer-key')
            evidence=validate_final(encoded(f.p.intent),reply['record'],encoded(approval),f.p.ctx,f.crypto.verifier)
            records={'intent':node.cfg['intentBinding'],'attestation':f.bind(attestation),'approval':f.bind(approval_path)}
            late=LateAuthenticatedEvidence(records,f.p.ctx,f.crypto.policy_binding,str(f.crypto.signature_directory),
                f.crypto.openssl_binding,digest(evidence),evidence['scope'],budget=VerificationBudget(5),
                creation_frame={'observerBinding':node.cfg['creationFrameObserverBinding'],'bundlePath':str(bundle/'config.json')})
            self.assertTrue(late())
            source.write_bytes(b'CI_PRIVATE_LATE_BIND_DRIFT')
            with self.assertRaises(PreexecDenied):late()
            self.assertEqual(json.loads(self.command(*runc_args,'state',cid))['status'],'created')
            self.assertFalse(marker.exists())
            print('NODE_V4_CREATION_FRAME=PASS REAL_SOURCE_BYTES_AND_KERNEL_BIND=true SIGNED_POLICY_ARTIFACT_BOUND=true REAL_LATE_REAUTHENTICATION=true LATE_BIND_BYTE_DRIFT_DENIED=true APPLICATION_NOT_STARTED=true CI_ONLY=true')


if __name__=='__main__':unittest.main()
