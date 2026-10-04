"""Opt-in real created runc, namespace observation and live mandate CLI.

Authority/keys are ephemeral CI-only fixtures; no observation or command mock.
The exact OCI is accepted after fixture create and before pinning producer
configuration. This does not prove Docker's immutable pre-create binding path.
"""
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
from tools.semantic_provider_preexec_native import NativeBackend


@unittest.skipUnless(os.environ.get('OUF_NODE_LIVE_NATIVE_TEST')=='1','isolated real runc live mandate opt-in')
class NodeLiveNativeTest(unittest.TestCase):
    setUp=network_fixture.NativeTest.setUp
    command=network_fixture.NativeTest.command
    cleanup=network_fixture.NativeTest.cleanup
    peer=network_fixture.NativeTest.peer

    def test_real_created_generation_rootfs_and_producer_cli_before_application_start(self):
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
        self.assertFalse(Path(node.cfg['acceptanceMandatePath']).exists())
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


if __name__=='__main__':unittest.main()
