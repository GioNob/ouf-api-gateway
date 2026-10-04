"""Real two-producer cryptography, persistent phases and common-lock composition.

Native runc/preparer are replaced here; the Docker opt-in job exercises them.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from scripts import semantic_provider_deployment_broker as broker
from tests import test_semantic_deployment_producer as producer_fixture
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_preexec import digest

@unittest.skipUnless(os.geteuid()==0,'root-private broker fixture')
class BrokerTest(unittest.TestCase):
    def setUp(self):
        self.fixture=producer_fixture.ProducerTest();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;p=f.protocol;self.root=f.fixture.root
        self.candidate={'containerId':p.intent['containerId'],'transactionId':p.intent['transactionId'],
            'networkBindings':[],'transport':[],'tableName':'test_owned','runtimeBinding':{'path':'/runc','sha256':'f'*64}}
        transport=digest({k:self.candidate[k] for k in ('networkBindings','transport','tableName')})
        p.intent['transportHash']=transport;p.creation['transportHash']=transport
        p.attestation['transportHash']=transport;p.attestation['creationAcceptance']=copy.deepcopy(p.creation)
        p.attestation['intentHash']=digest(p.intent)
        p.approval['transportHash']=transport;p.approval['creationAcceptanceHash']=digest(p.creation)
        self.template={'schema':'ouf.semantic-admission-preparer-template.v1','pythonPath':'/usr/bin/python3','pythonHash':'f'*64,
            'commands':{},'commandHashes':{},'candidate':self.candidate,'kernel':{},'dns':{},'coordinationBinding':{},
            'coordinationJournal':str(self.root/'coordination.json'),'lockFile':str(self.root/'guard.lock'),'budgetSeconds':5,
            'hostNetworkNamespace':1}
        (self.root/'guard.lock').touch(mode=0o600)
        for name in ('attestation','approval'):(self.root/(name+'-results')).mkdir(mode=0o700)
        self.attestor=f.configured('CREATION_ATTESTATION',f.facts_for('CREATION_ATTESTATION'))
        self.approver=f.configured('FINAL_DEPLOYMENT_APPROVAL',f.facts_for('FINAL_DEPLOYMENT_APPROVAL'))
        f.fixture.sign(encoded(p.intent),'DEPLOYMENT_INTENT','installer-a','installer-key')
        self.write('intent.json',p.intent);self.write('template.json',self.template)
        self.cfg={'schema':'ouf.semantic-deployment-broker.v1','sourceRoot':str(self.root),'sourceHashes':{},
            'authorities':p.ctx,'intentBinding':self.file_binding('intent.json'),'preparerTemplate':self.file_binding('template.json'),
            'policyBinding':f.fixture.policy_binding,'signatureDirectory':str(f.fixture.signature_directory),
            'opensslBinding':f.fixture.openssl_binding,'producers':{'attestation':self.attestor.configured,'approval':self.approver.configured},
            'candidateRoot':str(self.root),'runtimeRootParent':'/run'}
        for path in f.fixture.signature_directory.glob('*.json'):
            if not path.name.endswith('.DEPLOYMENT_INTENT.json'):path.unlink()
        self.write('broker.json',self.cfg)
        self.args=SimpleNamespace(container_id=p.intent['containerId'],bundle=str(self.root/'bundle'),runtime_root='/run/fixture',mode='prepare')
        self.value=self.new()
        self.write('deployment.json',{'schema':'ouf.semantic-deployment-consumption.v1',**self.value.binding,'state':'CREATED',
            'bundleHash':p.attestation['applicationHash'],'generation':p.attestation['generation'],'evidenceHash':None,'approvalHash':None,'driverHash':None})
        self.write('broker-state.json',{'schema':'ouf.semantic-deployment-broker-journal.v1',**self.value.binding,'state':'CREATED',
            'runtimeRoot':self.args.runtime_root,'bundleHash':p.attestation['applicationHash'],'driverHash':None})

    def write(self,name,value):
        path=self.root/name;path.write_bytes(encoded(value));path.chmod(0o600)
    def file_binding(self,name):
        path=self.root/name;return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def new(self):return broker.Broker(self.cfg,encoded(self.cfg),self.root/'broker.json',self.args,clock=lambda:150)
    def native(self,state):return self.fixture.protocol.attestation['applicationHash'],self.fixture.protocol.attestation['generation']
    def preparer(self,mode,state):
        value=json.loads((self.root/'preparer.json').read_bytes())
        self.write('driver.json',{'schema':'ouf.semantic-preexec-driver.v5','consumptionBinding':value['consumptionBinding'],
            'authenticationBinding':value['authenticationBinding']})
        admission=json.loads((self.root/'admission.json').read_bytes());admission.update(state='PROTECTED',driverHash=self.file_binding('driver.json')['sha256'])
        self.write('admission.json',admission)
    def prepare(self,callback=None):
        with patch.object(self.value,'runtime',side_effect=self.native),patch.object(self.value,'invoke_preparer',side_effect=callback or self.preparer):
            self.value.operate({})

    def test_real_producers_publish_ready_and_seal_driver_without_nested_lock(self):
        self.prepare();self.assertEqual(self.value.record()['state'],'PROTECTED')
        self.assertEqual(self.value.gate.record()['state'],'READY');self.assertEqual(self.value.gate.record()['driverHash'],self.file_binding('driver.json')['sha256'])
        for name in ('attestation','approval'):
            self.assertEqual(json.loads((self.root/(name+'-emission.json')).read_bytes())['state'],'ISSUED')
            self.assertEqual(len(list((self.root/(name+'-results')).glob('*.json'))),1)
        with self.assertRaisesRegex(RuntimeError,'DO_NOT_REPLAY_BROKER_PREPARATION'):self.prepare()

    def test_incomplete_authenticated_creation_never_invokes_approval(self):
        f=self.fixture;changed=copy.deepcopy(f.protocol.attestation);changed['creationAcceptance']['accepted']=False
        configured=f.configured('CREATION_ATTESTATION',f.facts_for('CREATION_ATTESTATION'),response=f.response('CREATION_ATTESTATION',f.facts_for('CREATION_ATTESTATION'),changed))
        for path in f.fixture.signature_directory.glob('*.json'):
            if not path.name.endswith('.DEPLOYMENT_INTENT.json'):path.unlink()
        self.cfg['producers']['attestation']=configured.configured;self.write('broker.json',self.cfg);self.value=self.new()
        for name in ('deployment.json','broker-state.json'):
            value=json.loads((self.root/name).read_bytes());value['configurationHash']=self.value.binding['configurationHash'];self.write(name,value)
        with self.assertRaisesRegex(Exception,'COMPLETE_CREATION_ACCEPTANCE_REQUIRED'):self.prepare()
        self.assertFalse((self.root/'approval-emission.json').exists());self.assertEqual(self.value.gate.record()['state'],'CREATED')
        self.assertEqual(self.value.record()['state'],'PREPARING')

    def test_preparer_failure_keeps_ready_unsealed_and_never_reissues(self):
        with self.assertRaises(RuntimeError):self.prepare(lambda *_:(_ for _ in ()).throw(RuntimeError('unknown preparer outcome')))
        self.assertEqual(self.value.record()['state'],'PREPARING');self.assertEqual(self.value.gate.record()['state'],'READY')
        self.assertIsNone(self.value.gate.record()['driverHash'])
        self.value=self.new()
        with self.assertRaisesRegex(RuntimeError,'DO_NOT_REPLAY_BROKER_PREPARATION'):self.prepare()

    def test_custody_drift_during_preparation_blocks_driver_seal(self):
        def drift(*args):
            self.preparer(*args);path=next((self.root/'attestation-results').glob('*.json'));path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(RuntimeError,'BROKER_PRODUCER_CUSTODY_DRIFT'):self.prepare(drift)
        self.assertIsNone(self.value.gate.record()['driverHash']);self.assertEqual(self.value.record()['state'],'PREPARING')

    def test_generation_changes_before_ready_never_seal(self):
        count=[0]
        def drift(state):
            count[0]+=1;app,gen=self.native(state)
            return app,gen if count[0]==1 else {**gen,'startTicks':gen['startTicks']+1}
        with patch.object(self.value,'runtime',side_effect=drift),patch.object(self.value,'invoke_preparer',side_effect=AssertionError('must not prepare')):
            with self.assertRaisesRegex(RuntimeError,'BROKER_CREATED_GENERATION_DRIFT'):self.value.operate({})
        self.assertEqual(self.value.gate.record()['state'],'CREATED')

    def test_foreign_claim_is_preserved_without_emission_or_approval(self):
        self.write('attestation-emission.json',{'foreign':True})
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual(json.loads((self.root/'attestation-emission.json').read_bytes()),{'foreign':True})
        self.assertFalse((self.root/'approval-emission.json').exists())

    def test_changed_sealed_configuration_blocks_before_claim(self):
        (self.root/'broker.json').write_bytes(encoded(self.cfg)+b' ')
        with self.assertRaisesRegex(RuntimeError,'BROKER_INPUT_CHANGED'):self.prepare()
        self.assertEqual(self.value.record()['state'],'CREATED');self.assertFalse((self.root/'attestation-emission.json').exists())

    def test_changed_signed_intent_never_creates_claim(self):
        (self.root/'intent.json').write_bytes(encoded(self.fixture.protocol.intent)+b' ')
        with self.assertRaisesRegex(RuntimeError,'BROKER_BOUND_FILE_DRIFT'):self.prepare()
        self.assertEqual(self.value.record()['state'],'CREATED')

if __name__=='__main__':unittest.main()
