"""Real file seals/crypto; mocked live observations are explicitly unit-only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from scripts import semantic_provider_node_attestor as cli
from tests import test_semantic_installer_approval as installer_fixture
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_deployment_producer import LocalEvidenceProducer,encoded
from tools.semantic_provider_node_attestor import NodeAttestor
from tools.semantic_provider_node_observation import rootfs_seal,NodeObservation
from tools.semantic_provider_preexec import PreexecDenied

@unittest.skipUnless(os.geteuid()==0,'root-private node attestor fixture')
class NodeAttestorTest(unittest.TestCase):
    def setUp(self):
        f=installer_fixture.InstallerApprovalTest();f.setUp();self.addCleanup(f.doCleanups);self.f=f;self.root=f.root
        source=Path(f.cfg['sourceRoot']);repository=Path(__file__).resolve().parents[1]
        paths=[cli.SELF,*('tools/'+m+'.py' for m in cli.MODULES)]
        for p in paths:
            target=source/p;target.parent.mkdir(mode=0o700,exist_ok=True);target.write_bytes((repository/p).read_bytes());target.chmod(0o600)
        rootfs=self.root/'rootfs';rootfs.mkdir(mode=0o700);(rootfs/'application').write_bytes(b'approved fixture executable')
        self.limits={'maxEntries':100,'maxBytes':10000,'maxDepth':8};self.seal=rootfs_seal(rootfs,self.limits,VerificationBudget(12))
        self.cfg={k:copy.deepcopy(f.cfg[k]) for k in ('sourceRoot','pythonBinding','authorities','intentBinding','policyBinding',
            'signatureDirectory','opensslBinding','signingKeyBinding','brokerEmissionJournal','issuanceClaimPath','budgetSeconds')}
        self.cfg.update(schema='ouf.semantic-node-attestor.v1',sourceHashes={p:f.sha(source/p) for p in paths},keyRef='verifier-key',
            acceptanceMandatePath=str(self.root/'node-mandate.json'),brokerStateJournal=str(self.root/'broker-state.json'),
            runtimeBinding=f.cfg['pythonBinding'],runtimeRootParents=[str(self.root)],bundleParents=[str(self.root)],
            commands={'ip':f.cfg['pythonBinding'],'nsenter':f.cfg['pythonBinding']},
            candidate={'networkBindings':[],'transport':[],'tableName':'unit_fixture'},rootfsLimits=self.limits)
        self.facts={k:v for k,v in f.facts.items() if k not in {'attestationHash','creationAcceptanceHash'}}
        # In unit fixtures the runtime binding is a pinned executable, never run.
        self.facts['runtimeExecutableHash']=self.cfg['runtimeBinding']['sha256']
        f.p.intent['runtimeExecutableHash']=self.facts['runtimeExecutableHash'];f.write(self.root/'intent.json',f.p.intent)
        f.crypto.sign(encoded(f.p.intent),'DEPLOYMENT_INTENT','installer-a','installer-key')
        self.cfg['intentBinding']=f.bind(self.root/'intent.json');self.facts['intentHash']=self.cfg['intentBinding']['sha256']
        self.path=self.root/'node.json';self.refresh()
        self.mandate={'schema':'ouf.semantic-node-creation-acceptance-mandate.v1','issuerRef':'verifier-a',
            'installationRef':'installation-a','entityRef':'entity-a',**self.facts,
            'rootfsSeal':self.seal,'issuedAt':f.mandate['issuedAt'],'expiresAt':f.mandate['expiresAt'],'state':'ACTIVE',
            'attestationAuthorized':True,'completeCreationAccepted':True}
        self.resign()
        self.observed={'applicationHash':self.facts['applicationHash'],'rootfsSeal':self.seal,'generation':self.facts['generation'],
            'bundle':str(self.root/'bundle'),'rootfs':str(rootfs),'state':{'status':'created'}}
    def refresh(self):
        f=self.f;f.write(self.path,self.cfg);self.binding={'python':self.cfg['pythonBinding'],
            'source':f.bind(Path(self.cfg['sourceRoot'])/cli.SELF),'configuration':f.bind(self.path)}
        budget=VerificationBudget(18);f.crypto.verifier.budget=budget
        self.producer=LocalEvidenceProducer(self.binding,f.p.ctx,f.crypto.verifier,budget)
        self.request,self.request_raw=self.producer.request('CREATION_ATTESTATION',self.facts)
        f.write(Path(self.cfg['brokerEmissionJournal']),{'schema':'ouf.semantic-local-producer-emission.v1',
            **{k:self.request[k] for k in ('role','issuerRef','installationRef','entityRef','containerId','transactionId')},
            'requestHash':hashlib.sha256(self.request_raw).hexdigest(),'producerHash':hashlib.sha256(encoded(self.binding)).hexdigest(),
            'state':'ISSUING','resultHash':None})
        f.write(Path(self.cfg['brokerStateJournal']),{'schema':'ouf.semantic-deployment-broker-journal.v1',
            **{k:self.request[k] for k in ('installationRef','entityRef','containerId','transactionId','intentHash')},
            'configurationHash':'a'*64,'state':'PREPARING','runtimeRoot':str(self.root/'runtime'),
            'bundleHash':self.facts['applicationHash'],'driverHash':None})
    def resign(self):
        self.f.write(Path(self.cfg['acceptanceMandatePath']),self.mandate)
        self.f.crypto.sign(encoded(self.mandate),'CREATION_ATTESTATION','verifier-a','verifier-key')
    def core(self):return NodeAttestor(self.cfg,encoded(self.cfg),self.path,self.binding)
    def emit(self):
        with patch.object(NodeObservation,'observe',return_value=self.observed):return self.core().emit(self.request_raw)
    def test_observed_acceptance_emits_two_real_signatures(self):
        result=json.loads(self.emit());import base64
        raw=base64.b64decode(result['recordBase64']);record=json.loads(raw)
        self.assertTrue(record['creationAcceptance']['accepted']);self.assertEqual(record['generation'],self.facts['generation'])
        signature=encoded(result['recordSignature'])
        self.assertTrue(self.f.crypto.verifier.verify_detached(raw,signature,'CREATION_ATTESTATION','verifier-a','installation-a','entity-a'))
        claim=json.loads(Path(self.cfg['issuanceClaimPath']).read_bytes());self.assertEqual(claim['schema'],'ouf.semantic-node-attestation-issuance-claim.v1')
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY'):self.emit()
    def test_wrong_entity_mandate_denied_before_private_key(self):
        self.mandate['entityRef']='foreign';self.resign()
        with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw',side_effect=AssertionError()):
            with self.assertRaisesRegex(PreexecDenied,'EXPLICIT_COMPLETE_NODE_ACCEPTANCE_REQUIRED'):self.emit()
        self.assertFalse(Path(self.cfg['issuanceClaimPath']).exists())
    def test_incomplete_acceptance_denies_without_claim(self):
        self.mandate['completeCreationAccepted']=False;self.resign()
        with self.assertRaisesRegex(PreexecDenied,'EXPLICIT_COMPLETE_NODE_ACCEPTANCE_REQUIRED'):self.emit()
        self.assertFalse(Path(self.cfg['issuanceClaimPath']).exists())
    def test_expired_acceptance_denied(self):
        self.mandate['expiresAt']=int(time.time())-1;self.mandate['issuedAt']=self.mandate['expiresAt']-1;self.resign()
        with self.assertRaises(PreexecDenied):self.emit()
    def test_altered_mandate_signature_denied(self):
        raw=encoded(self.mandate);p=self.f.crypto.filename(raw,'CREATION_ATTESTATION');v=json.loads(p.read_bytes());v['signature']='0'*128;self.f.write(p,v)
        with self.assertRaisesRegex(PreexecDenied,'DETACHED_SIGNATURE_INVALID'):self.emit()
    def test_live_rootfs_diff_blocks_before_claim(self):
        self.observed['rootfsSeal']={**self.seal,'sha256':'0'*64}
        with self.assertRaisesRegex(PreexecDenied,'NODE_APPROVED_ROOTFS_DRIFT'):self.emit()
        self.assertFalse(Path(self.cfg['issuanceClaimPath']).exists())
    def test_observation_changes_during_signing_denied_with_claim(self):
        with patch.object(NodeObservation,'observe',side_effect=[self.observed,{**self.observed,'generation':{'pid':999}}]):
            with self.assertRaisesRegex(PreexecDenied,'NODE_OBSERVATION_CHANGED_DURING_SIGNING'):self.core().emit(self.request_raw)
        self.assertTrue(Path(self.cfg['issuanceClaimPath']).exists())
    def test_foreign_or_wrong_phase_broker_journal_denied(self):
        path=Path(self.cfg['brokerStateJournal']);v=json.loads(path.read_bytes());v['state']='CREATED';self.f.write(path,v)
        with self.assertRaisesRegex(PreexecDenied,'NODE_BROKER_PREPARING_REQUIRED'):self.emit()
    def test_rootfs_every_file_mode_link_and_xattr_are_sealed(self):
        root=Path(self.observed['rootfs']);before=rootfs_seal(root,self.limits,VerificationBudget(12))
        (root/'application').chmod(0o755);changed=rootfs_seal(root,self.limits,VerificationBudget(12));self.assertNotEqual(before,changed)
        (root/'link').symlink_to('/outside/not/read');self.assertNotEqual(changed,rootfs_seal(root,self.limits,VerificationBudget(12)))
        (root/'application').write_bytes(b'different');self.assertNotEqual(changed,rootfs_seal(root,self.limits,VerificationBudget(12)))
        before=rootfs_seal(root,self.limits,VerificationBudget(12));os.setxattr(root/'application','user.test',b'metadata')
        self.assertNotEqual(before,rootfs_seal(root,self.limits,VerificationBudget(12)))
    def test_rootfs_fifo_is_refused_without_blocking(self):
        os.mkfifo(Path(self.observed['rootfs'])/'fifo')
        with self.assertRaisesRegex(PreexecDenied,'ROOTFS_SPECIAL_ENTRY_UNSUPPORTED'):rootfs_seal(self.observed['rootfs'],self.limits,VerificationBudget(12))
    def test_rootfs_entry_byte_depth_and_deadline_limits(self):
        root=Path(self.observed['rootfs'])
        for limits in ({**self.limits,'maxEntries':1},{**self.limits,'maxBytes':1}):
            with self.assertRaises(PreexecDenied):rootfs_seal(root,limits,VerificationBudget(12))
        (root/'a').mkdir();(root/'a/b').mkdir()
        with self.assertRaisesRegex(PreexecDenied,'ROOTFS_DEPTH_UNBOUNDED'):rootfs_seal(root,{**self.limits,'maxDepth':1},VerificationBudget(12))
        budget=VerificationBudget(1);budget.deadline=0
        with self.assertRaises(PreexecDenied):rootfs_seal(root,self.limits,budget)
    def test_rootfs_change_during_read_is_denied(self):
        root=Path(self.observed['rootfs']);read=os.read;changed=[False]
        def change(fd,size):
            data=read(fd,size)
            if data and not changed[0]:(root/'application').write_bytes(b'changed during read');changed[0]=True
            return data
        with patch('tools.semantic_provider_node_observation.os.read',side_effect=change):
            with self.assertRaisesRegex(PreexecDenied,'ROOTFS_CONTENT_CHANGED'):rootfs_seal(root,self.limits,VerificationBudget(12))

if __name__=='__main__':unittest.main()
