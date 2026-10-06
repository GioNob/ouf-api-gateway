"""Real Ed25519/custody/transport; synthetic observations are unit-only.

Separate mandatory native CI covers the actual sealed helper and runc mounts.
"""
import base64,copy,hashlib,json,os,time
from pathlib import Path
import unittest
from unittest.mock import patch
from tests import test_semantic_node_signed_path_authority as fixture
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_node_observation import NodeObservation
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_preexec import PreexecDenied
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_deployment_protocol import validate_final
from tools.semantic_provider_deployment_consumption import Consumption
from tools.semantic_provider_deployment_reauthorization import LateAuthenticatedEvidence
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_lease_coordination import PrivateJournal,hold_common_lock

@unittest.skipUnless(os.geteuid()==0,'root-private v4 fixture; all cases required by the mandatory root CI job')
class CreationFrameTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        unit=fixture.SignedPathAuthorityTest();unit.setUp();self.addCleanup(unit.doCleanups)
        self.unit=unit;self.node=unit.node;self.issuer=unit.issuer
        root=self.node.root;self.policy=root/'frame-policy.json';self.issuer.write(self.policy,{'schema':'UNIT_ONLY_POLICY'})
        self.helper=root/'frame-observer.py'
        self.node.cfg['schema']='ouf.semantic-node-attestor.v4'
        self.node.cfg['creationFrameObserverBinding']={'python':self.node.cfg['pythonBinding'],
            'source':{'path':str(self.helper),'sha256':'0'*64},'configuration':self.issuer.bind(self.policy)}
        self.node.facts['artifactHash']=self.issuer.sha(self.policy)
        self.issuer.p.intent['artifactHash']=self.node.facts['artifactHash']
        self.issuer.write(root/'intent.json',self.issuer.p.intent)
        self.issuer.crypto.sign(encoded(self.issuer.p.intent),'DEPLOYMENT_INTENT','installer-a','installer-key')
        self.node.cfg['intentBinding']=self.issuer.bind(root/'intent.json')
        self.node.facts['intentHash']=self.node.cfg['intentBinding']['sha256']
        self.unit.auth.update({k:v for k,v in self.node.facts.items() if k!='generation'})
        self.node.observed['state']['pid']=self.node.facts['generation']['pid']
        self.reply={'schema':'ouf.semantic-configured-created-frame.v1',
            'configuredPolicy':{'configuredPolicyConforms':True,'applicationHash':self.node.facts['applicationHash']},
            'sourceMountFrame':{'sourceByteHashesMatchExpected':True,'stableAcrossReads':True,'privateMaterialSpooled':False,
                'mountObservation':{'effectiveReadOnlyFileBindingsObserved':True}},
            **{k:False for k in ('policyAuthenticationProven','rootfsSealProven','imagePublisherProvenanceVerified',
                'completeCreationAccepted','acceptanceGranted','startAuthorized')},'signaturesIssued':0}
        self.observer();self.unit.sign()

    def observer(self):
        self.helper.write_text('import sys\nprint('+repr(encoded(self.reply).decode())+')\n');self.helper.chmod(0o600)
        self.node.cfg['creationFrameObserverBinding']['source']=self.issuer.bind(self.helper);self.node.refresh()

    def emit(self):
        with patch.object(NodeObservation,'observe',return_value=self.node.observed):
            return self.node.core().emit(self.node.request_raw)

    def test_v4_real_signatures_require_signed_exact_artifact_and_stable_frame(self):
        reply=json.loads(self.emit());self.assertIn('recordSignature',reply)
        mandate=json.loads(Path(self.node.cfg['acceptanceMandatePath']).read_bytes())
        self.assertEqual(mandate['artifactHash'],self.issuer.sha(self.policy))
        self.assertEqual(mandate['generation'],self.node.facts['generation'])
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY'):self.emit()

    def test_unsigned_authority_denied_before_observation_key_or_claim(self):
        self.unit.path.unlink()
        with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key')):
            with self.assertRaises((OSError,PreexecDenied)):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_policy_must_be_signed_artifact_before_key_or_claim(self):
        self.node.cfg['creationFrameObserverBinding']['configuration']['sha256']='f'*64;self.node.refresh()
        with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key')):
            with self.assertRaisesRegex(PreexecDenied,'NODE_CREATION_POLICY_ARTIFACT_DRIFT'):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_helper_drift_is_denied_before_key_or_claim(self):
        self.helper.write_bytes(self.helper.read_bytes()+b'\n')
        with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key')):
            with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_SOURCE_OR_CONFIGURATION_DRIFT'):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_unsigned_observation_cannot_claim_acceptance_or_hide_failed_byte_check(self):
        for key in ('acceptanceGranted','byteHash'):
            self.reply['acceptanceGranted']=key=='acceptanceGranted'
            self.reply['sourceMountFrame']['sourceByteHashesMatchExpected']=key!='byteHash'
            self.observer()
            with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key')):
                with self.assertRaisesRegex(PreexecDenied,'NODE_CONFIGURED_SOURCE_MOUNT_FRAME_REQUIRED'):self.emit()
            self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_observer_drift_during_signature_keeps_claim_and_does_not_publish_mandate(self):
        original=ExistingEd25519Signer.sign
        def change(signer,raw):
            result=original(signer,raw);self.helper.write_bytes(self.helper.read_bytes()+b'\n');return result
        with patch.object(ExistingEd25519Signer,'sign',change):
            with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_SOURCE_OR_CONFIGURATION_DRIFT'):self.emit()
        self.assertTrue(Path(self.node.cfg['issuanceClaimPath']).exists())
        self.assertFalse(Path(self.node.cfg['acceptanceMandatePath']).exists())

    def late_fixture(self):
        # Stateful synthetic frame tests only the real signature/journal
        # ordering. Actual PID/source-byte observation is mandatory native CI.
        root=self.node.root;self.bind_state=root/'unit-only-bind';self.bind_state.write_bytes(b'CI_UNIT_BIND')
        self.bind_state.chmod(0o600)
        self.helper.write_text('import hashlib,json\nfrom pathlib import Path\n'
            'reply='+repr(self.reply)+'\n'
            "reply['sourceMountFrame']['mountObservation']['mountInfoHash']=hashlib.sha256(Path("
            +repr(str(self.bind_state))+').read_bytes()).hexdigest()\nprint(json.dumps(reply))\n')
        self.helper.chmod(0o600);self.node.cfg['creationFrameObserverBinding']['source']=self.issuer.bind(self.helper)
        self.node.refresh();reply=json.loads(self.emit());raw=base64.b64decode(reply['recordBase64'])
        record=json.loads(raw);attestation=root/'late-attestation.json';attestation.write_bytes(raw);attestation.chmod(0o600)
        sig=self.issuer.crypto.filename(raw,'CREATION_ATTESTATION');sig.write_bytes(encoded(reply['recordSignature']));sig.chmod(0o600)
        approval=dict(self.issuer.p.approval)
        approval.update({k:record[k] for k in ('containerId','transactionId','applicationHash','transportHash')})
        approval.update(creationAcceptanceHash=digest(record['creationAcceptance']),issuedAt=int(time.time()),
            expiresAt=self.issuer.p.intent['expiresAt'])
        approval_path=root/'late-approval.json';self.issuer.write(approval_path,approval)
        self.issuer.crypto.sign(encoded(approval),'FINAL_DEPLOYMENT_APPROVAL','installer-a','installer-key')
        raws=(encoded(self.issuer.p.intent),raw,encoded(approval))
        evidence=validate_final(*raws,self.issuer.p.ctx,self.issuer.crypto.verifier)
        records={'intent':self.node.cfg['intentBinding'],'attestation':self.issuer.bind(attestation),
            'approval':self.issuer.bind(approval_path)}
        self.late=LateAuthenticatedEvidence(records,self.issuer.p.ctx,self.issuer.crypto.policy_binding,
            str(self.issuer.crypto.signature_directory),self.issuer.crypto.openssl_binding,digest(evidence),
            evidence['scope'],budget=VerificationBudget(12),creation_frame={
                'observerBinding':self.node.cfg['creationFrameObserverBinding'],'bundlePath':str(root/'bundle/config.json')})
        binding={k:record[k] for k in ('installationRef','entityRef','containerId','transactionId','intentHash')}
        binding['configurationHash']='c'*64
        journal=root/'late-consumption.json';self.issuer.write(journal,{'schema':'ouf.semantic-deployment-consumption.v1',
            **binding,'state':'STAGED',**dict.fromkeys(('bundleHash','generation','evidenceHash','approvalHash','driverHash'))})
        lock=root/'late.lock';lock.touch(mode=0o600)
        self.gate=Consumption(binding,PrivateJournal(journal),lambda:hold_common_lock(lock))
        self.gate.authorize_create(raws[0],self.issuer.p.ctx,self.issuer.crypto.verifier)
        self.gate.created(record['applicationHash'],record['generation'])
        self.gate.ready(*raws,self.issuer.p.ctx,self.issuer.crypto.verifier);self.gate.seal_driver('d'*64)
        self.evidence=evidence;self.started=[]

    def consume(self):
        with self.gate.hold_lock():
            self.gate.consume_locked(digest(self.evidence),'d'*64,self.evidence['generation'],self.late,
                lambda:self.started.append(1))

    def test_v2_signed_frame_cannot_be_consumed_without_fresh_observer_binding(self):
        self.late_fixture();self.late.creation_frame=None
        with self.assertRaisesRegex(PreexecDenied,'LATE_AUTHENTICATED_CREATION_FRAME_REQUIRED'):self.consume()
        self.assertEqual(self.gate.record()['state'],'READY');self.assertEqual(self.started,[])

    def test_frame_drift_before_consumption_preserves_ready_and_never_calls_starter(self):
        self.late_fixture();self.bind_state.write_bytes(b'CI_UNIT_CHANGED_BIND')
        with self.assertRaisesRegex(PreexecDenied,'LATE_CREATED_FRAME_DRIFT'):self.consume()
        self.assertEqual(self.gate.record()['state'],'READY');self.assertEqual(self.started,[])

    def test_frame_drift_after_durable_starting_is_denied_and_not_replayed(self):
        self.late_fixture();original=self.gate.journal.write
        def change(old,new):
            original(old,new)
            if new['state']=='STARTING':self.bind_state.write_bytes(b'CI_UNIT_CHANGED_AFTER_FSYNC')
        self.gate.journal.write=change
        with self.assertRaisesRegex(PreexecDenied,'LATE_CREATED_FRAME_DRIFT'):self.consume()
        self.assertEqual(self.gate.record()['state'],'STARTING');self.assertEqual(self.started,[])
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY_DEPLOYMENT_START'):self.consume()

if __name__=='__main__':unittest.main()
