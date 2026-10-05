"""Real Ed25519/custody/transport; synthetic observations are unit-only.

Separate mandatory native CI covers the actual sealed helper and runc mounts.
"""
import copy,hashlib,json,os
from pathlib import Path
import unittest
from unittest.mock import patch
from tests import test_semantic_node_signed_path_authority as fixture
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_node_observation import NodeObservation
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_preexec import PreexecDenied

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

if __name__=='__main__':unittest.main()
