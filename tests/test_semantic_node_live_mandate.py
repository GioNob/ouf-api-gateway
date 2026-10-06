"""Live mandate bridge with real Ed25519 and custody; live observations mocked."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from tests import test_semantic_node_attestor as node_fixture
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_node_attestor import NodeAttestor
from tools.semantic_provider_node_observation import NodeObservation
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_preexec import PreexecDenied


@unittest.skipUnless(os.geteuid()==0,'root-private live mandate fixture; covered by mandatory root CI job')
class LiveMandateTest(unittest.TestCase):
    def setUp(self):
        fixture=node_fixture.NodeAttestorTest();fixture.setUp();self.addCleanup(fixture.doCleanups);self.f=fixture
        self.authorization=copy.deepcopy(fixture.mandate)
        self.authorization.pop('generation')
        self.authorization.update(schema='ouf.semantic-node-live-acceptance-authorization.v1',
            generationBinding='OBSERVED_CREATED',mandateIssuanceAuthorized=True)
        self.authpath=fixture.root/'live-authorization.json'
        Path(fixture.cfg['acceptanceMandatePath']).unlink()
        fixture.cfg['schema']='ouf.semantic-node-attestor.v2'
        self.resign()

    def resign(self):
        self.f.f.write(self.authpath,self.authorization)
        self.f.f.crypto.sign(encoded(self.authorization),'CREATION_ATTESTATION','verifier-a','verifier-key')
        self.f.cfg['liveAcceptanceAuthorizationBinding']=self.f.f.bind(self.authpath)
        self.f.refresh()

    def emit(self):
        with patch.object(NodeObservation,'observe',return_value=self.f.observed):
            return self.f.core().emit(self.f.request_raw)

    def test_live_generation_binds_signed_mandate_and_attestation(self):
        reply=json.loads(self.emit());record=json.loads(base64.b64decode(reply['recordBase64']))
        raw=Path(self.f.cfg['acceptanceMandatePath']).read_bytes();mandate=json.loads(raw)
        self.assertEqual(mandate['generation'],self.f.facts['generation'])
        self.assertEqual(record['generation'],mandate['generation'])
        self.assertEqual(mandate['rootfsSeal'],self.authorization['rootfsSeal'])
        self.assertGreaterEqual(mandate['issuedAt'],self.authorization['issuedAt'])
        self.assertLessEqual(mandate['expiresAt'],self.authorization['expiresAt'])
        self.assertTrue(self.f.f.crypto.verifier(raw,'CREATION_ATTESTATION','verifier-a','installation-a','entity-a'))
        self.assertTrue(record['creationAcceptance']['accepted'])
        self.assertEqual(json.loads(Path(self.f.cfg['issuanceClaimPath']).read_bytes())['state'],'ISSUING')

    def test_no_authority_flags_never_read_private_key_or_claim(self):
        for flag in ('mandateIssuanceAuthorized','completeCreationAccepted','attestationAuthorized'):
            self.authorization[flag]=False;self.resign()
            with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key read')):
                with self.subTest(flag=flag),self.assertRaisesRegex(PreexecDenied,'EXPLICIT_LIVE_ACCEPTANCE_AUTHORITY_REQUIRED'):
                    self.emit()
            self.assertFalse(Path(self.f.cfg['issuanceClaimPath']).exists());self.authorization[flag]=True

    def test_generation_cannot_be_presigned_or_policy_wildcard(self):
        self.authorization['generation']=self.f.facts['generation'];self.resign()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_SIGNED_LIVE_ACCEPTANCE_AUTHORIZATION_REQUIRED'):self.emit()
        self.authorization.pop('generation');self.authorization['generationBinding']='ANY';self.resign()
        with self.assertRaisesRegex(PreexecDenied,'EXPLICIT_LIVE_ACCEPTANCE_AUTHORITY_REQUIRED'):self.emit()

    def test_resealed_wrong_identity_artifact_oci_transport_denied(self):
        for key in ('issuerRef','installationRef','entityRef','containerId','transactionId','intentHash',
                    'artifactHash','deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash'):
            original=self.authorization[key];self.authorization[key]='f'*64;self.resign()
            with self.subTest(key=key),self.assertRaises(PreexecDenied):self.emit()
            self.assertFalse(Path(self.f.cfg['issuanceClaimPath']).exists());self.authorization[key]=original

    def test_rootfs_mismatch_before_private_key(self):
        self.f.observed={**self.f.observed,'rootfsSeal':{**self.f.seal,'sha256':'f'*64}}
        with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key read')):
            with self.assertRaisesRegex(PreexecDenied,'NODE_APPROVED_ROOTFS_DRIFT'):self.emit()
        self.assertFalse(Path(self.f.cfg['issuanceClaimPath']).exists())

    def test_expired_or_outside_intent_authorization(self):
        self.authorization['expiresAt']=self.authorization['issuedAt']+1;self.resign()
        with self.assertRaises(PreexecDenied):self.emit()
        self.authorization['expiresAt']=self.f.f.p.intent['expiresAt']+1;self.resign()
        with self.assertRaisesRegex(PreexecDenied,'NODE_ACCEPTANCE_EXCEEDS_INTENT'):self.emit()

    def test_initial_observation_must_match_request_generation_and_oci(self):
        original=copy.deepcopy(self.f.observed)
        for key,value in (('generation',{'pid':999}),('applicationHash','f'*64)):
            self.f.observed={**original,key:value}
            with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected private key read')):
                with self.subTest(key=key),self.assertRaisesRegex(PreexecDenied,'NODE_OBSERVED_REQUEST_DRIFT'):self.emit()
            self.assertFalse(Path(self.f.cfg['issuanceClaimPath']).exists())

    def test_invalid_signature(self):
        path=self.f.f.crypto.filename(encoded(self.authorization),'CREATION_ATTESTATION')
        value=json.loads(path.read_bytes());value['signature']='0'*128;self.f.f.write(path,value)
        with self.assertRaisesRegex(PreexecDenied,'DETACHED_SIGNATURE_INVALID'):self.emit()
        self.assertFalse(Path(self.f.cfg['issuanceClaimPath']).exists())

    def test_observation_drift_during_mandate_preserves_claim_without_publication(self):
        changed={**self.f.observed,'generation':{'pid':999}}
        with patch.object(NodeObservation,'observe',side_effect=[self.f.observed,changed]):
            with self.assertRaisesRegex(PreexecDenied,'NODE_OBSERVATION_CHANGED_DURING_MANDATE'):
                self.f.core().emit(self.f.request_raw)
        self.assertTrue(Path(self.f.cfg['issuanceClaimPath']).exists())
        self.assertFalse(Path(self.f.cfg['acceptanceMandatePath']).exists())

    def test_authorization_changed_during_mandate_preserves_claim(self):
        sign=ExistingEd25519Signer.sign
        def mutate(signer,raw):
            sig=sign(signer,raw);self.authpath.write_bytes(b'changed authorization');return sig
        with patch.object(ExistingEd25519Signer,'sign',mutate):
            with self.assertRaisesRegex(PreexecDenied,'INSTALLER_EVIDENCE_CHANGED'):self.emit()
        self.assertTrue(Path(self.f.cfg['issuanceClaimPath']).exists())
        self.assertFalse(Path(self.f.cfg['acceptanceMandatePath']).exists())

    def test_existing_mandate_or_symlink_never_overwritten(self):
        path=Path(self.f.cfg['acceptanceMandatePath']);path.write_bytes(b'preexisting evidence');path.chmod(0o600)
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY_LIVE_NODE_MANDATE'):self.emit()
        self.assertEqual(path.read_bytes(),b'preexisting evidence');path.unlink();path.symlink_to('/missing')
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY_LIVE_NODE_MANDATE'):self.emit()
        self.assertTrue(path.is_symlink());self.assertFalse(Path(self.f.cfg['issuanceClaimPath']).exists())

    def test_partial_publication_retained_and_replay_denied(self):
        from tools.semantic_provider_installer_approval import publish_once
        def fail(path,raw,reason):
            if Path(path)==Path(self.f.cfg['acceptanceMandatePath']):raise OSError('simulated interruption')
            return publish_once(path,raw,reason)
        signatures=set(self.f.f.crypto.signature_directory.iterdir())
        with patch('tools.semantic_provider_node_attestor.publish_once',fail):
            with self.assertRaises(OSError):self.emit()
        self.assertTrue(Path(self.f.cfg['issuanceClaimPath']).exists())
        self.assertEqual(len(set(self.f.f.crypto.signature_directory.iterdir())-signatures),1)
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY_INSTALLER_ISSUANCE'):self.emit()

    def test_concurrent_issuance_has_one_winner(self):
        def attempt():
            try:return json.loads(self.f.core().emit(self.f.request_raw))
            except PreexecDenied as error:return str(error)
        with patch.object(NodeObservation,'observe',return_value=self.f.observed),ThreadPoolExecutor(2) as pool:
            replies=list(pool.map(lambda _:attempt(),range(2)))
        self.assertEqual(sum(isinstance(r,dict) for r in replies),1,replies)
        self.assertIn('DO_NOT_REPLAY',next(r for r in replies if isinstance(r,str)))

    def test_v1_configuration_cannot_implicitly_opt_into_v2(self):
        self.f.cfg['schema']='ouf.semantic-node-attestor.v1';self.f.refresh()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_NODE_ATTESTOR_CONFIGURATION_REQUIRED'):self.f.core()

    def test_source_sealed_v2_cli_and_real_producer_transport(self):
        # Pin an explicit observation stub only inside the ephemeral fixture
        # package. Production sources and native observation are not modified.
        source=Path(self.f.cfg['sourceRoot'])/'tools/semantic_provider_node_observation.py'
        source.write_text('class NodeObservation:\n'
                          '    def __init__(self,cfg,budget): pass\n'
                          '    def observe(self,request,journal,reader):\n'
                          '        return '+repr(self.f.observed)+'\n')
        source.chmod(0o600)
        self.f.cfg['sourceHashes']['tools/semantic_provider_node_observation.py']=self.f.f.sha(source)
        self.f.refresh()
        result=self.f.producer.emit('CREATION_ATTESTATION',self.f.facts)
        record=json.loads(result['record'])
        self.assertEqual(record['generation'],self.f.facts['generation'])
        self.assertTrue(record['creationAcceptance']['accepted'])
        self.assertTrue(Path(self.f.cfg['acceptanceMandatePath']).exists())


if __name__=='__main__':unittest.main()
