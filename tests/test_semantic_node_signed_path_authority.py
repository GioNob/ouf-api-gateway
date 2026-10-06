"""Explicit v3 private signed authority path, immutable producer bindings."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_semantic_node_live_mandate as fixture
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_node_attestor import NodeAttestor
from tools.semantic_provider_node_observation import NodeObservation
from tools.semantic_provider_preexec import PreexecDenied


@unittest.skipUnless(os.geteuid()==0,'root-private signed path authority; mandatory root CI job')
class SignedPathAuthorityTest(unittest.TestCase):
    def setUp(self):
        f=fixture.LiveMandateTest();f.setUp();self.addCleanup(f.doCleanups)
        self.fixture=f;self.node=f.f;self.issuer=self.node.f
        self.auth=f.authorization;self.path=f.authpath
        self.node.cfg['schema']='ouf.semantic-node-attestor.v3'
        self.node.cfg.pop('liveAcceptanceAuthorizationBinding')
        self.node.cfg['liveAcceptanceAuthorizationPath']=str(self.path)
        self.node.refresh()

    def sign(self):
        self.issuer.write(self.path,self.auth)
        self.issuer.crypto.sign(encoded(self.auth),'CREATION_ATTESTATION','verifier-a','verifier-key')

    def emit(self):
        with patch.object(NodeObservation,'observe',return_value=self.node.observed):
            return self.node.core().emit(self.node.request_raw)

    def test_late_exact_signed_authority_does_not_mutate_pinned_configuration(self):
        configuration=self.node.path.read_bytes();binding=copy.deepcopy(self.node.binding)
        self.path.unlink();self.auth['issuedAt']+=1
        self.node.producer.pinned()  # authority bytes are not required to pin producer
        self.sign();reply=json.loads(self.emit())
        self.assertEqual(self.node.path.read_bytes(),configuration);self.assertEqual(self.node.binding,binding)
        mandate=json.loads(Path(self.node.cfg['acceptanceMandatePath']).read_bytes())
        self.assertEqual(mandate['applicationHash'],self.auth['applicationHash'])
        self.assertEqual(mandate['generation'],self.node.facts['generation'])
        self.assertIn('recordSignature',reply)

    def test_unsigned_late_content_denied_before_private_key_and_claim(self):
        self.auth['issuedAt']+=1;self.issuer.write(self.path,self.auth)
        with patch.object(ExistingEd25519Signer,'key_raw',side_effect=AssertionError('unexpected signing key read')):
            with self.assertRaises((OSError,PreexecDenied)):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_late_signed_wrong_exact_oci_denied_before_claim(self):
        self.auth['applicationHash']='f'*64;self.sign()
        with self.assertRaisesRegex(PreexecDenied,'EXPLICIT_LIVE_ACCEPTANCE_AUTHORITY_REQUIRED'):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_missing_authority_is_denial_not_implicit_acceptance(self):
        self.path.unlink()
        with self.assertRaises((OSError,PreexecDenied)):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_symlink_and_nonprivate_authority_are_denied(self):
        raw=self.path.read_bytes();target=self.path.with_name('foreign.json');target.write_bytes(raw);target.chmod(0o600)
        self.path.unlink();self.path.symlink_to(target)
        with self.assertRaises((OSError,PreexecDenied)):self.emit()
        self.path.unlink();self.path.write_bytes(raw);self.path.chmod(0o644)
        with self.assertRaises(PreexecDenied):self.emit()
        self.assertFalse(Path(self.node.cfg['issuanceClaimPath']).exists())

    def test_authority_drift_during_issuance_retains_claim_and_no_mandate(self):
        original=ExistingEd25519Signer.sign
        def change(signer,raw):
            signature=original(signer,raw);self.path.write_bytes(b'changed authority');return signature
        with patch.object(ExistingEd25519Signer,'sign',change):
            with self.assertRaisesRegex(PreexecDenied,'INSTALLER_EVIDENCE_CHANGED'):self.emit()
        self.assertTrue(Path(self.node.cfg['issuanceClaimPath']).exists())
        self.assertFalse(Path(self.node.cfg['acceptanceMandatePath']).exists())

    def test_explicit_schemas_never_accept_mixed_bindings_or_relative_paths(self):
        self.node.cfg['liveAcceptanceAuthorizationBinding']=self.issuer.bind(self.path);self.node.refresh()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_NODE_ATTESTOR_CONFIGURATION_REQUIRED'):self.node.core()
        self.node.cfg.pop('liveAcceptanceAuthorizationBinding');self.node.cfg['liveAcceptanceAuthorizationPath']='relative.json';self.node.refresh()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_PRIVATE_LIVE_AUTHORIZATION_PATH_REQUIRED'):self.node.core()
        self.node.cfg['liveAcceptanceAuthorizationPath']=str(self.path);self.node.cfg['schema']='ouf.semantic-node-attestor.v2';self.node.refresh()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_NODE_ATTESTOR_CONFIGURATION_REQUIRED'):self.node.core()

    def test_source_sealed_v3_cli_accepts_late_signed_exact_authority(self):
        source=Path(self.node.cfg['sourceRoot'])/'tools/semantic_provider_node_observation.py'
        source.write_text('class NodeObservation:\n'
            '    def __init__(self,cfg,budget): pass\n'
            '    def observe(self,request,journal,reader):\n'
            '        return '+repr(self.node.observed)+'\n');source.chmod(0o600)
        self.node.cfg['sourceHashes']['tools/semantic_provider_node_observation.py']=self.issuer.sha(source)
        self.node.refresh();configuration=self.node.path.read_bytes()
        self.path.unlink();self.auth['issuedAt']+=1;self.sign()
        result=self.node.producer.emit('CREATION_ATTESTATION',self.node.facts)
        self.assertEqual(json.loads(result['record'])['generation'],self.node.facts['generation'])
        self.assertEqual(self.node.path.read_bytes(),configuration)


if __name__=='__main__':unittest.main()
