"""Real OpenSSL and source-sealed issuer CLI with ephemeral CI keys only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

from scripts import semantic_provider_creation_intent as cli
from tests.test_semantic_deployment_authentication import AuthenticationTest
from tools.semantic_provider_creation_intent import CreationIntentIssuer
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_deployment_protocol import validate_intent
from tools.semantic_provider_preexec import PreexecDenied


@unittest.skipUnless(os.geteuid() == 0, 'root-private real issuer fixture')
class CreationIntentTest(unittest.TestCase):
    def setUp(self):
        self.crypto = AuthenticationTest(); self.crypto.setUp(); self.addCleanup(self.crypto.doCleanups)
        self.root = self.crypto.root; self.now = int(time.time())
        for key in self.crypto.policy['keys']: key.update(notBefore=self.now-100, expiresAt=self.now+300)
        self.crypto.write_policy(); self.crypto.policy_binding['sha256'] = self.sha(self.crypto.policy_path)
        self.crypto.verifier.policy_binding = self.crypto.policy_binding.copy(); self.crypto.verifier.clock = time.time
        self.mandate = {'schema': 'ouf.semantic-creation-intent-mandate.v1', 'issuerRef': 'installer-a',
            'installationRef': 'installation-a', 'entityRef': 'entity-a', 'containerId': 'a'*64, 'transactionId': 'b'*64,
            'artifactHash': 'c'*64, 'deploymentConstraintsHash': 'd'*64, 'transportHash': 'e'*64, 'runtimeExecutableHash': 'f'*64,
            'issuedAt': self.now-10, 'expiresAt': self.now+180, 'issuanceAuthorized': True,
            'infrastructureAuthorized': True, 'creationAuthorized': True, 'applicationStartAuthorized': False}
        self.mandate_path = self.root/'mandate.json'; self.write(self.mandate_path, self.mandate)
        self.output = self.root/'output'; self.output.mkdir(mode=0o700)
        self.source = self.root/'source'; self.source.mkdir(mode=0o700)
        repository = Path(__file__).resolve().parents[1]
        names = [cli.SELF, *('tools/'+n+'.py' for n in cli.MODULES)]
        for name in names:
            p = self.source/name; p.parent.mkdir(mode=0o700, exist_ok=True)
            p.write_bytes((repository/name).read_bytes()); p.chmod(0o600)
        self.cfg = {'schema': 'ouf.semantic-creation-intent-issuer.v1', 'sourceRoot': str(self.source),
            'sourceHashes': {n: self.sha(self.source/n) for n in names}, 'pythonBinding': self.bind(Path('/usr/bin/python3').resolve()),
            'authorities': self.crypto.ctx, 'creationMandateBinding': self.bind(self.mandate_path),
            'policyBinding': self.crypto.policy_binding, 'signatureDirectory': str(self.crypto.signature_directory),
            'opensslBinding': self.crypto.openssl_binding, 'signingKeyBinding': self.bind(self.crypto.key), 'keyRef': 'installer-key',
            'outputDirectory': str(self.output), 'budgetSeconds': 12}
        self.path = self.root/'configuration.json'; self.refresh()
    def sha(self, path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    def bind(self, path): return {'path': str(path), 'sha256': self.sha(path)}
    def write(self, path, value): path.write_bytes(encoded(value)); path.chmod(0o600)
    def refresh(self): self.write(self.path, self.cfg)
    def remandate(self):
        self.write(self.mandate_path, self.mandate); self.cfg['creationMandateBinding'] = self.bind(self.mandate_path); self.refresh()
    def core(self, clock=time.time): return CreationIntentIssuer(self.cfg, encoded(self.cfg), self.path, clock)
    def argv(self):
        return [self.cfg['pythonBinding']['path'], '-I', '-B', str(self.source/cli.SELF),
            '--configuration', str(self.path), '--configuration-sha256', self.sha(self.path), '--authorize-creation-only']
    def test_real_cli_signature_is_accepted_by_existing_protocol_without_start(self):
        p = subprocess.run(self.argv(), capture_output=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stdout.decode()+p.stderr.decode())
        raw = (self.output/'intent.json').read_bytes()
        value = validate_intent(raw, self.crypto.ctx, self.crypto.verifier, time.time)
        self.assertFalse(value['applicationStartAuthorized']); self.assertTrue(value['creationAuthorized'])
        report = json.loads(p.stdout.decode().split('=', 1)[1])
        self.assertEqual(report['signaturesIssued'], 1); self.assertEqual(report['containerLifecycleOperations'], 0)
        self.assertEqual(json.loads((self.output/'issuance-claim.json').read_bytes())['state'], 'ISSUING')
    def test_missing_operator_flag_blocks_without_reading_key_or_claim(self):
        with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw', side_effect=AssertionError('key read')):
            with self.assertRaisesRegex(PreexecDenied, 'EXPLICIT_CREATION_ONLY'): self.core().emit()
        self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_start_authority_is_rejected_before_key_read(self):
        self.mandate['applicationStartAuthorized'] = True; self.remandate()
        with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw', side_effect=AssertionError('key read')):
            with self.assertRaisesRegex(PreexecDenied, 'CREATION_ONLY_INTENT'): self.core().emit(True)
        self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_wrong_installation_is_rejected(self):
        self.mandate['installationRef'] = 'another-installation'; self.remandate()
        with self.assertRaisesRegex(PreexecDenied, 'INSTALLATION_INTENT_SCOPE_DRIFT'): self.core().emit(True)
        self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_expired_or_excessive_mandate_is_rejected(self):
        for end in (self.now-1, self.now+301):
            self.mandate['expiresAt'] = end; self.remandate()
            with self.assertRaises(PreexecDenied): self.core().emit(True)
        self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_unapproved_root_mandate_is_rejected(self):
        self.mandate['issuanceAuthorized'] = False; self.remandate()
        with self.assertRaisesRegex(PreexecDenied, 'EXPLICIT_ROOT_CREATION_MANDATE'): self.core().emit(True)
    def test_source_drift_is_rejected_before_claim(self):
        p = self.source/'tools/semantic_provider_creation_intent.py'; p.write_bytes(p.read_bytes()+b'\n')
        with self.assertRaisesRegex(PreexecDenied, 'CREATION_ISSUER_SOURCE_CHANGED'): self.core().emit(True)
        self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_key_drift_retains_claim_and_cannot_be_replayed(self):
        self.crypto.key.write_bytes(self.crypto.key.read_bytes()+b'\n')
        with self.assertRaisesRegex(PreexecDenied, 'EXISTING_SIGNING_KEY_DRIFT'): self.core().emit(True)
        before = (self.output/'issuance-claim.json').read_bytes()
        with self.assertRaisesRegex(PreexecDenied, 'DO_NOT_REPLAY_CREATION_INTENT'): self.core().emit(True)
        self.assertEqual((self.output/'issuance-claim.json').read_bytes(), before)
    def test_revoked_policy_prevents_signing(self):
        self.crypto.policy['keys'][0]['state'] = 'REVOKED'; self.crypto.write_policy()
        self.cfg['policyBinding'] = self.bind(self.crypto.policy_path); self.refresh()
        with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw', side_effect=AssertionError('key read')):
            with self.assertRaisesRegex(PreexecDenied, 'EXPLICIT_SIGNING_ROLE_MANDATE'): self.core().emit(True)
        self.assertFalse((self.output/'intent.json').exists())
    def test_two_real_cli_processes_cannot_issue_twice(self):
        children = [subprocess.Popen(self.argv(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        replies = [c.communicate(timeout=15) for c in children]
        self.assertEqual(sorted(c.returncode for c in children), [0, 1])
        self.assertEqual(len(list(self.crypto.signature_directory.glob('*.DEPLOYMENT_INTENT.json'))), 2)
    def test_claim_fsync_failure_never_reads_key(self):
        with patch('tools.semantic_provider_installer_approval.os.fsync', side_effect=OSError('fsync')):
            with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw', side_effect=AssertionError('key read')):
                with self.assertRaises(OSError): self.core().emit(True)
        self.assertTrue((self.output/'issuance-claim.json').exists())
    def test_wrong_config_pin_blocks_real_cli_before_issuance(self):
        argv = self.argv(); argv[argv.index('--configuration-sha256')+1] = '0'*64
        p = subprocess.run(argv, capture_output=True, timeout=15)
        self.assertEqual(p.returncode, 1); self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_foreign_intent_is_preserved_without_claim(self):
        p = self.output/'intent.json'; p.write_bytes(b'foreign evidence'); p.chmod(0o600)
        with self.assertRaisesRegex(PreexecDenied, 'EXISTING_INTENT_EVIDENCE_PRESERVED'): self.core().emit(True)
        self.assertEqual(p.read_bytes(), b'foreign evidence'); self.assertFalse((self.output/'issuance-claim.json').exists())
    def test_expiry_during_signing_retains_claim_without_publishing_intent(self):
        from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
        core = self.core(); original = ExistingEd25519Signer.sign
        def advancing(signer, raw):
            signature = original(signer, raw)
            core.clock = lambda: self.now+181; core.verifier.clock = core.clock
            return signature
        with patch.object(ExistingEd25519Signer, 'sign', advancing):
            with self.assertRaises(PreexecDenied): core.emit(True)
        self.assertTrue((self.output/'issuance-claim.json').exists()); self.assertFalse((self.output/'intent.json').exists())

if __name__ == '__main__': unittest.main()
