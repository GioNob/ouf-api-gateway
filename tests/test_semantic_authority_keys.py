import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

@unittest.skipUnless(os.geteuid() == 0, 'Root private fixture; dedicated CI root job runs it')
class AuthorityKeyTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT', str(Path.cwd())))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'keys'
        self.root.mkdir(mode=448)
        self.inv = self.base / 'inv'
        self.inv.mkdir(mode=448)
        self.source = self.base / 'helper.py'
        self.source.write_bytes((Path(__file__).parents[1] / 'scripts/prepare_semantic_authority_keys.py').read_bytes())
        self.source.chmod(384)
        spec = importlib.util.spec_from_file_location('key_fixture', self.source)
        self.h = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.h)
        d = {'installationRef': 'ouf-lab-netcup-01'}
        p = {'schema': 'ouf.semantic-deployment-authority-provisioning-plan.v1', 'installationRef': d['installationRef'], 'entityRef': None, 'state': 'DRAFT_NOT_AUTHORIZED', 'trustPolicyProvisioned': False, 'startAuthorized': False}
        self.write('target-dossier.json', d)
        self.write('authority-plan.json', p)
        dh = self.h.digest(self.h.encoded(d))
        ah = self.h.digest(self.h.encoded(p))
        r = {'schema': 'ouf.semantic-target-acceptance-inventory.v1', 'dossierHash': dh, 'authorityPlanHash': ah, 'sourcePackageReceiptHash': 'b' * 64, 'candidateCount': 2, 'mountCount': 8}
        r.update({k: True for k in ('candidatesNeverStarted', 'sourceCustodyVerified', 'stableAcrossReads', 'readOnlyTarget', 'privateEvidenceOnly')})
        r.update({k: False for k in ('deploymentAuthorityProven', 'startAuthorized', 'runtimeRegistrationAuthorized', 'environmentRead', 'mountContentsRead', 'rulesChanged', 'unitsChanged', 'containersChanged')})
        r.update({k: 0 for k in ('keysGenerated', 'signaturesIssued', 'providerCalls', 'dnsCalls', 'iamCalls', 'privateKeysRead')})
        self.write('inventory-receipt.json', r)
        self.a = argparse.Namespace(mode='plan', inventory_root=self.inv, snapshot_root=self.root, openssl_path=Path('/usr/bin/openssl'), openssl_sha256=hashlib.sha256(Path('/usr/bin/openssl').read_bytes()).hexdigest(), source_sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(), source_commit='a' * 40, dossier_sha256=dh, authority_plan_sha256=ah, package_receipt_sha256='b' * 64, installation_ref='ouf-lab-netcup-01', entity_ref='ouf-lab', installer_issuer_ref='ouf-lab-infrastructure-installer', attestor_issuer_ref='ouf-lab-node-attestor', installer_key_ref='ouf-lab-installer-ed25519-1', attestor_key_ref='ouf-lab-attestor-ed25519-1', authorize_key_generation_only=True)

    def write(self, n, v):
        p = self.inv / n
        p.write_bytes(self.h.encoded(v))
        p.chmod(384)

    def runmode(self, m):
        self.a.mode = m
        return self.h.execute(self.a)

    def cli(self, m):
        v = ['python3', '-I', '-B', str(self.source), '--mode', m]
        for k, x in vars(self.a).items():
            if k == 'mode':
                continue
            if k == 'authorize_key_generation_only':
                if x:
                    v.append('--authorize-key-generation-only')
            else:
                v.extend(['--' + k.replace('_', '-'), str(x)])
        return v

    def test_plan_without_command_or_output(self):
        with mock.patch.object(self.h, 'command', side_effect=AssertionError('plan command')):
            r = self.runmode('plan')
        self.assertEqual(r['keysGenerated'], 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_real_apply_verify_and_no_replay(self):
        r = self.runmode('apply')
        self.assertEqual(r['keysGenerated'], 2)
        self.assertEqual(r['selfTestSignaturesIssued'], 2)
        before = {n: self.h.digest(self.h.private(self.root / n)) for n in self.h.FILES}
        r = self.runmode('verify')
        self.assertEqual(r['keysGenerated'], 0)
        self.assertEqual(r['selfTestSignaturesIssued'], 0)
        self.assertEqual(before, {n: self.h.digest(self.h.private(self.root / n)) for n in self.h.FILES})
        d = json.loads((self.root / 'authority-draft.json').read_bytes())
        self.assertFalse(d['trustPolicyProvisioned'])
        self.assertNotEqual(d['keys'][0]['publicKey'], d['keys'][1]['publicKey'])
        for n in self.h.FILES:
            self.assertEqual((self.root / n).stat().st_mode & 511, 384)
        with self.assertRaisesRegex(self.h.Blocked, 'EXISTING_OR_PARTIAL_CUSTODY_NO_REPLAY'):
            self.runmode('apply')

    def test_explicit_authorization_required(self):
        self.a.authorize_key_generation_only = False
        with self.assertRaisesRegex(self.h.Blocked, 'EXPLICIT_KEY_CUSTODY_AUTHORIZATION_REQUIRED'):
            self.runmode('apply')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_separate_identity_keys_and_backend_hash(self):
        self.a.attestor_key_ref = self.a.installer_key_ref
        with self.assertRaisesRegex(self.h.Blocked, 'SEPARATE_INSTALLER_ATTESTOR_REQUIRED'):
            self.runmode('apply')
        self.a.attestor_key_ref = 'attestor'
        self.a.entity_ref = '../bad'
        with self.assertRaises(self.h.Blocked):
            self.runmode('apply')
        self.a.entity_ref = 'ouf-lab'
        self.a.openssl_sha256 = '0' * 64
        with self.assertRaisesRegex(self.h.Blocked, 'OPENSSL_HASH_DRIFT'):
            self.runmode('apply')

    def test_inventory_receipt_and_source_hash_drift(self):
        self.a.source_sha256 = '0' * 64
        with self.assertRaisesRegex(self.h.Blocked, 'HELPER_SOURCE_DRIFT'):
            self.runmode('apply')
        self.a.source_sha256 = self.h.digest(self.source.read_bytes())
        r = json.loads((self.inv / 'inventory-receipt.json').read_bytes())
        r['startAuthorized'] = True
        self.write('inventory-receipt.json', r)
        with self.assertRaisesRegex(self.h.Blocked, 'COMPLETED_PRIVATE_INVENTORY_REQUIRED'):
            self.runmode('apply')

    def test_concurrent_directory_lock(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = subprocess.run(self.cli('apply'), capture_output=True, timeout=10)
            self.assertEqual(r.returncode, 1)
            self.assertIn(b'KEY_CUSTODY_LOCK_BUSY', r.stdout)
            self.assertEqual(list(self.root.iterdir()), [])
        finally:
            os.close(fd)

    def test_partial_crash_no_receipt_or_replay(self):
        original = self.h.command

        def fail(argv, *a, **kw):
            if 'pkey' in argv:
                raise self.h.Blocked('INJECTED_FAILURE')
            return original(argv, *a, **kw)
        with mock.patch.object(self.h, 'command', side_effect=fail):
            with self.assertRaises(self.h.Blocked):
                self.runmode('apply')
        self.assertTrue((self.root / 'installer.pem').exists())
        self.assertFalse((self.root / 'key-custody-receipt.json').exists())
        with self.assertRaisesRegex(self.h.Blocked, 'EXISTING_OR_PARTIAL_CUSTODY_NO_REPLAY'):
            self.runmode('apply')
        with self.assertRaises(OSError):
            self.runmode('verify')

    def test_private_permissions_symlink_hardlink(self):
        p = self.inv / 'target-dossier.json'
        raw = p.read_bytes()
        p.chmod(420)
        with self.assertRaisesRegex(self.h.Blocked, 'PRIVATE_FILE_REQUIRED'):
            self.runmode('plan')
        p.chmod(384)
        other = self.inv / 'other'
        os.link(p, other)
        with self.assertRaises(self.h.Blocked):
            self.runmode('plan')
        other.unlink()
        p.unlink()
        other.write_bytes(raw)
        other.chmod(384)
        p.symlink_to(other)
        with self.assertRaises(OSError):
            self.runmode('plan')

    def test_signature_corruption_and_active_draft(self):
        self.runmode('apply')
        p = self.root / 'installer.self-test.sig'
        raw = p.read_bytes()
        p.write_bytes(b'x' * 64)
        with self.assertRaises(self.h.Blocked):
            self.runmode('verify')
        p.write_bytes(raw)
        p = self.root / 'authority-draft.json'
        d = json.loads(p.read_bytes())
        d['trustPolicyProvisioned'] = True
        p.write_bytes(self.h.encoded(d))
        with self.assertRaises(self.h.Blocked):
            self.runmode('verify')

    def test_public_private_drift_even_with_rewritten_receipt(self):
        self.runmode('apply')
        (self.root / 'installer.der').write_bytes((self.root / 'attestor.der').read_bytes())
        p = self.root / 'key-custody-receipt.json'
        r = json.loads(p.read_bytes())
        r['outputHashes']['installer.der'] = self.h.digest(self.h.private(self.root / 'installer.der'))
        p.write_bytes(self.h.encoded(r))
        with self.assertRaisesRegex(self.h.Blocked, 'PUBLIC_PRIVATE_KEY_DRIFT'):
            self.runmode('verify')

    def test_cli_redaction_and_verify_no_signing(self):
        r = subprocess.run(self.cli('apply'), capture_output=True, timeout=15)
        self.assertEqual(r.returncode, 0, r.stdout.decode())
        self.assertNotIn(b'PRIVATE KEY', r.stdout + r.stderr)
        for role in ('installer', 'attestor'):
            self.assertTrue((self.root / (role + '.pem')).read_bytes() not in r.stdout + r.stderr)
        original = self.h.command

        def no_sign(argv, *a, **kw):
            self.assertNotIn('genpkey', argv)
            self.assertNotIn('-sign', argv)
            return original(argv, *a, **kw)
        with mock.patch.object(self.h, 'command', side_effect=no_sign):
            self.runmode('verify')

    def test_commands_timeout_output_limit_nonzero(self):
        for argv, budget, reason in [(['python3', '-c', 'import time;time.sleep(2)'], 0.05, 'COMMAND_DEADLINE'), (['python3', '-c', 'print("x"*9000)'], 3, 'COMMAND_OUTPUT_LIMIT'), (['python3', '-c', 'raise SystemExit(2)'], 3, 'COMMAND_FAILED')]:
            with self.assertRaisesRegex(self.h.Blocked, reason):
                self.h.command(argv, time.monotonic() + budget)

    def test_input_drift_no_completion_marker(self):
        original = self.h.inputs
        calls = []

        def drift(a):
            r = original(a)
            calls.append(1)
            return {**r, 'target-dossier.json': b'altered'} if len(calls) > 1 else r
        with mock.patch.object(self.h, 'inputs', side_effect=drift):
            with self.assertRaisesRegex(self.h.Blocked, 'INPUT_DRIFT'):
                self.runmode('apply')
        self.assertFalse((self.root / 'key-custody-receipt.json').exists())

    def test_snapshot_directory_permissions_and_expired_draft(self):
        self.root.chmod(493)
        with self.assertRaisesRegex(self.h.Blocked, 'PRIVATE_DIRECTORY_REQUIRED'):
            self.runmode('apply')
        self.root.chmod(448)
        self.runmode('apply')
        with mock.patch.object(self.h.time, 'time', return_value=time.time() + 91 * 86400):
            with self.assertRaisesRegex(self.h.Blocked, 'PROPOSED_VALIDITY_EXPIRED_OR_CLOCK_REGRESSED'):
                self.runmode('verify')

    def test_helper_source_changed_before_receipt(self):
        original = self.h.inputs
        calls = []

        def drift(a):
            r = original(a)
            calls.append(1)
            if len(calls) > 1:
                self.source.write_bytes(self.source.read_bytes() + b'\n# altered')
            return r
        with mock.patch.object(self.h, 'inputs', side_effect=drift):
            with self.assertRaisesRegex(self.h.Blocked, 'INPUT_DRIFT'):
                self.runmode('apply')
        self.assertFalse((self.root / 'key-custody-receipt.json').exists())
    def test_directory_enumeration_is_bounded(self):
        for i in range(12):
            (self.root / ('unexpected-' + str(i))).touch()
        with self.assertRaisesRegex(self.h.Blocked, 'UNEXPECTED_PRIVATE_OUTPUT_NO_REPLAY'):
            self.runmode('plan')

    def test_draft_is_rejected_by_operational_policy_parser(self):
        from tools.semantic_provider_deployment_authentication import policy
        from tools.semantic_provider_preexec import PreexecDenied
        self.runmode('apply')
        raw = self.h.private(self.root / 'authority-draft.json')
        with self.assertRaises(PreexecDenied):
            policy(raw, self.a.installation_ref, self.a.entity_ref, int(time.time()))

if __name__ == '__main__':
    unittest.main()
