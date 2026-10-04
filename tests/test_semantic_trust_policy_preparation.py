import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest import mock
from tests import test_semantic_authority_keys as key_fixture

@unittest.skipUnless(os.geteuid() == 0, 'Root custody fixture; dedicated CI root job runs it')
class PrivatePolicyTest(unittest.TestCase):

    def setUp(self):
        self.f = key_fixture.AuthorityKeyTest(methodName='test_plan_without_command_or_output')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.runmode('apply')
        self.root = self.f.base / 'policy'
        self.root.mkdir(mode=448)
        self.source = self.f.base / 'policy-helper.py'
        self.source.write_bytes((Path(__file__).parents[1] / 'scripts/prepare_semantic_trust_policy.py').read_bytes())
        self.source.chmod(384)
        spec = importlib.util.spec_from_file_location('policy_fixture', self.source)
        self.h = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.h)
        self.validators = self.f.base / 'validators'
        self.validators.mkdir(mode=448)
        for n in ('authentication', 'protocol'):
            name = 'semantic_provider_deployment_' + n + '.py'
            p = self.validators / name
            p.write_bytes((Path(__file__).parents[1] / 'tools' / name).read_bytes())
            p.chmod(384)
        self.a = argparse.Namespace(**vars(self.f.a))
        del self.a.authorize_key_generation_only
        self.a.mode = 'plan'
        self.a.snapshot_root = self.root
        self.a.helper_source = self.f.source
        self.a.helper_sha256 = self.f.a.source_sha256
        self.a.source_sha256 = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.a.custody_root = self.f.root
        self.a.custody_source_commit = self.f.a.source_commit
        self.a.validator_source_root = self.validators
        self.a.auth_source_sha256 = self.f.h.digest((self.validators / 'semantic_provider_deployment_authentication.py').read_bytes())
        self.a.protocol_source_sha256 = self.f.h.digest((self.validators / 'semantic_provider_deployment_protocol.py').read_bytes())
        self.a.custody_receipt_sha256 = self.f.h.digest((self.f.root / 'key-custody-receipt.json').read_bytes())
        self.a.draft_sha256 = self.f.h.digest((self.f.root / 'authority-draft.json').read_bytes())
        self.a.authorize_private_role_policy_only = True

    def runmode(self, m):
        self.a.mode = m
        return self.h.execute(self.a)

    def cli(self, m):
        args = ['python3', '-I', '-B', str(self.source), '--mode', m]
        for k, v in vars(self.a).items():
            if k == 'mode':
                continue
            if k == 'authorize_private_role_policy_only':
                if v:
                    args.append('--authorize-private-role-policy-only')
            else:
                args.extend(['--' + k.replace('_', '-'), str(v)])
        return args

    def test_real_policy_dates_roles_and_replay(self):
        before = {n: self.f.h.digest((self.f.root / n).read_bytes()) for n in self.f.h.FILES}
        r = self.runmode('plan')
        self.assertFalse(r['policyActiveInArtifact'])
        self.assertEqual(list(self.root.iterdir()), [])
        r = self.runmode('apply')
        self.assertTrue(r['realPolicyParserValidated'])
        self.assertEqual(r['privateKeysRead'], 0)
        p = json.loads((self.root / 'trust-policy.json').read_bytes())
        d = json.loads((self.f.root / 'authority-draft.json').read_bytes())
        self.assertEqual([k['roles'] for k in p['keys']], [['DEPLOYMENT_INTENT', 'FINAL_DEPLOYMENT_APPROVAL'], ['CREATION_ATTESTATION']])
        self.assertEqual(p['keys'][0]['notBefore'], d['proposedNotBefore'])
        self.assertEqual(p['keys'][0]['expiresAt'], d['proposedExpiresAt'])
        hashes = {n: self.f.h.digest((self.root / n).read_bytes()) for n in ('trust-policy.json', 'policy-preparation-receipt.json')}
        self.runmode('verify')
        self.assertEqual(hashes, {n: self.f.h.digest((self.root / n).read_bytes()) for n in hashes})
        self.assertEqual(before, {n: self.f.h.digest((self.f.root / n).read_bytes()) for n in self.f.h.FILES})
        with self.assertRaisesRegex(ValueError, 'EXISTING_OR_PARTIAL_POLICY_NO_REPLAY'):
            self.runmode('apply')

    def test_never_reads_pem_or_generates_or_signs(self):
        original = self.h.load_helper

        def load(*args):
            h, raw = original(*args)
            private = h.private
            command = h.command

            def safe_private(path):
                self.assertFalse(str(path).endswith('.pem'))
                return private(path)

            def safe_command(argv, *a, **kw):
                self.assertNotIn('genpkey', argv)
                self.assertNotIn('-sign', argv)
                return command(argv, *a, **kw)
            h.private = safe_private
            h.command = safe_command
            return (h, raw)
        with mock.patch.object(self.h, 'load_helper', side_effect=load):
            self.runmode('apply')
            self.runmode('verify')

    def test_authorization_and_identity_binding(self):
        self.a.authorize_private_role_policy_only = False
        with self.assertRaises(ValueError):
            self.runmode('apply')
        self.a.authorize_private_role_policy_only = True
        self.a.entity_ref = 'wrong'
        with self.assertRaises(ValueError):
            self.runmode('apply')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_receipt_draft_validator_helper_backend_hashes(self):
        for name in ('custody_receipt_sha256', 'draft_sha256', 'auth_source_sha256', 'protocol_source_sha256', 'helper_sha256', 'openssl_sha256'):
            old = getattr(self.a, name)
            setattr(self.a, name, '0' * 64)
            with self.assertRaises(ValueError):
                self.runmode('apply')
            setattr(self.a, name, old)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_original_validity_not_renewed(self):
        with mock.patch.object(self.h.time, 'time', return_value=time.time() + 91 * 86400):
            with self.assertRaisesRegex(ValueError, 'ORIGINAL_PROPOSED_VALIDITY_REQUIRED'):
                self.runmode('apply')

    def test_policy_parser_parity_on_real_schema_and_bad_role(self):
        from tools.semantic_provider_deployment_authentication import policy
        from tools.semantic_provider_preexec import PreexecDenied
        self.runmode('apply')
        raw = (self.root / 'trust-policy.json').read_bytes()
        h, _ = self.h.load_helper(self.a.helper_source, self.a.helper_sha256)
        parse, _, _ = self.h.validator(h, self.validators, self.a.auth_source_sha256, self.a.protocol_source_sha256)
        self.assertEqual(policy(raw, self.a.installation_ref, self.a.entity_ref, int(time.time())), parse(raw, self.a.installation_ref, self.a.entity_ref, int(time.time())))
        d = json.loads(raw)
        d['keys'][0]['roles'] = ['RUNTIME_START']
        raw = h.encoded(d)
        with self.assertRaises(PreexecDenied):
            policy(raw, self.a.installation_ref, self.a.entity_ref, int(time.time()))
        with self.assertRaises(h.Blocked):
            parse(raw, self.a.installation_ref, self.a.entity_ref, int(time.time()))

    def test_corrupt_signature_public_key_blocks(self):
        p = self.f.root / 'installer.self-test.sig'
        p.write_bytes(b'x' * 64)
        with self.assertRaises(ValueError):
            self.runmode('apply')

    def test_partial_publication_is_preserved_no_replay(self):
        load = self.h.load_helper

        def fail(*args):
            h, raw = load(*args)
            exclusive = h.exclusive

            def publish(root, name, **kw):
                if name == 'policy-preparation-receipt.json':
                    raise h.Blocked('INJECTED_FAILURE')
                return exclusive(root, name, **kw)
            h.exclusive = publish
            return (h, raw)
        with mock.patch.object(self.h, 'load_helper', side_effect=fail):
            with self.assertRaises(ValueError):
                self.runmode('apply')
        self.assertTrue((self.root / 'trust-policy.json').exists())
        self.assertFalse((self.root / 'policy-preparation-receipt.json').exists())
        with self.assertRaisesRegex(ValueError, 'EXISTING_OR_PARTIAL_POLICY_NO_REPLAY'):
            self.runmode('apply')

    def test_policy_drift_and_linked_receipt_rejected(self):
        self.runmode('apply')
        p = self.root / 'policy-preparation-receipt.json'
        r = json.loads(p.read_bytes())
        r['policyConsumerLinked'] = True
        p.write_bytes(self.f.h.encoded(r))
        with self.assertRaisesRegex(ValueError, 'EXACT_PRIVATE_POLICY_READBACK_REQUIRED'):
            self.runmode('verify')

    def test_policy_snapshot_separate_from_custody(self):
        self.a.snapshot_root = self.f.root
        with self.assertRaisesRegex(ValueError, 'SEPARATE_POLICY_SNAPSHOT_REQUIRED'):
            self.runmode('apply')

    def test_source_drift_before_receipt(self):
        original = self.h.load_helper

        def load(*args):
            h, raw = original(*args)
            exclusive = h.exclusive

            def publish(root, name, **kw):
                v = exclusive(root, name, **kw)
                if name == 'trust-policy.json':
                    self.source.write_bytes(self.source.read_bytes() + b'\n# drift')
                return v
            h.exclusive = publish
            return (h, raw)
        with mock.patch.object(self.h, 'load_helper', side_effect=load):
            with self.assertRaisesRegex(ValueError, 'POLICY_INPUT_READBACK_DRIFT'):
                self.runmode('apply')
        self.assertFalse((self.root / 'policy-preparation-receipt.json').exists())

    def test_cli_hermetic_output_no_public_or_private_key_values(self):
        r = subprocess.run(self.cli('apply'), capture_output=True, timeout=15)
        self.assertEqual(r.returncode, 0, r.stdout.decode())
        self.assertNotIn(b'PRIVATE KEY', r.stdout + r.stderr)
        d = json.loads((self.f.root / 'authority-draft.json').read_bytes())
        for k in d['keys']:
            self.assertNotIn(k['publicKey'].encode(), r.stdout + r.stderr)

    def test_policy_directory_lock_from_another_process(self):
        import fcntl
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = subprocess.run(self.cli('apply'), capture_output=True, timeout=15)
            self.assertEqual(r.returncode, 1)
            self.assertIn(b'POLICY_LOCK_BUSY', r.stdout)
            self.assertEqual(list(self.root.iterdir()), [])
        finally:
            os.close(fd)

    def test_private_permissions_and_duplicate_parser_fields(self):
        p = self.f.root / 'installer.der'
        p.chmod(420)
        with self.assertRaises(ValueError):
            self.runmode('apply')
        p.chmod(384)
        h, _ = self.h.load_helper(self.a.helper_source, self.a.helper_sha256)
        parse, _, _ = self.h.validator(h, self.validators, self.a.auth_source_sha256, self.a.protocol_source_sha256)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_AUTHENTICATION_KEY'):
            parse(b'{"schema":"x","schema":"y"}', self.a.installation_ref, self.a.entity_ref, int(time.time()))

    def test_expiry_not_extended_by_rewritten_policy_receipt(self):
        self.runmode('apply')
        p = self.root / 'trust-policy.json'
        d = json.loads(p.read_bytes())
        d['keys'][0]['expiresAt'] += 86400
        p.write_bytes(self.f.h.encoded(d))
        p = self.root / 'policy-preparation-receipt.json'
        r = json.loads(p.read_bytes())
        r['policyHash'] = self.f.h.digest((self.root / 'trust-policy.json').read_bytes())
        p.write_bytes(self.f.h.encoded(r))
        with self.assertRaisesRegex(ValueError, 'EXACT_PRIVATE_POLICY_READBACK_REQUIRED'):
            self.runmode('verify')
if __name__ == '__main__':
    unittest.main()
