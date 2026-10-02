import contextlib
import copy
import io
import json
import os
from pathlib import Path
import ssl
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from scripts import prepare_semantic_provider_trust as module


@unittest.skipUnless(os.geteuid() == 0, 'mandatory CI runs private ownership/OpenSSL fixture as root')
class TrustPrepareTest(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get('OUF_TRUST_ROOT_FIXTURE_PARENT')
        if not parent: self.skipTest('explicit root-owned private fixture parent required')
        self.tmp = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.tmp.name)
        self.public = self.root/'public-ca.pem'
        module.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-x509', '-sha256', '-days', '2', '-keyout', str(self.root/'public-ca.key'),
                    '-out', str(self.public), '-subj', '/CN=synthetic-public-root',
                    '-addext', 'basicConstraints=critical,CA:TRUE'])
        self.args = module.parser().parse_args(['--mode', 'plan', '--gateway-container', 'gw',
            '--expected-gateway-id', 'a'*64, '--adapter-image-id', 'sha256:'+'b'*64,
            '--adapter-source-commit', 'c'*40, '--adapter-hostname', 'adapter.install.example',
            '--southbound-hostname', 'gateway.install.example', '--installation-id', 'fixture-install',
            '--adapter-uid', '10006', '--adapter-gid', '10006', '--ca-validity-days', '90',
            '--server-validity-days', '30', '--public-ca-file', str(self.public),
            '--snapshot-root', str(self.root/'trust')])
        self.gateway = {'id': 'a'*64, 'image': 'sha256:'+'d'*64, 'user': 'gateway-user', 'running': True}
        self.image = {'Id': 'sha256:'+'b'*64, 'Config': {'User': '10006:10006',
            'Entrypoint': ['python3', '-B', '-m', 'tools.semantic_provider_adapter'],
            'Labels': {'org.opencontainers.image.revision': 'c'*40,
                       'ouf.component': 'semantic-provider-transport', 'ouf.payload.sha256': 'e'*64}}}
        self.commands = []; real = module.run
        def command(args, **kwargs):
            self.commands.append(args)
            if args[0] != 'docker': return real(args, **kwargs)
            if args[1] == 'inspect': raw = json.dumps(self.gateway)
            elif args[1] == 'exec': raw = '10004\n'
            elif args[1:3] == ['image', 'inspect']: raw = json.dumps([self.image])
            else: self.fail('unexpected Docker mutation')
            return subprocess.CompletedProcess(args, 0, raw, '')
        self.patch = patch.object(module, 'run', side_effect=command); self.patch.start()

    def tearDown(self):
        self.patch.stop(); self.tmp.cleanup()

    def apply(self):
        self.args.mode = 'apply'; return module.operate(self.args)

    def test_plan_is_read_only_and_excludes_secret_inspect_fields(self):
        result = module.operate(self.args)
        self.assertFalse(result['verified']); self.assertFalse(self.args.snapshot_root.exists())
        inspect = next(c for c in self.commands if c[:2] == ['docker', 'inspect'])
        self.assertNotIn('.Config.Env', inspect[5]); self.assertNotIn('.Mounts', inspect[5])
        self.assertFalse(any(c[0] == 'openssl' and c[1] != 'version' for c in self.commands))
        self.assertFalse(any(c[0] == 'docker' and c[1] not in ('inspect', 'image', 'exec') for c in self.commands))

    @unittest.skipUnless(os.environ.get('OUF_TRUST_FULL_OWNER_TEST') == '1', 'mandatory CI verifies real runtime UID ownership')
    def test_real_tls_material_ownership_key_pair_and_verify(self):
        saved = self.apply(); self.assertTrue(saved['verified'])
        root = self.args.snapshot_root
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for role, uid in (('adapter', 10006), ('southbound', 10004)):
            for filename in ('server.key', 'server.crt', 'provider-receipt.key'):
                info = (root/role/filename).stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (uid, uid, 0o600))
        self.assertEqual((root/'adapter/provider-receipt.key').read_bytes(), (root/'southbound/provider-receipt.key').read_bytes())
        self.assertEqual((root/'ca.key').stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE((root/'ca.crt').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((root/'trust-bundle.pem').stat().st_mode), 0o644)
        ssl.create_default_context(cafile=str(root/'trust-bundle.pem'))
        # Actual local TLS using the prepared leaf/key/trust; no provider I/O.
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(root/'adapter/server.crt', root/'adapter/server.key')
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(3)
        failures = []
        def serve():
            try:
                for _ in range(2):
                    peer, _ = listener.accept(); peer.settimeout(3)
                    try:
                        with server_context.wrap_socket(peer, server_side=True) as tls:
                            if tls.recv(20) == b'fixture': tls.sendall(b'accepted')
                    except ssl.SSLError: peer.close()  # wrong-name client fails handshake
            except Exception as error: failures.append(type(error).__name__)
        worker = threading.Thread(target=serve, daemon=True); worker.start()
        try:
            client_context = ssl.create_default_context(cafile=str(root/'trust-bundle.pem'))
            with client_context.wrap_socket(socket.socket(), server_hostname=self.args.adapter_hostname) as tls:
                tls.settimeout(3); tls.connect(listener.getsockname()); tls.sendall(b'fixture')
                self.assertEqual(tls.recv(20), b'accepted')
            with client_context.wrap_socket(socket.socket(), server_hostname='wrong.example') as tls:
                tls.settimeout(3)
                with self.assertRaises(ssl.SSLCertVerificationError): tls.connect(listener.getsockname())
            worker.join(timeout=4); self.assertFalse(worker.is_alive()); self.assertEqual(failures, [])
        finally:
            listener.close(); worker.join(timeout=4)
        self.args.mode = 'verify'; before = len(self.commands)
        self.assertEqual(module.operate(self.args), saved)
        self.assertFalse(any('-newkey' in c or '-keyout' in c for c in self.commands[before:]))

    @unittest.skipUnless(os.environ.get('OUF_TRUST_FULL_OWNER_TEST') == '1', 'mandatory CI verifies real runtime UID ownership')
    def test_no_overwrite_apply_and_binding_drift(self):
        self.apply()
        with self.assertRaisesRegex(module.Blocked, 'TRUST_ROOT_EXISTS_RECONCILE'): module.operate(self.args)
        self.args.mode = 'verify'; self.args.adapter_hostname = 'different.install.example'
        with self.assertRaisesRegex(module.Blocked, 'TRUST_BINDING_OR_ROLE_DRIFT'): module.operate(self.args)

    def test_partial_generation_retains_intent_without_receipt(self):
        with patch.object(module, 'openssl', side_effect=module.Blocked('SYNTHETIC_FAILURE')):
            with self.assertRaisesRegex(module.Blocked, 'SYNTHETIC_FAILURE'): self.apply()
        self.assertTrue((self.args.snapshot_root/'trust-intent.json').exists())
        self.assertFalse((self.args.snapshot_root/'trust-receipt.json').exists())
        with self.assertRaisesRegex(module.Blocked, 'TRUST_ROOT_EXISTS_RECONCILE'): module.operate(self.args)

    @unittest.skipUnless(os.environ.get('OUF_TRUST_FULL_OWNER_TEST') == '1', 'mandatory CI verifies real runtime UID ownership')
    def test_private_pair_symlink_owner_and_content_drift(self):
        self.apply(); self.args.mode = 'verify'
        key = self.args.snapshot_root/'adapter/provider-receipt.key'
        original = key.read_bytes(); key.write_bytes(b'f'*64)
        with self.assertRaisesRegex(module.Blocked, 'PURPOSE_RECEIPT_KEY_PAIR_INVALID'): module.operate(self.args)
        key.write_bytes(original); os.chmod(key, 0o644)
        with self.assertRaisesRegex(module.Blocked, 'ARTIFACT_OWNER_OR_MODE_UNSAFE'): module.operate(self.args)
        os.chmod(key, 0o600); key.unlink(); key.symlink_to(self.args.snapshot_root/'southbound/provider-receipt.key')
        with self.assertRaises(OSError): module.operate(self.args)

    def test_ca_input_mode_private_key_and_role_drift(self):
        os.chmod(self.public, 0o666)
        with self.assertRaisesRegex(module.Blocked, 'ARTIFACT_OWNER_OR_MODE_UNSAFE'): module.operate(self.args)
        os.chmod(self.public, 0o600)
        original = self.public.read_bytes(); self.public.write_bytes(original+(self.root/'public-ca.key').read_bytes())
        with self.assertRaisesRegex(module.Blocked, 'PUBLIC_CA_INPUT_CONTAINS_PRIVATE_KEY'): module.operate(self.args)
        self.public.write_bytes(original); self.gateway['id'] = 'f'*64
        with self.assertRaisesRegex(module.Blocked, 'GATEWAY_ID_OR_RUNNING_MISMATCH'): module.operate(self.args)

    def test_safe_hostnames_image_uid_and_validity(self):
        original = copy.deepcopy(self.args)
        for value in ('x/extra', 'host\nDNS:other', '*.example', '-bad.example'):
            self.args.adapter_hostname = value
            with self.assertRaisesRegex(module.Blocked, 'EXPLICIT_SAFE_DNS_HOSTNAME_REQUIRED'): module.operate(self.args)
        self.args = original; self.image['Config']['User'] = '0:0'
        with self.assertRaisesRegex(module.Blocked, 'ADAPTER_IMAGE_CONTRACT_MISMATCH'): module.operate(self.args)
        self.image['Config']['User'] = '10006:10006'; self.args.server_validity_days = self.args.ca_validity_days
        with self.assertRaisesRegex(module.Blocked, 'BOUNDED_CERTIFICATE_VALIDITY_REQUIRED'): module.operate(self.args)

    def test_cli_errors_and_success_do_not_print_key_material(self):
        output = io.StringIO()
        argv = ['--mode', 'verify']
        with patch.object(module, 'parser') as parser:
            parser.return_value.parse_args.return_value = self.args
            with contextlib.redirect_stdout(output): self.assertEqual(module.main(argv), 0)
        self.assertNotIn('PRIVATE KEY', output.getvalue())
        self.assertNotIn('artifactHashes', output.getvalue())
        output = io.StringIO()
        with patch.object(module, 'parser') as parser, patch.object(module, 'operate', side_effect=ValueError('SECRET_TEST_VALUE')):
            parser.return_value.parse_args.return_value = self.args
            with contextlib.redirect_stdout(output): self.assertEqual(module.main(argv), 1)
        self.assertNotIn('SECRET_TEST_VALUE', output.getvalue())
        self.assertIn('TRUST_PREPARE_UNPROVEN', output.getvalue())


if __name__ == '__main__':
    unittest.main()
