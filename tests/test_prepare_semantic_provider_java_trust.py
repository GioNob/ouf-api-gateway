import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from scripts import prepare_semantic_provider_java_trust as module
from scripts import prepare_semantic_provider_trust as trust
from scripts import prepare_semantic_provider_tls_runtime as tls
from tests import test_prepare_semantic_provider_tls_runtime as tls_fixture


class PublicStoreBoundaryTest(unittest.TestCase):
    def test_empty_private_key_and_key_entry_outputs_rejected(self):
        for raw in (b'', b'-----BEGIN PRIVATE KEY-----', b'PrivateKeyEntry', b'SecretKeyEntry', b'x'*2097153):
            with self.assertRaises(trust.Blocked): module.cert_set(raw)


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('OUF_JAVA_TRUST_DOCKER_TEST') == '1',
                     'mandatory CI runs real image keytool and private ownership fixture as root')
class JavaTrustPrepareTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('docker') or not shutil.which('java'): raise RuntimeError('mandatory real Docker/Java tools missing')
        cls.tag = 'ouf-java-trust-fixture:'+uuid.uuid4().hex
        source_image = os.environ['OUF_JAVA_TRUST_IMAGE']
        # CI pulls the fixture JRE once; build uses its immutable local ID, no network.
        image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', source_image], text=True).strip()
        source = 'FROM '+source_image+'\nUSER 10001:10001\nLABEL org.opencontainers.image.revision="'+('d'*40)+'"\n'
        subprocess.run(['docker', 'build', '--network=none', '--pull=false', '-t', cls.tag, '-'], input=source,
                       text=True, capture_output=True, check=True, timeout=120)
        cls.image = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', cls.tag], text=True).strip()
        original_layers = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{json .RootFS.Layers}}', image_id], text=True)
        fixture_layers = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{json .RootFS.Layers}}', cls.image], text=True)
        if original_layers != fixture_layers: raise RuntimeError('fixture base image changed during local build')

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['docker', 'image', 'rm', cls.tag], capture_output=True, check=True, timeout=30)

    def setUp(self):
        self.tls_fixture = tls_fixture.TLSRuntimePrepareTest('test_private_runtime_ownership_existing_leaf_serialization_and_verify')
        self.tls_fixture.setUp(); self.addCleanup(self.tls_fixture.doCleanups)
        self.tls_fixture.args.mode = 'apply'; tls.operate(self.tls_fixture.args)
        # Trust/TLS fixture setup mocks only old role metadata; Java work below is real Docker.
        self.tls_fixture.fixture.patch.stop()
        root = self.tls_fixture.fixture.root
        self.role_name = 'ouf-java-role-fixture-'+uuid.uuid4().hex
        role_id = subprocess.check_output(['docker', 'run', '-d', '--name', self.role_name, '--network', 'none',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--entrypoint', '/bin/sh',
            self.image, '-c', 'while :; do sleep 30; done'], text=True).strip()
        self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', self.role_name], capture_output=True, check=True, timeout=30))
        self.args = SimpleNamespace(mode='plan', trust_root=self.tls_fixture.args.trust_root,
            tls_runtime_root=self.tls_fixture.args.snapshot_root, snapshot_root=root/'java-trust',
            semantic_container=self.role_name, expected_semantic_id=role_id, semantic_image_id=self.image,
            semantic_source_commit='d'*40, java_home='/opt/java/openjdk',
            runtime_truststore_path='/run/fixture-semantic/java-truststore.p12', docker_path='docker', openssl_path='openssl')

    def apply(self):
        self.args.mode = 'apply'; return module.operate(self.args)

    def test_plan_only_readonly_metadata_public_ca_and_leaf_no_private_key_reads(self):
        reads = []; commands = []; real_read = trust.read_file; real_run = trust.run
        def read(path, *args, **kwargs):
            reads.append(str(path)); return real_read(path, *args, **kwargs)
        def run(command, **kwargs):
            commands.append(command); return real_run(command, **kwargs)
        with patch.object(trust, 'read_file', side_effect=read), patch.object(trust, 'run', side_effect=run), \
                patch.object(module, 'create_store', side_effect=AssertionError('plan cannot create helper container')):
            value = module.operate(self.args)
        self.assertFalse(self.args.snapshot_root.exists()); self.assertEqual(value['semantic']['uid'], 10001)
        self.assertFalse(any(p.endswith('.key') or p.endswith('apisix.yaml') for p in reads))
        self.assertTrue(all(c[0] == 'openssl' or c[1] in ('inspect', 'exec', 'image') for c in commands))

    def test_real_image_keytool_preserves_roots_ownership_readback_no_overwrite_and_cleanup(self):
        value = self.apply(); root = self.args.snapshot_root
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for name, uid in [('java-truststore.p12', 10001), ('java-trust-options.json', 10001),
                          ('baseline.pem', 0), ('merged.pem', 0), ('java-trust-intent.json', 0), ('java-trust-receipt.json', 0)]:
            info = (root/name).stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (uid, uid, 0o600))
        saved = json.loads((root/'java-trust-receipt.json').read_bytes())
        self.assertTrue(saved['publicRootsPreserved']); self.assertTrue(saved['keytoolContainerCleanupProven'])
        self.assertGreater(len(saved['outputs']['baselineCertificateHashes']), 20)
        self.assertEqual(len(saved['outputs']['mergedCertificateHashes']), len(saved['outputs']['baselineCertificateHashes'])+1)
        self.args.mode = 'verify'; self.assertEqual(module.operate(self.args), value)
        with (root/'java-truststore.p12').open('ab') as stream: stream.write(b'altered')
        with self.assertRaises(trust.Blocked): module.operate(self.args)
        self.args.mode = 'apply'
        with self.assertRaisesRegex(trust.Blocked, 'JAVA_TRUST_ROOT_EXISTS_RECONCILE'): module.operate(self.args)
        remaining = subprocess.check_output(['docker', 'ps', '-a', '--filter', 'name=ouf-java-trust-prepare-', '--format', '{{.ID}}'], text=True)
        self.assertEqual(remaining.strip(), '')

    def test_role_and_ca_binding_drift_and_partial_failure_retained(self):
        self.args.expected_semantic_id = 'f'*64
        with self.assertRaises(trust.Blocked): module.operate(self.args)
        self.args.expected_semantic_id = subprocess.check_output(['docker', 'inspect', '--format', '{{.Id}}', self.role_name], text=True).strip()
        ca = self.args.trust_root/'ca.crt'; original = ca.read_bytes(); ca.write_bytes(original+b'\n')
        with self.assertRaisesRegex(trust.Blocked, 'PUBLIC_TRUST_ARTIFACT_DRIFT'): module.operate(self.args)
        ca.write_bytes(original); self.args.mode = 'apply'
        with patch.object(module, 'create_store', side_effect=trust.Blocked('SYNTHETIC_KEYTOOL_FAILURE')):
            with self.assertRaises(trust.Blocked): module.operate(self.args)
        self.assertTrue((self.args.snapshot_root/'java-trust-intent.json').exists())
        self.assertFalse((self.args.snapshot_root/'java-trust-receipt.json').exists())
        with self.assertRaisesRegex(trust.Blocked, 'JAVA_TRUST_ROOT_EXISTS_RECONCILE'): module.operate(self.args)

    def test_cli_redacts_raw_errors(self):
        output = io.StringIO()
        argv = ['--mode', 'plan']
        for name in ('trust_root', 'tls_runtime_root', 'snapshot_root', 'semantic_container', 'expected_semantic_id',
                     'semantic_image_id', 'semantic_source_commit', 'java_home', 'runtime_truststore_path'):
            argv += ['--'+name.replace('_', '-'), str(getattr(self.args, name))]
        with patch.object(module, 'operate', side_effect=RuntimeError('PRIVATE-DATA-DO-NOT-PRINT')), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit): module.main(argv)
        self.assertNotIn('PRIVATE-DATA', output.getvalue()); self.assertIn('NO_SECRETS_PRINTED=true', output.getvalue())

    def test_java21_httpclient_trusts_internal_ca_and_rejects_wrong_hostname_and_missing_ca(self):
        self.apply(); root = self.tls_fixture.fixture.root
        key = root/'java-fixture.key'; cert = root/'java-fixture.crt'; csr = root/'java-fixture.csr'; ext = root/'java-fixture.ext'
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(key), '-out', str(csr), '-subj', '/CN=localhost'], capture_output=True, check=True)
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
        subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(self.args.trust_root/'ca.crt'),
            '-CAkey', str(self.args.trust_root/'ca.key'), '-set_serial', '9001', '-days', '1', '-sha256',
            '-extfile', str(ext), '-out', str(cert)], capture_output=True, check=True)
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path); body = b'fixture-only'
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        source = root/'JavaTrustProbe.java'
        source.write_text('''import java.net.URI; import java.net.http.*; import java.time.Duration;
class JavaTrustProbe { public static void main(String[] a) throws Exception {
  try { var h=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    var r=h.send(HttpRequest.newBuilder(URI.create(a[0])).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.ofString());
    if (!a[1].equals("accept") || r.statusCode()!=200 || !r.body().equals("fixture-only")) throw new AssertionError("unexpected acceptance");
    System.out.println("JAVA_TLS_ACCEPT");
  } catch (javax.net.ssl.SSLHandshakeException e) {
    if (!a[1].equals("deny")) throw e; System.out.println("JAVA_TLS_DENY");
  }
}}''')
        opts = ['-Djavax.net.ssl.trustStore='+str(self.args.snapshot_root/'java-truststore.p12'),
            '-Djavax.net.ssl.trustStoreType=PKCS12', '-Djavax.net.ssl.trustStorePassword=changeit']
        port = server.server_port
        for host, options, expected in [('localhost', opts, 'accept'), ('127.0.0.1', opts, 'deny'), ('localhost', [], 'deny')]:
            result = subprocess.run(['java', *options, str(source), 'https://'+host+':'+str(port)+'/fixture', expected],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr[-1500:])
            self.assertIn('JAVA_TLS_'+('ACCEPT' if expected=='accept' else 'DENY'), result.stdout)
        self.assertEqual(requests, ['/fixture'])
        print('SEMANTIC_JAVA_TRUST_CI=PASS REAL_IMAGE_KEYTOOL=true PUBLIC_ROOTS_PRESERVED=true JAVA21_HTTPCLIENT=true '
              'CORRECT_HOST_ACCEPTED=true WRONG_HOST_AND_MISSING_CA_DENIED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')


if __name__ == '__main__': unittest.main()
