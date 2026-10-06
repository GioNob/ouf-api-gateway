"""Real minimal OCI packaging/start/TLS/admission gate; no provider request.

Host networking is confined to this fixture and proves no egress isolation.
The valid receipt intentionally wraps rejected grammar, keeping provider I/O inert.
"""
from dataclasses import asdict
import hashlib
import http.client
import json
import os
import re
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest

from scripts import stage_semantic_provider_adapter as stage
from tests.test_semantic_provider_adapter import binding, claims, signed, KEY
from tools.semantic_provider_admission import HEADER


@unittest.skipUnless(os.environ.get('OUF_PROVIDER_CONTAINER_TEST') == '1', 'requires mandatory Docker packaging job')
class ProviderContainerTest(unittest.TestCase):
    def test_digest_pinned_minimal_image_nonroot_readonly_tls_and_admission(self):
        repository = Path(__file__).resolve().parents[1]
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository, text=True).strip()
        requested = os.environ.get('OUF_PROVIDER_TEST_BASE_IMAGE', 'python:3.13-slim')
        if 'OUF_PROVIDER_TEST_BASE_IMAGE' in os.environ:
            self.assertRegex(requested, r'^python@sha256:[0-9a-f]{64}$')
        subprocess.run(['docker', 'pull', '--platform=linux/amd64', requested], check=True, capture_output=True, timeout=180)
        base_info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', requested], text=True))[0]
        base = requested if '@sha256:' in requested else base_info['RepoDigests'][0]
        tag = 'ouf-provider-package-ci:'+revision[:12]; name = 'ouf-provider-package-ci-'+str(os.getpid())
        final_image = os.environ.get('OUF_PROVIDER_TEST_FINAL_IMAGE')
        if final_image is not None:
            self.assertRegex(final_image, r'^sha256:[0-9a-f]{64}$')
            tag = final_image
        uid = gid = 10006  # isolated fixture inputs, not installation defaults
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); context = root/'context'; context.mkdir(mode=0o700)
            for relative, expected in stage.PAYLOAD_HASHES.items():
                raw = (repository/relative).read_bytes(); self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                target = context/relative; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(raw); target.chmod(0o600)
            build = ['docker', 'build', '--network=none', '--pull=false', '--file', str(context/'Dockerfile.semantic-provider'), '--tag', tag]
            for key, value in {'PYTHON_BASE_IMAGE': base, 'SOURCE_REVISION': revision, 'PAYLOAD_SHA256': stage.digest(stage.PAYLOAD_HASHES),
                               'RUNTIME_UID': uid, 'RUNTIME_GID': gid}.items(): build.extend(['--build-arg', key+'='+str(value)])
            build.append(str(context))
            if final_image is None:
                subprocess.run(build, check=True, capture_output=True, timeout=180)
            image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag], text=True))[0]
            self.assertEqual(image['Config']['User'], '10006:10006'); self.assertEqual(image['Config']['Entrypoint'], stage.ENTRYPOINT)
            self.assertEqual(image['Config']['Labels']['org.opencontainers.image.revision'], revision)
            self.assertEqual(image['Config']['Labels']['ouf.payload.sha256'], stage.digest(stage.PAYLOAD_HASHES))
            cert, private, receipt = root/'cert.pem', root/'key.pem', root/'receipt.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-out', str(cert), '-keyout', str(private)],
                capture_output=True, check=True, timeout=15)
            receipt.write_text(KEY); receipt.chmod(0o600); private.chmod(0o600); cert.chmod(0o644)
            subprocess.run(['sudo', 'chown', str(uid)+':'+str(gid), str(receipt), str(private)], check=True, timeout=10)
            with socket.socket() as socket_:
                socket_.bind(('127.0.0.1', 0)); port = socket_.getsockname()[1]
            b = binding()
            cfg = {'listenAddress': '127.0.0.1', 'listenPort': port, 'maxWorkers': 4, 'requestTimeoutSeconds': 3,
                'searchPath': b.search_path, 'fetchPath': b.fetch_path, 'provider': asdict(b.provider), 'admission': asdict(b.admission),
                'receiptKeyFile': '/run/provider/receipt.key', 'tlsCertificateFile': '/run/provider/cert.pem',
                'tlsPrivateKeyFile': '/run/provider/key.pem'}
            config = root/'config.json'; config.write_text(json.dumps(cfg)); config.chmod(0o644)
            command = ['docker', 'run', '-d', '--name', name, '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--pids-limit', '32', '--network', 'host']
            for source, target in [(config, '/run/provider/config.json'), (cert, '/run/provider/cert.pem'),
                                   (private, '/run/provider/key.pem'), (receipt, '/run/provider/receipt.key')]:
                command.extend(['-v', str(source)+':'+target+':ro'])
            command.extend([tag, '--configuration', '/run/provider/config.json'])
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            try:
                tls = ssl.create_default_context(cafile=str(cert))
                def request(body=b'query=DROP+ALL&format=application%2Fsparql-results%2Bjson', proof='forged', extra=None):
                    connection = http.client.HTTPSConnection('localhost', port, context=tls, timeout=5)
                    try:
                        headers = {HEADER: proof, 'Content-Type': 'application/x-www-form-urlencoded'}; headers.update(extra or {})
                        connection.request('POST', b.search_path, body=body, headers=headers)
                        response = connection.getresponse(); return response.status, response.read()
                    finally: connection.close()
                deadline = time.monotonic()+20
                while True:
                    try:
                        status, _ = request()
                        if status == 403: break
                    except (OSError, http.client.HTTPException): pass
                    if time.monotonic() > deadline: self.fail('CONTAINER_TLS_ADMISSION_NOT_READY')
                    time.sleep(0.2)
                body = b'query=DROP+ALL&format=application%2Fsparql-results%2Bjson'; now = int(time.time())
                valid = signed(claims(body=body, iat=now, exp=now+30))
                self.assertEqual(request(body, valid)[0], 400, 'authenticated invalid grammar must stop before provider/DNS')
                self.assertEqual(request(body+b'x', valid)[0], 403)
                self.assertEqual(request(body, valid, {'Authorization': 'Bearer forbidden'})[0], 403)
                self.assertEqual(request(body, signed(claims(body=body, actor='HUMAN', iat=now, exp=now+30)))[0], 403)
                runtime = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True))[0]
                self.assertTrue(runtime['State']['Running']); self.assertTrue(runtime['HostConfig']['ReadonlyRootfs'])
                self.assertEqual(runtime['HostConfig']['CapDrop'], ['ALL'])
                self.assertTrue(any(value in ('no-new-privileges', 'no-new-privileges=true') for value in runtime['HostConfig']['SecurityOpt']))
                self.assertTrue(all(mount['RW'] is False for mount in runtime['Mounts']))
                proof = {'schema': 'ouf.semantic-provider-package-ci.v1', 'sourceRevision': revision, 'baseImage': base,
                    'imageId': image['Id'], 'runtimeUser': '10006:10006', 'readOnlyRoot': True, 'capabilitiesDropped': True,
                    'tlsAdmissionProven': True, 'externalProviderCalls': 0, 'egressIsolationProven': False, 'notReleaseAcceptance': True}
                print('SEMANTIC_PROVIDER_PACKAGE_PROOF='+json.dumps(proof, sort_keys=True))
                evidence = repository/'generated/semantic-provider-package-proof.json'; evidence.parent.mkdir(exist_ok=True)
                evidence.write_text(json.dumps(proof, sort_keys=True)+'\n')
            finally:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, check=False, timeout=20)


if __name__ == '__main__': unittest.main()
