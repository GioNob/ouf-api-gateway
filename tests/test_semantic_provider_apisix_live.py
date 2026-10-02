"""Real APISIX OIDC -> signed request -> TLS adapter gate; no external provider.

Controlled issuer, keys and certificate are confined to the CI fixture. Host
network is a fixture convenience, not a deployable isolation topology.
"""
import contextlib
from dataclasses import replace
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode

from tools import semantic_provider_adapter as adapter
from tools import semantic_provider_relay as relay
from tools.materialize_semantic_provider import materialize
from tools.materialize_semantic_provider_tls import materialize_tls
from tests.test_semantic_provider_adapter import binding, form, KEY
from tests.test_semantic_provider_materialization import config


@unittest.skipUnless(os.environ.get('OUF_SEMANTIC_PROVIDER_APISIX_TEST') == '1', 'requires Docker APISIX gate')
class RealProviderGatewayTest(unittest.TestCase):
    def test_signed_jwt_admission_tls_transport_and_negative_boundaries(self):
        import jwt
        import yaml
        from cryptography.hazmat.primitives.asymmetric import rsa
        signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing.public_key()))
        jwk.update(kid='provider-ci', use='sig', alg='RS256')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); certificate, private = root/'cert.pem', root/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                # OpenResty lua-resty-http checks the literal host as a DNS name,
                # whereas native TLS clients recognize IP SANs. Cover both in
                # this generated loopback-only fixture; never disable validation.
                # A valid extra SAN deliberately has no SSL/SNI resource, so its
                # refusal proves server SNI matching rather than client rejection.
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1,DNS:southbound.fixture,DNS:unregistered.example.invalid',
                '-out', str(certificate), '-keyout', str(private)], capture_output=True, check=True, timeout=15)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certificate, private)
            cfg = config(); calls = root/'calls'; calls.write_text('')
            class Issuer(BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_GET(self):
                    if self.path == '/.well-known/openid-configuration':
                        raw = json.dumps({'issuer': cfg['issuer'], 'jwks_uri': cfg['issuer']+'/jwks',
                            'token_endpoint': cfg['issuer']+'/token', 'authorization_endpoint': cfg['issuer']+'/auth',
                            'id_token_signing_alg_values_supported': ['RS256']}).encode()
                    elif self.path == '/jwks': raw = json.dumps({'keys': [jwk]}).encode()
                    else: self.send_error(404); return
                    self.send_response(200); self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
            issuer = ThreadingHTTPServer(('127.0.0.1', 0), Issuer)
            issuer.socket = context.wrap_socket(issuer.socket, server_side=True)
            cfg['issuer'] = 'https://127.0.0.1:'+str(issuer.server_port)
            threading.Thread(target=issuer.serve_forever, daemon=True).start()
            try:
                admitted = replace(binding().admission, issuer=cfg['issuer'])
                server = adapter.BoundedTLSServer(('127.0.0.1', 0), replace(binding(), admission=admitted), context, 4)
                backend_port = server.server_port
                def exchange(*args, **kwargs):
                    with calls.open('a') as stream: stream.write('provider-exchange\n')
                    if 'text/turtle' in kwargs['accepted']:
                        return relay.ProviderResponse(b'<https://vocab.example/class/Place> <http://example/type> <http://example/Class> .', 'text/turtle')
                    return relay.ProviderResponse(b'{"results":{"bindings":[]}}', 'application/sparql-results+json')
                def serve():
                    with patch.object(relay, 'exchange', side_effect=exchange): server.serve_forever()
                process = multiprocessing.get_context('fork').Process(target=serve); process.start(); server.server_close()
                try:
                    with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
                    cfg['upstream']['nodes'] = {'127.0.0.1:'+str(backend_port): 1}
                    cfg['upstream']['upstream_host'] = 'localhost'
                    bootstrap = materialize_tls(cfg, {'listenAddress': '127.0.0.1', 'listenPort': port,
                        'serverHostname': 'southbound.fixture', 'sslResourceId': 'provider-ci-tls'},
                        certificate_pem=certificate.read_text(), private_key_pem=private.read_text())
                    resources = bootstrap['resources']; routes = resources['routes']
                    wrong_tls = config(); wrong_tls['issuer'] = cfg['issuer']
                    wrong_tls.update(searchPath='/provider/untrusted', fetchPath='/provider/untrusted-fetch',
                        searchRouteId='untrusted-search', fetchRouteId='untrusted-fetch')
                    wrong_tls['upstream']['nodes'] = cfg['upstream']['nodes']
                    wrong_tls['upstream']['upstream_host'] = 'foreign.invalid'
                    routes += materialize({'routes': []}, wrong_tls)['routes']
                    # Synthetic misnamed SSL control proves client hostname
                    # verification even when the server deliberately matches SNI.
                    resources['ssls'].append(dict(resources['ssls'][0], id='misnamed-ci-tls', snis=['misnamed.example.invalid']))
                    runtime = bootstrap['runtimeConfiguration']
                    (root/'config.yaml').write_text(yaml.safe_dump(runtime))
                    (root/'apisix.yaml').write_text(yaml.safe_dump(resources)+'\n#END\n')
                    name = 'ouf-provider-ci-'+str(os.getpid())
                    subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'host',
                        '-e', 'OIDC_SECRET=fixture-only', '-e', 'OUF_SEMANTIC_PROVIDER_OWNER_KEY='+KEY,
                        # Bind only the public trust anchor. The host temp parent
                        # is private; the APISIX worker cannot traverse that dir.
                        '-v', str(certificate)+':/provider-fixture/cert.pem:ro',
                        '-v', str(root/'config.yaml')+':/usr/local/apisix/conf/config.yaml:ro',
                        '-v', str(root/'apisix.yaml')+':/usr/local/apisix/conf/apisix.yaml:ro',
                        'apache/apisix:3.18.0-debian'], check=True, stdout=subprocess.DEVNULL, timeout=180)
                    try:
                        def token(**changes):
                            now = int(time.time()); claims = {'iss': cfg['issuer'], 'aud': cfg['audience'],
                                'azp': cfg['workload'], 'sub': 'service-subject', 'tenant_id': 'tenant-test',
                                'ouf_actor_type': 'SERVICE', 'scope': cfg['scope'], 'iat': now, 'exp': now+300}
                            claims.update(changes)
                            return jwt.encode(claims, signing, algorithm='RS256', headers={'kid': 'provider-ci'})
                        def request(method='POST', target='/provider/search', body=None, bearer=None):
                            conn = relay.PinnedHTTPSConnection('southbound.fixture', port, '127.0.0.1', 10,
                                ssl.create_default_context(cafile=str(certificate)))
                            try:
                                headers = {'Content-Type': 'application/x-www-form-urlencoded',
                                    'X-OUF-Semantic-Provider-Receipt': 'forged', 'X-OUF-Tenant-ID': 'forged'}
                                if bearer: headers['Authorization'] = 'Bearer '+bearer
                                conn.request(method, target, body=form() if body is None else body, headers=headers)
                                response = conn.getresponse(); return response.status, response.read()
                            finally: conn.close()
                        deadline = time.monotonic()+40
                        code = None
                        while True:
                            try:
                                code, _ = request(bearer=token())
                                if code == 200: break
                            except (OSError, http.client.HTTPException): pass
                            if time.monotonic() > deadline:
                                logs = subprocess.run(['docker', 'logs', '--tail', '15', name], capture_output=True,
                                    text=True, check=False, timeout=10)
                                # This fixture contains only synthetic IAM keys,
                                # identities and generated certificates, never live data.
                                detail = re.sub(r'-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----',
                                    '[fixture-PEM]', (logs.stdout+logs.stderr).replace(KEY, '[fixture-key]'), flags=re.S)[-6000:]
                                self.fail('APISIX_PROVIDER_READY_NOT_PROVEN status='+str(code)+'\n'+detail)
                            time.sleep(0.25)
                        self.assertEqual(code, 200)
                        # Read only generated NGINX configuration; never SSL YAML,
                        # env values or private keys. Numeric listeners must be the
                        # single TLS-only endpoint (internal Unix sockets excluded).
                        nginx = subprocess.run(['docker', 'exec', name, 'cat', '/usr/local/apisix/conf/nginx.conf'],
                            capture_output=True, text=True, check=True, timeout=10).stdout
                        listeners = re.findall(r'^\s*listen\s+([^;]+);', nginx, re.M)
                        numeric = [line for line in listeners if not line.startswith('unix:')]
                        self.assertEqual(len(numeric), 1, 'no implicit HTTP/admin/control/metrics listener')
                        self.assertIn('127.0.0.1:'+str(port), numeric[0]); self.assertIn(' ssl ', ' '+numeric[0]+' ')
                        target = '/provider/fetch?'+urlencode({'uri': 'https://vocab.example/class/Place'})
                        code, body = request('GET', target, b'', token())
                        self.assertEqual(code, 200); self.assertIn(b'Place', body)
                        before = len(calls.read_text().splitlines())
                        # Extra SAN is trusted and correctly named but unregistered
                        # SNI must fail the server handshake, with verification on.
                        tls_client = ssl.create_default_context(cafile=str(certificate))
                        for sni in ('unregistered.example.invalid', 'misnamed.example.invalid'):
                            expected = ssl.SSLCertVerificationError if sni.startswith('misnamed') else ssl.SSLError
                            with socket.create_connection(('127.0.0.1', port), timeout=5) as plain:
                                with self.assertRaises(expected):
                                    tls_client.wrap_socket(plain, server_hostname=sni)
                        plaintext = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                        try:
                            plaintext.request('POST', '/provider/search', body=form())
                            self.assertEqual(plaintext.getresponse().status, 400)
                        finally: plaintext.close()
                        for bearer in [None, token()+'broken', token(aud='wrong'), token(iss='https://foreign.example'),
                                token(scope='ouf.semantic.read'), token(ouf_actor_type='HUMAN'), token(azp='wrong'),
                                token(tenant_id='wrong'), token(exp=int(time.time())-1)]:
                            code, _ = request(bearer=bearer)
                            self.assertIn(code, (401, 403))
                        code, _ = request(body=b'query=DROP+ALL&format=application%2Fsparql-results%2Bjson', bearer=token())
                        self.assertEqual(code, 400)
                        self.assertEqual(len(calls.read_text().splitlines()), before)
                        code, _ = request(target='/provider/untrusted', bearer=token())
                        self.assertEqual(code, 502, 'upstream hostname mismatch must fail TLS before HTTP')
                        # Direct TLS access without the Gateway receipt stays denied.
                        direct = http.client.HTTPSConnection('localhost', backend_port,
                            context=ssl.create_default_context(cafile=str(certificate)), timeout=5)
                        try:
                            direct.request('POST', '/provider/search', body=form(), headers={'Content-Type': 'application/x-www-form-urlencoded'})
                            self.assertEqual(direct.getresponse().status, 403)
                        finally: direct.close()
                        self.assertEqual(len(calls.read_text().splitlines()), before)
                    finally:
                        removed = subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, timeout=20)
                        self.assertEqual(removed.returncode, 0, 'fixture container cleanup must succeed')
                finally:
                    process.terminate(); process.join(timeout=5)
                    if process.is_alive(): process.kill(); process.join(timeout=5)
            finally:
                issuer.shutdown(); issuer.server_close()
        print('SOUTHBOUND_APISIX_TLS=PASS REAL_APISIX_3_18=true TLS_ONLY_LISTENER=true '
            'EXACT_SNI=true CLIENT_HOSTNAME_VERIFY=true OIDC_RECEIPT_ADAPTER_TLS=true '
            'UPSTREAM_HOSTNAME_MISMATCH_DENIED=true FIXTURE_CLEANUP=true '
            'EXTERNAL_PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')


if __name__ == '__main__': unittest.main()
