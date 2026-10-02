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
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
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
                    routes = materialize({'routes': []}, cfg)['routes']
                    wrong_tls = config(); wrong_tls['issuer'] = cfg['issuer']
                    wrong_tls.update(searchPath='/provider/untrusted', fetchPath='/provider/untrusted-fetch',
                        searchRouteId='untrusted-search', fetchRouteId='untrusted-fetch')
                    wrong_tls['upstream']['nodes'] = cfg['upstream']['nodes']
                    wrong_tls['upstream']['upstream_host'] = 'foreign.invalid'
                    routes += materialize({'routes': []}, wrong_tls)['routes']
                    runtime = {'apisix': {'node_listen': port, 'enable_admin': False,
                            'ssl': {'ssl_trusted_certificate': '/provider-fixture/cert.pem'}},
                        'deployment': {'role': 'data_plane', 'role_data_plane': {'config_provider': 'yaml'}},
                        'nginx_config': {'envs': ['OIDC_SECRET', 'OUF_SEMANTIC_PROVIDER_OWNER_KEY']}}
                    (root/'config.yaml').write_text(yaml.safe_dump(runtime))
                    (root/'apisix.yaml').write_text(yaml.safe_dump({'routes': routes})+'\n#END\n')
                    name = 'ouf-provider-ci-'+str(os.getpid())
                    subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'host',
                        '-e', 'OIDC_SECRET=fixture-only', '-e', 'OUF_SEMANTIC_PROVIDER_OWNER_KEY='+KEY,
                        '-v', folder+':/provider-fixture:ro',
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
                            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
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
                            if time.monotonic() > deadline: self.fail('APISIX_PROVIDER_READY_NOT_PROVEN status='+str(code))
                            time.sleep(0.25)
                        self.assertEqual(code, 200)
                        target = '/provider/fetch?'+urlencode({'uri': 'https://vocab.example/class/Place'})
                        code, body = request('GET', target, b'', token())
                        self.assertEqual(code, 200); self.assertIn(b'Place', body)
                        before = len(calls.read_text().splitlines())
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
                        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=20)
                finally:
                    process.terminate(); process.join(timeout=5)
                    if process.is_alive(): process.kill(); process.join(timeout=5)
            finally:
                issuer.shutdown(); issuer.server_close()


if __name__ == '__main__': unittest.main()
