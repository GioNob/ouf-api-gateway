import base64
from dataclasses import replace
from email.message import Message
import hashlib
import hmac
import http.client
import json
import multiprocessing
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from tools import semantic_provider_admission as admission
from tools import semantic_provider_adapter as adapter
from tools import semantic_provider_relay as relay
from tests.test_semantic_provider_relay import form

KEY = 'ab'*32
NOW = 1000


def binding():
    return adapter.AdapterBinding(relay.ProviderBinding('https://provider.example/sparql', ('https://vocab.example/class/',)),
        admission.AdmissionBinding('install-test', 'https://auth.example/realms/test', 'gateway-test',
            'semantic-test', 'gateway.southbound.invoke', ('tenant-test',)), '/provider/search', '/provider/fetch', KEY)


def claims(method='POST', target='/provider/search', body=None, **changes):
    body = form() if body is None else body
    value = {'purpose': admission.PURPOSE, 'installation': 'install-test',
        'issuer': 'https://auth.example/realms/test', 'audience': 'gateway-test',
        'workload': 'semantic-test', 'tenant': 'tenant-test', 'subject': 'service-subject',
        'actor': 'SERVICE', 'scope': 'gateway.southbound.invoke',
        'requestHash': admission.request_hash(method, target, body), 'iat': NOW, 'exp': NOW+30}
    value.update(changes)
    return value


def signed(value, key=KEY):
    raw = json.dumps(value, separators=(',', ':')).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    return encoded+'.'+hmac.new(key.encode(), (admission.PURPOSE+'.'+encoded).encode(), hashlib.sha256).hexdigest()


def headers(receipt, **extra):
    result = Message(); result.add_header(admission.HEADER, receipt)
    result.add_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
    for key, value in extra.items(): result.add_header(key, value)
    return result


class AdmissionTest(unittest.TestCase):
    def test_correct_purpose_identity_exact_bytes_and_short_expiry(self):
        value = claims()
        self.assertEqual(admission.verify(binding().admission, KEY, signed(value), 'POST', '/provider/search', form(), now=NOW), value)

    def test_context_and_time_tampering_rejected_even_with_valid_mac(self):
        cases = {'purpose': 'semantic-read-owner', 'installation': 'other', 'issuer': 'https://foreign.example',
            'audience': 'other', 'workload': 'other', 'tenant': 'other', 'actor': 'HUMAN',
            'scope': 'ouf.semantic.read', 'requestHash': '0'*64, 'subject': '', 'iat': NOW+1,
            'exp': NOW, 'extra': 'forged'}
        for key, value in cases.items():
            with self.subTest(key=key), self.assertRaises(admission.AdmissionDenied):
                admission.verify(binding().admission, KEY, signed(claims(**{key: value})), 'POST', '/provider/search', form(), now=NOW)
        for changes in [{'exp': NOW+31}, {'iat': True}, {'exp': 1030.0}]:
            with self.assertRaises(admission.AdmissionDenied):
                admission.verify(binding().admission, KEY, signed(claims(**changes)), 'POST', '/provider/search', form(), now=NOW)

    def test_signature_method_target_body_mutations_rejected(self):
        receipt = signed(claims())
        for method, target, body in [('GET', '/provider/search', form()), ('POST', '/other', form()), ('POST', '/provider/search', form()+b' ' )]:
            with self.assertRaises(admission.AdmissionDenied):
                admission.verify(binding().admission, KEY, receipt, method, target, body, now=NOW)
        for value in [receipt[:-1]+'x', signed(claims(), 'cd'*32), 'not-a-receipt', receipt*10]:
            with self.assertRaises(admission.AdmissionDenied):
                admission.verify(binding().admission, KEY, value, 'POST', '/provider/search', form(), now=NOW)

    def test_direct_forged_duplicate_header_and_caller_bearer_never_invoke_transport(self):
        provider = Mock()
        variants = [Message(), headers('forged'), headers(signed(claims()), Authorization='Bearer secret')]
        duplicate = headers(signed(claims())); duplicate.add_header(admission.HEADER, signed(claims())); variants.append(duplicate)
        for value in variants:
            with self.assertRaises(admission.AdmissionDenied):
                adapter.dispatch(binding(), 'POST', '/provider/search', value, form(), provider_search=provider)
        provider.assert_not_called()

    def test_search_and_fetch_match_native_owner_post_get_contract(self):
        provider = Mock(return_value=relay.ProviderResponse(b'{}', 'application/json'))
        with patch.object(admission.time, 'time', return_value=NOW):
            adapter.dispatch(binding(), 'POST', '/provider/search', headers(signed(claims())), form(), provider_search=provider)
            target = '/provider/fetch?'+urlencode({'uri': 'https://vocab.example/class/Place'})
            adapter.dispatch(binding(), 'GET', target, headers(signed(claims('GET', target, b''))), b'', provider_fetch=provider)
        self.assertEqual(provider.call_args_list[0].args[1], form())
        self.assertEqual(provider.call_args_list[1].args[1], target.split('?', 1)[1].encode())

    def test_route_body_and_media_abuse_never_invokes_transport(self):
        provider = Mock()
        with patch.object(admission.time, 'time', return_value=NOW):
            for method, target in [('POST', '/provider/search?url=evil'), ('GET', '/provider/search'), ('PUT', '/provider/search'), ('GET', 'https://evil.example/provider/fetch?uri=x')]:
                with self.assertRaises(adapter.AdapterDenied):
                    adapter.dispatch(binding(), method, target, headers('forged'), b'', provider_fetch=provider, provider_search=provider)
            wrong = headers(signed(claims())); wrong.replace_header('Content-Type', 'application/json')
            with self.assertRaises(adapter.AdapterDenied):
                adapter.dispatch(binding(), 'POST', '/provider/search', wrong, form(), provider_search=provider)
        provider.assert_not_called()

    def test_private_key_file_rejects_symlink_public_permissions_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); file = root/'key'; file.write_text(KEY); file.chmod(0o600)
            self.assertEqual(adapter.private_file(file, 256), KEY.encode())
            link = root/'symlink'; link.symlink_to(file)
            with self.assertRaises(OSError): adapter.private_file(link, 256)
            file.chmod(0o644)
            with self.assertRaises(adapter.AdapterDenied): adapter.private_file(file, 256)
            file.chmod(0o600); (root/'hardlink').hardlink_to(file)
            with self.assertRaises(adapter.AdapterDenied): adapter.private_file(file, 256)

    def test_nested_deadline_preserves_outer_budget(self):
        start = time.monotonic()
        with self.assertRaises(relay.RelayDenied):
            with relay.request_deadline(0.1):
                with relay.request_deadline(1): time.sleep(0.3)
        self.assertLess(time.monotonic()-start, 0.25)


@unittest.skipUnless(shutil.which('openssl'), 'TLS fixture requires OpenSSL')
class TLSAdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name); cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
            '-out', str(cert), '-keyout', str(key)], capture_output=True, check=True, timeout=15)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        server = adapter.BoundedTLSServer(('127.0.0.1', 0), replace(binding(), request_timeout_seconds=2), context, 2)
        self.port = server.server_port
        def serve():
            with patch.object(relay, 'exchange', return_value=relay.ProviderResponse(b'{"results":{"bindings":[]}}', 'application/sparql-results+json')):
                server.serve_forever()
        self.process = multiprocessing.get_context('fork').Process(target=serve); self.process.start()
        self.addCleanup(self.stop); server.server_close()
        self.context = ssl.create_default_context(cafile=str(cert))

    def stop(self):
        self.process.terminate(); self.process.join(timeout=5)
        if self.process.is_alive(): self.process.kill(); self.process.join(timeout=5)

    def call(self, body, receipt, extra=None, context=None):
        conn = http.client.HTTPSConnection('localhost', self.port, context=context or self.context, timeout=4)
        try:
            request_headers = {admission.HEADER: receipt, 'Content-Type': 'application/x-www-form-urlencoded'}
            request_headers.update(extra or {})
            conn.request('POST', '/provider/search', body=body, headers=request_headers)
            response = conn.getresponse(); return response.status, response.read(), response.getheader('Connection')
        finally: conn.close()

    def test_real_tls_valid_receipt_and_native_form(self):
        now = int(time.time()); receipt = signed(claims(iat=now, exp=now+30))
        status, body, close = self.call(form(), receipt)
        self.assertEqual((status, json.loads(body), close), (200, {'results': {'bindings': []}}, 'close'))

    def test_real_tls_direct_forgery_and_body_tamper_denied(self):
        now = int(time.time()); receipt = signed(claims(iat=now, exp=now+30))
        for body, value, extra in [(form(), 'forged', None), (b'query=DROP+ALL', receipt, None), (form(), receipt, {'Authorization': 'Bearer secret'})]:
            self.assertEqual(self.call(body, value, extra)[0], 403)

    def test_untrusted_server_tls_fails_before_http(self):
        with self.assertRaises(ssl.SSLError): self.call(form(), 'forged', context=ssl.create_default_context())

    def test_invalid_framing_is_bounded_and_redacted(self):
        try:
            status, body, _ = self.call(form(), 'forged', {'Transfer-Encoding': 'chunked'})
        except (http.client.RemoteDisconnected, http.client.IncompleteRead, ConnectionResetError):
            # Early rejection of an unread ambiguous body may close TLS before
            # its error response is delivered; no unbounded drain is required.
            return
        self.assertEqual(status, 400); self.assertNotIn(b'forged', body); self.assertNotIn(b'query', body)

    def test_slow_tls_handshake_is_closed_by_worker_deadline(self):
        start = time.monotonic()
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as client:
            self.assertEqual(client.recv(1), b'')
        self.assertLess(time.monotonic()-start, 3.5)

    def test_incomplete_headers_are_closed_by_worker_deadline(self):
        start = time.monotonic()
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as plain:
            with self.context.wrap_socket(plain, server_hostname='localhost') as client:
                client.sendall(b'POST /provider/search HTTP/1.1\r\nHost: localhost\r\nIncomplete: ')
                self.assertEqual(client.recv(1), b'')
        self.assertLess(time.monotonic()-start, 3.5)


if __name__ == '__main__': unittest.main()
