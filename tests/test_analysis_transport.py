"""GW-51N-08. A remote reservation owner and two IAM adapters over real, private test TLS."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests import test_analysis_mandate as fixtures
from tests.test_analysis_mandate import ISSUER, ReservationServer
from tools.analysis_mandate import new_ref
from tools.analysis_clients import Endpoint, RemoteIAM, Reservations
from tools.analysis_protocol import Rejected, digest, parse, wire


@contextmanager
def tls_server(dispatch):
    # Ephemeral synthetic credentials scoped to this loopback test only.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ca = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture-ca')])
        now = datetime.now(timezone.utc)
        issuer_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key())

        def cert(subject, public, *, is_ca=False):
            usage = x509.KeyUsage(digital_signature=not is_ca, content_commitment=False,
                                  key_encipherment=False, data_encipherment=False, key_agreement=False,
                                  key_cert_sign=is_ca, crl_sign=is_ca, encipher_only=False, decipher_only=False)
            return (x509.CertificateBuilder().issuer_name(name).subject_name(subject).public_key(public)
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                    .not_valid_after(now + timedelta(hours=1))
                    .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
                    .add_extension(usage, critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
                    .add_extension(issuer_id, critical=False))

        pem = serialization.Encoding.PEM
        ca_cert = cert(name, ca.public_key(), is_ca=True).sign(ca, hashes.SHA256())
        (root/'ca').write_bytes(ca_cert.public_bytes(pem))
        for role in ('localhost', 'gateway'):
            key = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)])
            names = [x509.DNSName(role)]
            if role == 'localhost':
                names.append(x509.IPAddress(ip_address('127.0.0.1')))
            leaf = cert(subject, key.public_key()).add_extension(x509.SubjectAlternativeName(names), False)
            purpose = ExtendedKeyUsageOID.SERVER_AUTH if role == 'localhost' else ExtendedKeyUsageOID.CLIENT_AUTH
            leaf = leaf.add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            (root/role).write_bytes(leaf.sign(ca, hashes.SHA256()).public_bytes(pem))
            (root/(role + '.key')).write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                                 serialization.NoEncryption()))
        class Server(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                try:
                    result = dispatch(self.path, body)
                    status = 200
                except Rejected as exc:
                    result, status = {'code':exc.code}, exc.status
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(wire(result))

            def log_message(self, *_):
                pass

        with ThreadingHTTPServer(('127.0.0.1', 0), Server) as server:
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(root/'localhost', root/'localhost.key')
            server_ctx.load_verify_locations(root/'ca')
            server_ctx.verify_mode = ssl.CERT_REQUIRED
            server_ctx.verify_flags |= ssl.VERIFY_X509_STRICT
            server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
            client = ssl.create_default_context(cafile=str(root/'ca'))
            client.verify_flags |= ssl.VERIFY_X509_STRICT
            client.load_cert_chain(root/'gateway', root/'gateway.key')
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                yield lambda path: Endpoint(f'https://127.0.0.1:{server.server_port}' + path, client, 3)
            finally:
                server.shutdown()
                thread.join(3)


class TransportPET(unittest.TestCase):
    def test_same_current_right_contract_and_reservation_for_both_iams(self):
        reservations = ReservationServer()
        b = dict(mandateId='33333333-3333-4333-8333-333333333333', analysisId='a'*64, generation='1',
                 intentKey='b'*64, attemptId='44444444-4444-4444-8444-444444444444', fence='1',
                 operation='semantic.discovery.status', arguments={'requestId':'55555555-5555-4555-8555-555555555555'})
        reservations.reserve(b)
        request_id = b['arguments']['requestId']
        reservations.request_owners[request_id] = (b['analysisId'], 'human')
        resource_ids = {request_id, fixtures.PROFILE['profileId']}
        ouf_grants = {('tenant', 'human', resource) for resource in resource_ids}
        external_acl = {'fixture-reader': resource_ids}
        external_groups = {'tenant/human': ['fixture-reader']}
        def dispatch(path, raw):
            if path == '/reservation':
                return reservations.evidence(raw, {})
            if path.endswith('/token'):
                return dict(active=raw == b'token=worker', iss=ISSUER, aud='gateway' if 'ouf' in path else ['gateway'],
                            sub='svc', client_id='worker', ouf_actor_type='SERVICE', exp=1100, tenant_id='tenant')
            q = parse(raw)
            resource = q.get('resourceId') or q['profile']['profileId']
            if path.startswith('/ouf/'):
                allowed = (q['tenant'], q['subject'], resource) in ouf_grants
            else:
                groups = external_groups.get(q['tenant']+'/'+q['subject'], [])
                allowed = any(resource in external_acl[group] for group in groups)
            if not allowed:
                return {'requestHash': digest(raw), 'allowed': False}
            return dict(requestHash=digest(raw), allowed=True, policyRef='p', grantRef='g', decisionRef='d',
                        validUntil=1050, grantExpiresAt=2000, allowedOperations=[fixtures.OP], roles=[],
                        acr='interactive', client='fixture')
        with tls_server(dispatch) as endpoint:
            for mode in ('ouf', 'preexisting'):
                iam = RemoteIAM(endpoint('/'+mode+'/token'), endpoint('/'+mode+'/decide'), ISSUER, 'gateway', 'worker')
                self.assertEqual(iam.authenticate('Bearer worker', 1000)['sub'], 'svc')
                with self.assertRaises(Rejected):
                    iam.authenticate('Bearer foreign', 1000)
                q = dict(tenant='tenant', subject='human', resourceId=b['arguments']['requestId'])
                self.assertTrue(iam.decide(q, 1000)['allowed'])
                pet = fixtures.MandatePET()
                pet.setUp()
                self.addCleanup(pet.doCleanups)
                pet.api.iam = iam
                pet.api.reservations = Reservations(endpoint('/reservation'))
                issue = dict(pet.issue, analysisId='c'*64, commandKey=new_ref())
                status, raw, _ = pet.api.handle('issue', wire(issue), 'Bearer worker', pet.proof())
                self.assertEqual(status, 200)
                attempt = dict(pet.b, analysisId=issue['analysisId'], mandateId=parse(raw)['mandateId'])
                reservations.reserve(attempt)
                self.assertEqual(pet.api.handle('dispatch', wire(attempt), 'Bearer worker')[0], 201)
                if mode == 'ouf':
                    ouf_grants.clear()
                else:
                    external_groups.clear()
                attempt['attemptId'] = new_ref()
                reservations.reserve(attempt)
                self.assertEqual(pet.api.handle('dispatch', wire(attempt), 'Bearer worker')[0], 403)
                pet.owner.post.assert_called_once()
                with self.assertRaises(Rejected) as denied:
                    iam.decide(q, 1000)
                self.assertEqual(denied.exception.status, 403)
            client = Reservations(endpoint('/reservation'))
            self.assertEqual(client.check(b, 'worker', 1000)['subject'], 'human')
            with self.assertRaises(Rejected) as stale:
                client.check(dict(b, fence='0'), 'worker', 1000)
            self.assertEqual(stale.exception.status, 409)
            reservations.request_owners[request_id] = (b['analysisId'], 'foreign-subject')
            with self.assertRaises(Rejected) as foreign:
                client.check(b, 'worker', 1000)
            self.assertEqual(foreign.exception.status, 404)
