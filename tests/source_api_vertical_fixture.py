"""Fictitious vertical (ouf.vertical-mock.v1 shape) over TLS with an ephemeral CA, for the 61f-a tests.

Only fictitious names and documentation networks are used (D-058). Certificates and keys are
generated at test time and never committed.
"""
import datetime
import hashlib
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tools.semantic_provider_relay import PinnedHTTPSConnection

HOST = 'vertical.example.invalid'
PORT = 8443
ADDRESS = '192.0.2.10'
EPOCH = '0f1e2d3c4b5a69788796a5b4c3d2e1f0'
EDICOLE = 'a' * 64
MUSEI = 'b' * 64
FIELDS = 'c' * 64


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True)


def catalog_digest(pairs):
    return hashlib.sha256(canonical(sorted(pairs)).encode()).hexdigest()


def _name(common):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def make_pki(directory, hostname=HOST):
    """Ephemeral CA and leaf certificate; returns (ca_file, cert_file, key_file)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name('ouf-test-ca')
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(_name(hostname)).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_file, cert_file, key_file = directory / 'ca.pem', directory / 'leaf.pem', directory / 'leaf.key'
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_file.chmod(0o600)
    return ca_file, cert_file, key_file


def catalog(collections=(('edicole', EDICOLE), ('musei', MUSEI))):
    rows = [{'collection': name, 'epoch': EPOCH, 'title': name.title() + ' (dati fittizi)', 'schemaVersion': version,
             'fieldsSha256': FIELDS, 'deltaModes': ['CURSOR', 'WATERMARK', 'SNAPSHOT'], 'defaultMode': 'CURSOR',
             'deletions': 'EXPLICIT', 'maxLateness': 'PT10M', 'retention': 'P7D',
             'retainedFrom': '2026-11-17T22:00:00Z', 'cycle': 'PT1M'} for name, version in collections]
    return {'epoch': EPOCH, 'schemaVersion': catalog_digest([[n, v] for n, v in collections]), 'collections': rows}


def schema(collection='edicole', version=EDICOLE):
    return {'collection': collection, 'schemaVersion': version, 'fieldsSha256': FIELDS,
            'fields': [{'name': 'id', 'type': 'string', 'nullable': False, 'description': 'Identificativo'}],
            'key': ['id'], 'geometry': None}


def items(collection='edicole', version=EDICOLE, mode='CURSOR', count=2):
    rows = [{'id': 'E-%06d' % i, 'revision': i + 1, 'op': 'UPSERT', 'changedAt': '2026-11-24T22:15:0%dZ' % (i % 10),
             'properties': {'id': 'E-%06d' % i, 'nome': 'Edicola «%d»' % i}} for i in range(count)]
    return {'collection': collection, 'schemaVersion': version, 'fieldsSha256': FIELDS, 'mode': mode, 'epoch': EPOCH,
            'items': rows, 'next': 'eyJzIjoxfQ.c2ln', 'hasMore': False, 'snapshotComplete': None, 'snapshotId': None,
            'resume': None, 'positionExpiresAt': None}


class Reply:
    """Response plan: status, headers, body, transfer mode (normal, chunked, incomplete), delay."""

    def __init__(self, status=200, body=b'', headers=None, mode='normal', delay=0.0):
        self.status, self.body, self.headers, self.mode, self.delay = status, body, headers or [], mode, delay

    @classmethod
    def json(cls, value, status=200, version=None, headers=None, **options):
        body = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        version = value.get('schemaVersion') if version is None and isinstance(value, dict) else version
        extra = [('Content-Type', 'application/json; charset=utf-8')]
        if version:
            extra.append(('X-Schema-Version', version))
        return cls(status, body, extra + list(headers or []), **options)


def default_reply(path):
    route = path.split('?', 1)[0]
    if route == '/collections':
        return Reply.json(catalog())
    if route.startswith('/collections/') and route.endswith('/schema'):
        name = route.split('/')[2]
        return Reply.json(schema(name, EDICOLE if name == 'edicole' else MUSEI))
    if route.startswith('/collections/') and route.endswith('/items'):
        name = route.split('/')[2]
        return Reply.json(items(name, EDICOLE if name == 'edicole' else MUSEI))
    return Reply.json({'code': 'UNKNOWN_COLLECTION', 'message': 'Not Found', 'schemaVersion': catalog()['schemaVersion']},
                      status=404)


class FakeVertical:
    """TLS vertical on loopback; the adapter reaches it through LoopbackPinnedConnection."""

    def __init__(self, directory):
        self.ca_file, cert_file, key_file = make_pki(directory)
        self.requests = []
        self.plan = None  # callable(path) -> Reply, or None for default_reply
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_GET(self):
                fake.requests.append({'method': 'GET', 'path': self.path,
                                      'headers': [(k.lower(), v) for k, v in self.headers.items()]})
                reply = (fake.plan or default_reply)(self.path)
                if reply.delay:
                    time.sleep(reply.delay)
                self.send_response(reply.status)
                for name, value in reply.headers:
                    self.send_header(name, value)
                if reply.mode == 'chunked':
                    self.send_header('Transfer-Encoding', 'chunked')
                    self.end_headers()
                    for start in range(0, len(reply.body), 1000):
                        chunk = reply.body[start:start + 1000]
                        self.wfile.write(b'%x\r\n' % len(chunk) + chunk + b'\r\n')
                    self.wfile.write(b'0\r\n\r\n')
                elif reply.mode == 'incomplete':
                    self.send_header('Content-Length', str(len(reply.body) + 100))
                    self.end_headers()
                    self.wfile.write(reply.body)
                    self.close_connection = True
                elif reply.mode == 'chunked-incomplete':
                    # One chunk announced longer than the data, then the connection closes.
                    self.send_header('Transfer-Encoding', 'chunked')
                    self.end_headers()
                    self.wfile.write(b'%x\r\n' % (len(reply.body) + 100) + reply.body)
                    self.close_connection = True
                else:
                    self.send_header('Content-Length', str(len(reply.body)))
                    self.end_headers()
                    self.wfile.write(reply.body)
                self.wfile.flush()
                self.close_connection = True

            do_POST = do_PUT = do_DELETE = do_GET

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Network:
    """Fake DNS and pinned connections: records lookups and approved addresses."""

    def __init__(self, vertical, answers=None):
        self.vertical, self.lookups, self.connections = vertical, [], []
        self.answers = answers if answers is not None else {HOST: [ADDRESS]}

    def resolver(self, host, port, type=None, *args, **kwargs):
        self.lookups.append((host, port))
        if host not in self.answers:
            raise socket.gaierror('fictitious name not found')
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port)) for ip in self.answers[host]]

    def connection_factory(self, host, port, address, timeout, context):
        self.connections.append((host, port, str(address)))
        connection = LoopbackPinnedConnection(host, port, address, timeout, context)
        connection.loopback_port = self.vertical.port
        return connection


class LoopbackPinnedConnection(PinnedHTTPSConnection):
    """Connects to the loopback fake while keeping SNI and TLS name verification of the registered host."""
    loopback_port = None

    def connect(self):
        plain = socket.create_connection(('127.0.0.1', self.loopback_port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(plain, server_hostname=self.host)
        except Exception:
            plain.close()
            raise
