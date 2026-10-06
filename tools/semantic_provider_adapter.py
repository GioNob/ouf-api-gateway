"""TLS-only bounded transport, invoked as python -B -m tools.semantic_provider_adapter.

Linux fork workers isolate elapsed-time limits and bound concurrent connections.
This is a Gateway transport component, not semantic discovery orchestration.
"""
import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ForkingMixIn
from urllib.parse import urlsplit

from tools import semantic_provider_relay as relay
from tools.semantic_provider_admission import AdmissionBinding, AdmissionDenied, HEADER, receipt_key, verify
from tools.semantic_provider_boundary import ProviderRequestDenied
from tools.southbound_security import SouthboundDenied


class AdapterDenied(ValueError):
    pass


def private_file(path, max_bytes):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() \
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > max_bytes:
            raise AdapterDenied('PRIVATE_FILE_REQUIRED')
        raw = os.read(fd, max_bytes + 1)
        if len(raw) > max_bytes:
            raise AdapterDenied('PRIVATE_FILE_REQUIRED')
        return raw
    finally:
        os.close(fd)


@dataclass(frozen=True)
class AdapterBinding:
    provider: relay.ProviderBinding
    admission: AdmissionBinding
    search_path: str
    fetch_path: str
    receipt_key: str
    request_timeout_seconds: int = 20

    def validate(self):
        self.provider.validate(); self.admission.validate(); receipt_key(self.receipt_key)
        for path in (self.search_path, self.fetch_path):
            if not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{1,200}', path) \
                    or '//' in path or path.endswith('/'):
                raise AdapterDenied('ADAPTER_PATH_INVALID')
        if self.search_path == self.fetch_path or type(self.request_timeout_seconds) is not int \
                or not 1 <= self.request_timeout_seconds <= 60:
            raise AdapterDenied('ADAPTER_BINDING_INVALID')


def dispatch(binding, method, target, headers, body, *, provider_search=relay.search, provider_fetch=relay.fetch):
    """Authenticate exact received bytes before grammar validation, DNS or provider I/O."""
    if not isinstance(target, str) or len(target) > 6144 or not target.isascii() \
            or re.search(r'[\x00-\x20\x7f]', target) or not target.startswith('/'):
        raise AdapterDenied('REQUEST_TARGET_INVALID')
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise AdapterDenied('REQUEST_TARGET_INVALID')
    operation = None
    if method == 'POST' and parsed.path == binding.search_path and not parsed.query:
        operation = 'search'
    if method == 'GET' and parsed.path == binding.fetch_path and parsed.query:
        operation = 'fetch'
    if operation is None:
        raise AdapterDenied('REQUEST_ROUTE_REJECTED')
    receipts = headers.get_all(HEADER, [])
    if len(receipts) != 1:
        raise AdmissionDenied('RECEIPT_INVALID')
    if headers.get_all('Authorization', []):
        raise AdmissionDenied('CALLER_CREDENTIAL_FORBIDDEN')
    if len(body) > binding.provider.max_request_bytes:
        raise AdapterDenied('REQUEST_TOO_LARGE')
    verify(binding.admission, binding.receipt_key, receipts[0], method, target, body)
    if operation == 'search':
        media = headers.get_all('Content-Type', [])
        if len(media) != 1 or media[0].lower() not in (
                'application/x-www-form-urlencoded', 'application/x-www-form-urlencoded; charset=utf-8'):
            raise AdapterDenied('REQUEST_MEDIA_REJECTED')
        return provider_search(binding.provider, body)
    if body:
        raise AdapterDenied('REQUEST_BODY_FORBIDDEN')
    return provider_fetch(binding.provider, parsed.query.encode('ascii'))


def handler_for(binding):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'OUF'; sys_version = ''; protocol_version = 'HTTP/1.0'

        def log_message(self, *args):
            pass  # Request URI, candidate query, receipts and credentials are never logged.

        def handle_request(self):
            self.close_connection = True
            status = 400; payload = b'{"error":"PROVIDER_REQUEST_REJECTED"}'; media = 'application/json'
            scope = None
            try:
                if len(self.path) > 6144 or self.headers.get_all('Transfer-Encoding', []) \
                        or self.headers.get_all('Content-Encoding', []) or self.headers.get_all('Expect', []):
                    raise AdapterDenied('REQUEST_FRAMING_REJECTED')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) > 1 or (lengths and not re.fullmatch(r'[0-9]{1,6}', lengths[0])):
                    raise AdapterDenied('REQUEST_FRAMING_REJECTED')
                size = int(lengths[0]) if lengths else 0
                if size > binding.provider.max_request_bytes or (self.command == 'POST' and not lengths):
                    raise AdapterDenied('REQUEST_TOO_LARGE')
                body = self.rfile.read(size)
                if len(body) != size:
                    raise AdapterDenied('REQUEST_INCOMPLETE')
                result = dispatch(binding, self.command, self.path, self.headers, body)
                status, payload, media, scope = 200, result.body, result.media_type, result.rdf_scope
            except AdmissionDenied:
                status = 403; payload = b'{"error":"PROVIDER_ADMISSION_DENIED"}'
            except (AdapterDenied, ProviderRequestDenied):
                pass
            except (relay.RelayDenied, SouthboundDenied):
                status = 502; payload = b'{"error":"PROVIDER_UNAVAILABLE"}'
            except Exception:
                status = 503; payload = b'{"error":"PROVIDER_UNAVAILABLE"}'
            self.send_response(status); self.send_header('Content-Type', media)
            self.send_header('Content-Length', str(len(payload))); self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            if scope:
                self.send_header('X-OUF-RDF-Scope', scope)
            self.end_headers(); self.wfile.write(payload)

        do_POST = handle_request
        do_GET = handle_request

        def send_error(self, code, message=None, explain=None):
            self.close_connection = True
            raw = b'{"error":"PROVIDER_REQUEST_REJECTED"}'
            self.send_response(code); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)

    return Handler


class BoundedTLSServer(ForkingMixIn, HTTPServer):
    block_on_close = True
    request_queue_size = 8

    def __init__(self, address, binding, context, max_children):
        if type(max_children) is not int or not 1 <= max_children <= 16:
            raise AdapterDenied('WORKER_LIMIT_INVALID')
        binding.validate()
        self.binding, self.context, self.max_children = binding, context, max_children
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler_for(binding))

    def finish_request(self, request, client_address):
        # Fork child is a main thread. TLS handshake, headers, body, relay and write
        # share one deadline, including slow/incomplete incoming connections.
        request.settimeout(self.binding.request_timeout_seconds)
        with relay.request_deadline(self.binding.request_timeout_seconds):
            with self.context.wrap_socket(request, server_side=True) as protected:
                self.RequestHandlerClass(protected, client_address, self)

    def handle_error(self, request, client_address):
        pass  # No traceback/exception may disclose queries, config paths or TLS data.


def load_configuration(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise AdapterDenied('CONFIGURATION_TOO_LARGE')
    cfg = json.loads(raw)
    expected = {'listenAddress', 'listenPort', 'maxWorkers', 'requestTimeoutSeconds',
                'searchPath', 'fetchPath', 'provider', 'admission', 'receiptKeyFile',
                'tlsCertificateFile', 'tlsPrivateKeyFile'}
    if not isinstance(cfg, dict) or set(cfg) != expected:
        raise AdapterDenied('CONFIGURATION_INVALID')
    if not isinstance(cfg['listenAddress'], str) or not cfg['listenAddress'] \
            or type(cfg['listenPort']) is not int or not 1 <= cfg['listenPort'] <= 65535:
        raise AdapterDenied('LISTENER_BINDING_INVALID')
    key = private_file(cfg['receiptKeyFile'], 256).decode('ascii').strip()
    binding = AdapterBinding(relay.ProviderBinding(**cfg['provider']), AdmissionBinding(**cfg['admission']),
                             cfg['searchPath'], cfg['fetchPath'], key, cfg['requestTimeoutSeconds'])
    binding.validate()
    private_file(cfg['tlsPrivateKeyFile'], 32768)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg['tlsCertificateFile'], cfg['tlsPrivateKeyFile'])
    return cfg, binding, context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() == 0:
            raise AdapterDenied('NON_ROOT_REQUIRED')
        cfg, binding, context = load_configuration(args.configuration)
        with BoundedTLSServer((cfg['listenAddress'], cfg['listenPort']), binding, context, cfg['maxWorkers']) as server:
            server.serve_forever()
    except Exception:
        print('SEMANTIC_PROVIDER_ADAPTER=BLOCKED NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
