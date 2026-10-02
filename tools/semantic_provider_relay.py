"""Bounded fixed-endpoint transport for the Semantic provider southbound adapter.

Gateway HTTP wiring, admission proofs and OS egress policy are separate installation
prerequisites. This module has no listening socket and must not be exposed directly.
"""
import contextlib
from dataclasses import dataclass
import http.client
import ipaddress
import json
import signal
import socket
import ssl
import threading
import time
from urllib.parse import urlencode, urlsplit

from tools.semantic_provider_boundary import (
    ProviderRequestDenied, validate_provider_endpoint, validate_search_form, validate_fetch_form,
)
from tools.southbound_security import RegisteredEndpoint, SouthboundDenied, validate_destination


class RelayDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderBinding:
    endpoint: str
    namespace_prefixes: tuple[str, ...]
    allowed_cidrs: tuple[str, ...] = ()
    max_request_bytes: int = 65536
    max_response_bytes: int = 8388608
    max_intent_chars: int = 2000
    timeout_seconds: int = 10
    ca_file: str | None = None

    def validate(self):
        validate_provider_endpoint(self.endpoint)
        if (not self.namespace_prefixes or type(self.max_request_bytes) is not int
                or not 1 <= self.max_request_bytes <= 65536 or type(self.max_response_bytes) is not int
                or not 1 <= self.max_response_bytes <= 8388608 or type(self.timeout_seconds) is not int
                or not 1 <= self.timeout_seconds <= 30):
            raise RelayDenied('PROVIDER_BINDING_INVALID')
        # Validate installed namespace boundaries without initiating a network call.
        sample = urlencode({'uri': self.namespace_prefixes[0] + 'binding-check'}).encode()
        validate_fetch_form(sample, max_bytes=self.max_request_bytes, namespace_prefixes=self.namespace_prefixes)
        for cidr in self.allowed_cidrs:
            ipaddress.ip_network(cidr)


@dataclass(frozen=True)
class ProviderResponse:
    body: bytes
    media_type: str
    rdf_scope: str | None = None


@contextlib.contextmanager
def request_deadline(seconds):
    # POSIX main-process execution bounds DNS, TCP, TLS, headers and body receipt.
    # A threaded HTTP adapter must use a separate bounded worker process instead.
    if threading.current_thread() is not threading.main_thread():
        raise RelayDenied('BOUNDED_WORKER_PROCESS_REQUIRED')
    previous = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    def expired(signum, frame):
        raise RelayDenied('PROVIDER_TIMEOUT')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, previous_timer[0]) if previous_timer[0] else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)
        if previous_timer[0]:
            remaining = previous_timer[0] - (time.monotonic() - started)
            if remaining <= 0:
                if callable(previous):
                    previous(signal.SIGALRM, None)
                else:
                    raise RelayDenied('PROVIDER_TIMEOUT')
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self.approved_address = ipaddress.ip_address(address)

    def connect(self):
        # Numeric socket connect avoids a second DNS lookup after admission.
        family = socket.AF_INET6 if self.approved_address.version == 6 else socket.AF_INET
        plain = socket.socket(family, socket.SOCK_STREAM)
        try:
            plain.settimeout(self.timeout)
            plain.connect((str(self.approved_address), self.port))
            self.sock = self._context.wrap_socket(plain, server_hostname=self.host)
        except Exception:
            plain.close()
            raise


def exchange(binding, form, *, accepted, resolver=socket.getaddrinfo, connection_factory=PinnedHTTPSConnection):
    binding.validate()
    parsed = urlsplit(binding.endpoint)
    port = parsed.port or 443
    registered = RegisteredEndpoint('https', parsed.hostname, port, binding.allowed_cidrs)
    try:
        with request_deadline(binding.timeout_seconds):
            addresses = validate_destination(binding.endpoint, registered, resolver)
            if not binding.allowed_cidrs and any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise SouthboundDenied('NON_GLOBAL_ADDRESS_UNREGISTERED')
            context = ssl.create_default_context(cafile=binding.ca_file)
            connection = connection_factory(parsed.hostname, port, addresses[0], binding.timeout_seconds, context)
            try:
                # Only technical headers are forwarded: no caller bearer, credential or arbitrary URL.
                connection.request('POST', parsed.path, body=form, headers={
                    'Accept': ','.join(sorted(accepted)), 'Accept-Encoding': 'identity',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                })
                with connection.getresponse() as response:
                    if response.status // 100 == 3:
                        raise RelayDenied('PROVIDER_REDIRECT_FORBIDDEN')
                    if response.status != 200:
                        raise RelayDenied('PROVIDER_HTTP_REJECTED')
                    values = response.headers.get_all('Content-Type', [])
                    media = values[0].split(';', 1)[0].strip().lower() if len(values) == 1 else ''
                    if media not in accepted:
                        raise RelayDenied('PROVIDER_MEDIA_TYPE_REJECTED')
                    encoding = response.headers.get('Content-Encoding', 'identity').strip().lower()
                    if encoding != 'identity':
                        raise RelayDenied('PROVIDER_ENCODING_REJECTED')
                    lengths = response.headers.get_all('Content-Length', [])
                    if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > binding.max_response_bytes)):
                        raise RelayDenied('PROVIDER_RESPONSE_TOO_LARGE')
                    if lengths and response.headers.get('Transfer-Encoding'):
                        raise RelayDenied('PROVIDER_FRAMING_REJECTED')
                    transfer = response.headers.get('Transfer-Encoding', '').strip().lower()
                    if transfer not in ('', 'chunked'):
                        raise RelayDenied('PROVIDER_FRAMING_REJECTED')
                    body = response.read(binding.max_response_bytes + 1)
                    if len(body) > binding.max_response_bytes:
                        raise RelayDenied('PROVIDER_RESPONSE_TOO_LARGE')
                    if lengths and len(body) != int(lengths[0]):
                        raise RelayDenied('PROVIDER_RESPONSE_INCOMPLETE')
                    return ProviderResponse(body, media)
            finally:
                connection.close()
    except (RelayDenied, ProviderRequestDenied, SouthboundDenied):
        raise
    except Exception:
        # No URL, provider response, caller intent or connection exception is exposed.
        raise RelayDenied('PROVIDER_UNAVAILABLE') from None


def search(binding, body, *, resolver=socket.getaddrinfo, connection_factory=PinnedHTTPSConnection):
    binding.validate()
    admitted = validate_search_form(body, max_bytes=binding.max_request_bytes, max_intent_chars=binding.max_intent_chars)
    form = urlencode({'query': admitted['query'], 'format': 'application/sparql-results+json'}).encode()
    response = exchange(binding, form, accepted={'application/sparql-results+json', 'application/json'},
                        resolver=resolver, connection_factory=connection_factory)
    try:
        payload = json.loads(response.body)
        rows = payload['results']['bindings']
        if not isinstance(rows, list) or len(rows) > 50 or any(not isinstance(row, dict) for row in rows):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise RelayDenied('PROVIDER_SEARCH_RESULT_INVALID') from None
    return response


def fetch(binding, body, *, resolver=socket.getaddrinfo, connection_factory=PinnedHTTPSConnection):
    binding.validate()
    admitted = validate_fetch_form(body, max_bytes=binding.max_request_bytes, namespace_prefixes=binding.namespace_prefixes)
    uri = admitted['canonicalUri']
    # IRI is query data only. No direct dereference, imports or recursive closure.
    # No LIMIT truncation: oversize/incomplete transport fails instead of returning a partial body.
    query = 'CONSTRUCT { <' + uri + '> ?p ?o . } WHERE { <' + uri + '> ?p ?o . }'
    form = urlencode({'query': query, 'format': 'text/turtle'}).encode()
    response = exchange(binding, form, accepted={'text/turtle'}, resolver=resolver, connection_factory=connection_factory)
    return ProviderResponse(response.body, response.media_type, 'OUTGOING_ASSERTED_SUBJECT_TRIPLES')
