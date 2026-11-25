"""Gateway-owned southbound `fetch` adapter for `ouf.vertical-source.v1` (task-61f-a).

Invoked as `python -B -m tools.source_api_adapter --configuration <file>` behind APISIX,
on the model of the Semantic provider transport (`tools/semantic_provider_adapter.py`).

Boundaries:
- APISIX performs OIDC admission (issuer, audience, technical scope, SERVICE actor,
  workload client) and mints a short receipt bound to tenant, workload, method, target
  and body hash. This process re-verifies the receipt over the exact received bytes and
  never trusts caller identity headers or bearer tokens.
- The binding registry, the credentials (`secret://<name>`) and the trust anchors
  (`trust://<name>`) are private installation files referenced by name, never by path.
- The call towards the vertical is built only from fixed templates (closed grammar):
  no free path, no caller header, no `/admin`. DNS answers are verified against the
  binding networks, the connection goes to the verified address with SNI and TLS name
  verification, redirects are refused, one attempt only, one deadline for DNS, TLS and
  body. Retry and budget belong to the caller (ouf.source-api.v1 section 2.2).
- Logs carry only code, duration, bytes and the validated correlation identifier.
"""
import argparse
import contextlib
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ForkingMixIn
from urllib.parse import quote, urlencode

from tools.semantic_provider_admission import AdmissionDenied, no_duplicates, receipt_key, request_hash
from tools.semantic_provider_relay import PinnedHTTPSConnection, RelayDenied, request_deadline
from tools.southbound_security import RegisteredEndpoint, SouthboundDenied, validate_destination

REGISTRY_SCHEMA = 'ouf.source-api-binding-registry.v1'
CONTRACT = 'ouf.vertical-source.v1'
PURPOSE = 'ouf-source-api-fetch-v1'
HEADER = 'X-OUF-Source-Fetch-Receipt'
RECEIPT_FIELDS = {'purpose', 'installation', 'issuer', 'audience', 'workload', 'tenant',
                  'subject', 'actor', 'scope', 'requestHash', 'iat', 'exp'}
ROLES = ('INGESTION', 'ONBOARDING')
# ouf.source-api.v1 section 2.2: Onboarding reads only COLLECTIONS and SCHEMA; ITEMS is Ingestion only.
RESOURCE_ROLES = {'COLLECTIONS': frozenset(ROLES), 'SCHEMA': frozenset(ROLES), 'ITEMS': frozenset({'INGESTION'})}

NAME = r'[a-z0-9][a-z0-9-]{0,62}'
BINDING_REF = re.compile(r'gateway://sources/' + NAME)
COLLECTION = re.compile(r'[a-z][a-z0-9_-]{0,62}')
LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
ORIGIN = re.compile(r'https://(' + LABEL + r'(?:\.' + LABEL + r')*)(?::([1-9][0-9]{0,4}))?')
TENANT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}')
# Opaque source tokens are always percent-encoded query values; this alphabet covers
# base64, base64url, hex and UUID tokens and excludes every URL delimiter but '/'.
TOKEN = re.compile(r'[A-Za-z0-9._~+/=-]{1,4096}')
BEARER = re.compile(r'[A-Za-z0-9._~+/-]{16,4096}=*')
CORRELATION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}')
OPAQUE = re.compile(r'[A-Za-z0-9._:-]{1,128}')
SOURCE_CODE = re.compile(r'[A-Z][A-Z0-9_]{0,63}')
RFC3339 = re.compile(r'[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]'
                     r'(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])')
TIMEOUT = re.compile(r'PT([1-9]|[1-5][0-9]|60)S')
CONTROL = re.compile('[\u0000-\u001f\u007f-\u009f]')
MAX_REGISTRY_BYTES = 1048576
MAX_REQUEST_BYTES = 16384
MAX_ERROR_BYTES = 65536
MAX_RETRY_AFTER = 86400
ITEM_MODES = {
    None: frozenset(),
    'CURSOR': frozenset({'cursor'}),
    'WATERMARK': frozenset({'cursor', 'changedSince', 'afterId'}),
    'SNAPSHOT': frozenset({'page'}),
}
QUERY_ORDER = ('mode', 'limit', 'cursor', 'changedSince', 'afterId', 'page')


class ConfigurationDenied(ValueError):
    pass


class SourceFailure(Exception):
    """Typed error returned to the caller (ouf.source-api.v1 section 2.2).

    The body is closed: code, plus reason, schemaVersion, epoch and retryAfter when known.
    `log` is a safe internal cause for the log line; it never reaches the caller.
    """
    STATUS = {
        'SOURCE_CURSOR_EXPIRED': 410,
        'SOURCE_RATE_LIMITED': 429,
        'SOURCE_UNAVAILABLE': 503,
        'SOURCE_CREDENTIAL_REJECTED': 502,
        'SOURCE_RESPONSE_TOO_LARGE': 502,
        'SOURCE_RESPONSE_INVALID': 502,
        'SOURCE_REQUEST_REJECTED': 422,
        'SOURCE_BINDING_NOT_ALLOWED': 403,
        'SOURCE_ADMISSION_DENIED': 403,
        'SOURCE_REQUEST_INVALID': 400,
    }

    def __init__(self, code, *, reason=None, schema_version=None, epoch=None, retry_after=None, log=None):
        if code not in self.STATUS:
            raise ValueError('SOURCE_CODE_UNKNOWN')
        super().__init__(code)
        self.code, self.reason, self.schema_version, self.epoch = code, reason, schema_version, epoch
        self.retry_after, self.log = retry_after, log or code

    @property
    def status(self):
        return self.STATUS[self.code]

    def body(self):
        value = {'code': self.code}
        for key, item in (('reason', self.reason), ('schemaVersion', self.schema_version),
                          ('epoch', self.epoch), ('retryAfter', self.retry_after)):
            if item is not None:
                value[key] = item
        return json.dumps(value, separators=(',', ':'), sort_keys=True).encode('ascii')

    def headers(self):
        return {'Retry-After': str(self.retry_after)} if self.retry_after is not None else {}


def not_allowed():
    # Identical answer for unknown, inactive, foreign-tenant, out-of-scope binding or resource.
    return SourceFailure('SOURCE_BINDING_NOT_ALLOWED')


def invalid(cause):
    return SourceFailure('SOURCE_REQUEST_INVALID', log='REQUEST_' + cause)


def _reject_constant(value):
    raise ValueError('JSON_CONSTANT_FORBIDDEN')


def _strict_pairs(pairs):
    try:
        return no_duplicates(pairs)
    except AdmissionDenied:
        raise ValueError('JSON_DUPLICATE_KEY') from None


def strict_json(raw, *, floats=True):
    kwargs = {'object_pairs_hook': _strict_pairs, 'parse_constant': _reject_constant}
    if not floats:
        kwargs['parse_float'] = _reject_constant
    try:
        return json.loads(raw.decode('utf-8'), **kwargs)
    except RecursionError:
        # A deeply nested document is malformed input, never an adapter failure (review 61f-a).
        raise ValueError('JSON_TOO_DEEP') from None


def _text(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit and not CONTROL.search(value)


def _utf8_length(value):
    # JSON admits lone surrogates; they cannot be percent-encoded, so they are a grammar error.
    try:
        return len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return None


def private_file(path, max_bytes):
    """Read a custodian-mapped file: regular, single link, owned by this process, no group/other bits."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() \
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > max_bytes:
            raise ConfigurationDenied('PRIVATE_FILE_REQUIRED')
        raw = os.read(fd, max_bytes + 1)
        if len(raw) > max_bytes:
            raise ConfigurationDenied('PRIVATE_FILE_REQUIRED')
        return raw
    finally:
        os.close(fd)


# --- binding registry -------------------------------------------------------------------

@dataclass(frozen=True)
class Limits:
    max_page_bytes: int
    timeout_seconds: int
    max_requests_per_minute: int
    max_concurrency: int


@dataclass(frozen=True)
class Binding:
    ref: str
    title: str
    host: str
    port: int
    allowed_networks: tuple
    credential_name: str
    trust_name: str | None
    tenants: frozenset
    collections: frozenset | None  # None means every collection of the source ("*")
    limits: Limits
    active: bool

    def allows(self, collection):
        return self.collections is None or collection in self.collections


BINDING_REQUIRED = {'bindingRef', 'title', 'contract', 'origin', 'allowedNetworks', 'credentialRef',
                    'tenants', 'collections', 'limits', 'status'}
BINDING_OPTIONAL = {'trustRef'}
LIMIT_KEYS = {'maxPageBytes', 'timeout', 'maxRequestsPerMinute', 'maxConcurrency'}


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _unique_list(value, low, high):
    return isinstance(value, list) and low <= len(value) <= high and len(set(map(json.dumps, value))) == len(value)


def parse_binding(entry):
    if not isinstance(entry, dict) or not BINDING_REQUIRED <= set(entry) \
            or set(entry) - BINDING_REQUIRED - BINDING_OPTIONAL:
        raise ConfigurationDenied('BINDING_INVALID')
    ref = entry['bindingRef']
    if not isinstance(ref, str) or not BINDING_REF.fullmatch(ref) or not _text(entry['title'], 200) \
            or entry['contract'] != CONTRACT or entry['status'] not in ('ACTIVE', 'INACTIVE'):
        raise ConfigurationDenied('BINDING_INVALID')
    origin = entry['origin']
    match = ORIGIN.fullmatch(origin) if isinstance(origin, str) and len(origin) <= 270 else None
    port = int(match.group(2)) if match and match.group(2) else 443
    if not match or len(match.group(1)) > 253 or not 1 <= port <= 65535:
        raise ConfigurationDenied('BINDING_ORIGIN_INVALID')
    networks = entry['allowedNetworks']
    if not _unique_list(networks, 1, 16) or any(not isinstance(n, str) or len(n) > 49 for n in networks):
        raise ConfigurationDenied('BINDING_NETWORKS_INVALID')
    try:
        parsed_networks = tuple(str(ipaddress.ip_network(n, strict=True)) for n in networks)
    except ValueError:
        raise ConfigurationDenied('BINDING_NETWORKS_INVALID') from None
    credential = entry['credentialRef']
    if isinstance(credential, str) and re.fullmatch('workload://' + NAME, credential):
        # ouf.source-api.v1 section 2.1: refused until a workload identity provider is configured.
        raise ConfigurationDenied('CREDENTIAL_PROVIDER_UNAVAILABLE')
    if not isinstance(credential, str) or not re.fullmatch('secret://' + NAME, credential):
        raise ConfigurationDenied('BINDING_CREDENTIAL_INVALID')
    trust = entry.get('trustRef')
    if trust is not None and (not isinstance(trust, str) or not re.fullmatch('trust://' + NAME, trust)):
        raise ConfigurationDenied('BINDING_TRUST_INVALID')
    tenants = entry['tenants']
    if not _unique_list(tenants, 1, 64) or any(not isinstance(t, str) or not TENANT.fullmatch(t) for t in tenants):
        raise ConfigurationDenied('BINDING_TENANTS_INVALID')
    collections = entry['collections']
    if collections == ['*']:
        allowed = None
    elif _unique_list(collections, 1, 256) and all(isinstance(c, str) and COLLECTION.fullmatch(c) for c in collections):
        allowed = frozenset(collections)
    else:
        raise ConfigurationDenied('BINDING_COLLECTIONS_INVALID')
    limits = entry['limits']
    if not isinstance(limits, dict) or set(limits) != LIMIT_KEYS \
            or not _int(limits['maxPageBytes'], 1024, 50000000) \
            or not isinstance(limits['timeout'], str) or not TIMEOUT.fullmatch(limits['timeout']) \
            or not _int(limits['maxRequestsPerMinute'], 1, 6000) or not _int(limits['maxConcurrency'], 1, 16):
        raise ConfigurationDenied('BINDING_LIMITS_INVALID')
    return Binding(ref, entry['title'], match.group(1), port, parsed_networks, credential[len('secret://'):],
                   trust[len('trust://'):] if trust else None, frozenset(tenants), allowed,
                   Limits(limits['maxPageBytes'], int(TIMEOUT.fullmatch(limits['timeout']).group(1)),
                          limits['maxRequestsPerMinute'], limits['maxConcurrency']),
                   entry['status'] == 'ACTIVE')


def load_registry(raw):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_REGISTRY_BYTES:
        raise ConfigurationDenied('REGISTRY_TOO_LARGE')
    try:
        document = strict_json(bytes(raw))
    except (ValueError, UnicodeError):
        raise ConfigurationDenied('REGISTRY_INVALID') from None
    if not isinstance(document, dict) or set(document) != {'schema', 'revision', 'bindings'} \
            or document['schema'] != REGISTRY_SCHEMA or not _int(document['revision'], 1, 2 ** 63 - 1) \
            or not isinstance(document['bindings'], list) or len(document['bindings']) > 256:
        raise ConfigurationDenied('REGISTRY_INVALID')
    bindings = {}
    for entry in document['bindings']:
        binding = parse_binding(entry)
        if binding.ref in bindings:
            raise ConfigurationDenied('REGISTRY_DUPLICATE_BINDING')
        bindings[binding.ref] = binding
    return document['revision'], bindings


# --- admission receipt ------------------------------------------------------------------

@dataclass(frozen=True)
class Admission:
    installation: str
    issuer: str
    audience: str
    scope: str
    workloads: dict = field(hash=False)  # role -> workload client identifier, from the installation projection

    def validate(self):
        values = [self.installation, self.issuer, self.audience, self.scope]
        if not isinstance(self.workloads, dict) or set(self.workloads) != set(ROLES):
            raise AdmissionDenied('ADMISSION_BINDING_INVALID')
        values += list(self.workloads.values())
        if any(not isinstance(v, str) or not v or len(v) > 512 or not v.isascii()
               or re.search(r'[\x00-\x20\x7f]', v) for v in values):
            raise AdmissionDenied('ADMISSION_BINDING_INVALID')
        if not self.issuer.startswith('https://') or len(set(self.workloads.values())) != len(ROLES):
            raise AdmissionDenied('ADMISSION_BINDING_INVALID')

    def role(self, workload):
        return next((role for role, client in self.workloads.items() if client == workload), None)


def sign_receipt(key, claims):
    """Reference signer, used by tests and by the APISIX parity gate of 61f-b."""
    encoded = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':'), sort_keys=True).encode()).decode().rstrip('=')
    return encoded + '.' + hmac.new(receipt_key(key), (PURPOSE + '.' + encoded).encode('ascii'), hashlib.sha256).hexdigest()


def verify_receipt(admission, key, receipt, method, target, body, *, now=None):
    admission.validate()
    key_bytes = receipt_key(key)
    if not isinstance(receipt, str) or len(receipt) > 4096:
        raise AdmissionDenied('RECEIPT_INVALID')
    match = re.fullmatch(r'([A-Za-z0-9_-]+)\.([0-9a-f]{64})', receipt)
    if not match:
        raise AdmissionDenied('RECEIPT_INVALID')
    encoded, signature = match.groups()
    expected = hmac.new(key_bytes, (PURPOSE + '.' + encoded).encode('ascii'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AdmissionDenied('RECEIPT_INVALID')
    try:
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        if base64.urlsafe_b64encode(raw).decode().rstrip('=') != encoded:
            raise ValueError()
        claims = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeError):
        raise AdmissionDenied('RECEIPT_INVALID') from None
    if not isinstance(claims, dict) or set(claims) != RECEIPT_FIELDS:
        raise AdmissionDenied('RECEIPT_INVALID')
    required = {'purpose': PURPOSE, 'installation': admission.installation, 'issuer': admission.issuer,
                'audience': admission.audience, 'actor': 'SERVICE', 'scope': admission.scope,
                'requestHash': request_hash(method, target, body)}
    if any(claims[k] != value for k, value in required.items()):
        raise AdmissionDenied('RECEIPT_CONTEXT_REJECTED')
    role = admission.role(claims['workload']) if isinstance(claims['workload'], str) else None
    if role is None or not isinstance(claims['tenant'], str) or not TENANT.fullmatch(claims['tenant']) \
            or not isinstance(claims['subject'], str) or not claims['subject'] or len(claims['subject']) > 512 \
            or re.search(r'[\x00-\x20\x7f]', claims['subject']):
        raise AdmissionDenied('RECEIPT_CONTEXT_REJECTED')
    instant = time.time() if now is None else now
    if type(claims['iat']) is not int or type(claims['exp']) is not int \
            or not claims['iat'] <= instant < claims['exp'] or not 0 < claims['exp'] - claims['iat'] <= 30:
        raise AdmissionDenied('RECEIPT_EXPIRED')
    # READ-only transport: a receipt can be replayed until its short expiry, like the provider receipts.
    return claims['tenant'], role


# --- request grammar --------------------------------------------------------------------

@dataclass(frozen=True)
class FetchRequest:
    binding_ref: str
    resource: str
    collection: str | None
    path: str
    query: tuple
    correlation: str


def _timestamp(value):
    return isinstance(value, str) and len(value) <= 40 and RFC3339.fullmatch(value) is not None


def parse_request(body):
    """Closed grammar of ouf.source-api.v1 section 2.2; the vertical path comes only from fixed templates."""
    if len(body) > MAX_REQUEST_BYTES:
        raise invalid('TOO_LARGE')
    try:
        document = strict_json(body, floats=False)
    except (ValueError, UnicodeError):
        raise invalid('JSON') from None
    if not isinstance(document, dict) or set(document) != {'bindingRef', 'parameters', 'correlationId'}:
        raise invalid('SHAPE')
    ref, parameters, correlation = document['bindingRef'], document['parameters'], document['correlationId']
    if not isinstance(ref, str) or not BINDING_REF.fullmatch(ref):
        raise invalid('BINDING_REF')
    if not isinstance(correlation, str) or not CORRELATION.fullmatch(correlation):
        raise invalid('CORRELATION')
    if not isinstance(parameters, dict) or not isinstance(parameters.get('resource'), str) \
            or parameters['resource'] not in RESOURCE_ROLES:
        raise invalid('RESOURCE')
    resource = parameters['resource']
    if resource == 'COLLECTIONS':
        if set(parameters) != {'resource'}:
            raise invalid('PARAMETERS')
        return FetchRequest(ref, resource, None, '/collections', (), correlation)
    collection = parameters.get('collection')
    if not isinstance(collection, str) or not COLLECTION.fullmatch(collection):
        raise invalid('COLLECTION')
    if resource == 'SCHEMA':
        if set(parameters) != {'resource', 'collection'}:
            raise invalid('PARAMETERS')
        return FetchRequest(ref, resource, collection, '/collections/' + collection + '/schema', (), correlation)
    mode = parameters.get('mode')
    if 'mode' in parameters and mode not in ('CURSOR', 'WATERMARK', 'SNAPSHOT'):
        raise invalid('MODE')
    allowed = {'resource', 'collection', 'limit'} | ({'mode'} if 'mode' in parameters else set()) | ITEM_MODES[mode]
    if set(parameters) - allowed:
        raise invalid('PARAMETERS')
    if 'limit' in parameters and not _int(parameters['limit'], 1, 1000):
        raise invalid('LIMIT')
    for name in ('cursor', 'page'):
        if name in parameters and (not isinstance(parameters[name], str) or not TOKEN.fullmatch(parameters[name])):
            raise invalid('TOKEN')
    if mode == 'WATERMARK':
        # First page: changedSince (+ afterId); continuation: cursor only.
        if ('cursor' in parameters) == ('changedSince' in parameters):
            raise invalid('POSITION')
        if 'changedSince' in parameters and not _timestamp(parameters['changedSince']):
            raise invalid('CHANGED_SINCE')
        if 'afterId' in parameters and ('changedSince' not in parameters
                                        or not _text(parameters['afterId'], 256)
                                        or not 0 < (_utf8_length(parameters['afterId']) or 0) <= 1024):
            raise invalid('AFTER_ID')
    query = tuple((name, str(parameters[name])) for name in QUERY_ORDER if name in parameters)
    return FetchRequest(ref, resource, collection, '/collections/' + collection + '/items', query, correlation)


def target_of(request):
    if not request.query:
        return request.path
    # Every value is percent-encoded with no safe character: a token can never alter path or host.
    return request.path + '?' + urlencode(request.query, quote_via=quote, safe='')


# --- limits -----------------------------------------------------------------------------

class BindingLimiter:
    """Per-binding concurrency and rate shared across forked workers through flock files.

    Locks are released by the kernel when a worker exits, so a crash never leaks a slot.
    """

    def __init__(self, directory, clock=time.time):
        self.directory, self.clock = directory, clock

    def _open(self, name):
        return os.open(os.path.join(self.directory, name),
                       os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o600)

    @contextlib.contextmanager
    def admit(self, binding):
        import fcntl
        key = hashlib.sha256(binding.ref.encode('ascii')).hexdigest()[:32]
        slot = None
        for index in range(binding.limits.max_concurrency):
            fd = self._open(key + '.slot' + str(index))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                slot = fd
                break
            except BlockingIOError:
                os.close(fd)
        if slot is None:
            raise SourceFailure('SOURCE_UNAVAILABLE', retry_after=1, log='BINDING_CONCURRENCY_LIMIT')
        try:
            self._rate(fcntl, key, binding.limits.max_requests_per_minute)
            yield
        finally:
            os.close(slot)

    def _rate(self, fcntl, key, limit):
        fd = self._open(key + '.rate')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            instant = self.clock()
            raw = os.pread(fd, 8 * 6001, 0)
            values = struct.unpack('<%dd' % (len(raw) // 8), raw[:len(raw) // 8 * 8]) if raw else ()
            window = sorted(v for v in values if instant - 60 < v <= instant + 5)
            if len(window) >= limit:
                wait = min(60, max(1, math.ceil(window[-limit] + 60 - instant)))
                raise SourceFailure('SOURCE_RATE_LIMITED', retry_after=wait, log='BINDING_RATE_LIMIT')
            window.append(instant)
            data = struct.pack('<%dd' % len(window), *window[-6000:])
            os.ftruncate(fd, 0)
            os.pwrite(fd, data, 0)
        finally:
            os.close(fd)


# --- transport and interpretation -------------------------------------------------------

@dataclass(frozen=True)
class Upstream:
    status: int
    headers: dict
    body: bytes


@dataclass(frozen=True)
class Result:
    status: int
    body: bytes
    headers: dict


def exchange(binding, target, token, *, trust_file, resolver, connection_factory):
    """One GET towards the verified address of the registered origin, inside one deadline."""
    registered = RegisteredEndpoint('https', binding.host, binding.port, binding.allowed_networks)
    origin = 'https://' + binding.host + ('' if binding.port == 443 else ':' + str(binding.port))
    limit_ok = binding.limits.max_page_bytes
    try:
        with request_deadline(binding.limits.timeout_seconds):
            addresses = validate_destination(origin + target, registered, resolver)
            context = ssl.create_default_context(cafile=trust_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = connection_factory(binding.host, binding.port, addresses[0],
                                            binding.limits.timeout_seconds, context)
            try:
                # Only technical headers: the caller's headers and bearer never reach the vertical.
                connection.request('GET', target, headers={
                    'Accept': 'application/json', 'Accept-Encoding': 'identity',
                    'Authorization': 'Bearer ' + token, 'User-Agent': 'ouf-gateway-source-api/1',
                })
                with connection.getresponse() as response:
                    status = response.status
                    if 300 <= status < 400:
                        raise SourceFailure('SOURCE_RESPONSE_INVALID', log='REDIRECT_FORBIDDEN')
                    encoding = response.headers.get_all('Content-Encoding', []) or []
                    if any(value.strip().lower() != 'identity' for value in encoding):
                        raise SourceFailure('SOURCE_RESPONSE_INVALID', log='ENCODING_REJECTED')
                    lengths = response.headers.get_all('Content-Length', []) or []
                    transfer = response.headers.get_all('Transfer-Encoding', []) or []
                    if len(lengths) > 1 or (lengths and not lengths[0].strip().isdigit()) \
                            or (lengths and transfer) or any(v.strip().lower() != 'chunked' for v in transfer):
                        raise SourceFailure('SOURCE_RESPONSE_INVALID', log='FRAMING_REJECTED')
                    limit = limit_ok if status == 200 else MAX_ERROR_BYTES
                    declared = int(lengths[0]) if lengths else None
                    if status == 200 and declared is not None and declared > limit:
                        raise SourceFailure('SOURCE_RESPONSE_TOO_LARGE')
                    body = response.read(limit + 1)
                    if len(body) > limit:
                        if status == 200:
                            raise SourceFailure('SOURCE_RESPONSE_TOO_LARGE')
                        # An oversized error body is not interpreted; the status mapping still applies.
                        body = b''
                    elif declared is not None and len(body) != declared:
                        # http.client returns a short read when the peer closes early: compare with the framing.
                        raise SourceFailure('SOURCE_UNAVAILABLE', log='RESPONSE_INCOMPLETE')
                    headers = {name: response.headers.get_all(name, []) or []
                               for name in ('Content-Type', 'X-Schema-Version', 'Retry-After')}
                    return Upstream(status, headers, body)
            finally:
                connection.close()
    except SourceFailure:
        raise
    except SouthboundDenied as denied:
        raise SourceFailure('SOURCE_UNAVAILABLE', log='EGRESS_' + str(denied)) from None
    except RelayDenied:
        raise SourceFailure('SOURCE_UNAVAILABLE', log='DEADLINE_EXCEEDED') from None
    except ssl.SSLError:
        raise SourceFailure('SOURCE_UNAVAILABLE', log='TLS_REJECTED') from None
    except (http.client.HTTPException, OSError):
        raise SourceFailure('SOURCE_UNAVAILABLE', log='TRANSPORT_FAILED') from None
    except Exception:
        # No URL, query, token or source response appears in an exception.
        raise SourceFailure('SOURCE_UNAVAILABLE', log='TRANSPORT_FAILED') from None


def _retry_after(headers):
    values = headers.get('Retry-After', [])
    if len(values) == 1 and re.fullmatch(r'[0-9]{1,9}', values[0].strip()):
        seconds = int(values[0].strip())
        if seconds > 0:
            return min(seconds, MAX_RETRY_AFTER)
    return None


def _opaque(value):
    return value if isinstance(value, str) and OPAQUE.fullmatch(value) else None


def _error_document(body):
    try:
        document = strict_json(body) if body else None
    except (ValueError, UnicodeError):
        return {}
    return document if isinstance(document, dict) else {}


def _error_version(headers, document):
    values = headers.get('X-Schema-Version', [])
    header = _opaque(values[0].strip()) if len(values) == 1 else None
    return header or _opaque(document.get('schemaVersion'))


def interpret(request, binding, upstream):
    status, headers, body = upstream.status, upstream.headers, upstream.body
    if status != 200:
        document = _error_document(body)
        version = _error_version(headers, document)
        if status == 410:
            reason = document.get('reason') if document.get('reason') in ('RETENTION', 'EPOCH_CHANGED') else None
            return SourceFailure('SOURCE_CURSOR_EXPIRED', reason=reason, schema_version=version,
                                 epoch=_opaque(document.get('epoch')))
        if status == 429:
            return SourceFailure('SOURCE_RATE_LIMITED', schema_version=version, retry_after=_retry_after(headers))
        if status == 503:
            return SourceFailure('SOURCE_UNAVAILABLE', schema_version=version, retry_after=_retry_after(headers))
        if status in (401, 403):
            return SourceFailure('SOURCE_CREDENTIAL_REJECTED')
        if status in (400, 404, 409):
            code = document.get('code')
            return SourceFailure('SOURCE_REQUEST_REJECTED', schema_version=version,
                                 reason=code if isinstance(code, str) and SOURCE_CODE.fullmatch(code) else None)
        return SourceFailure('SOURCE_UNAVAILABLE', log='SOURCE_STATUS_' + str(status))
    media = headers.get('Content-Type', [])
    if len(media) != 1 or media[0].split(';', 1)[0].strip().lower() != 'application/json':
        return SourceFailure('SOURCE_RESPONSE_INVALID', log='MEDIA_REJECTED')
    try:
        document = strict_json(body)
    except (ValueError, UnicodeError):
        return SourceFailure('SOURCE_RESPONSE_INVALID', log='JSON_REJECTED')
    if not isinstance(document, dict):
        return SourceFailure('SOURCE_RESPONSE_INVALID', log='JSON_REJECTED')
    header_values = headers.get('X-Schema-Version', [])
    header_version = header_values[0].strip() if len(header_values) == 1 else None
    body_version = document.get('schemaVersion')
    # D-076: every authenticated response declares its schema version; header and body must agree.
    if (header_version is None and body_version is None) or len(header_values) > 1 \
            or (header_version is not None and not _opaque(header_version)) \
            or (body_version is not None and not _opaque(body_version)) \
            or (header_version is not None and body_version is not None and header_version != body_version):
        return SourceFailure('SOURCE_RESPONSE_INVALID', log='SCHEMA_VERSION_REJECTED')
    epoch = document.get('epoch')
    if epoch is not None and not _opaque(epoch):
        return SourceFailure('SOURCE_RESPONSE_INVALID', log='EPOCH_REJECTED')
    if request.collection is not None and document.get('collection') != request.collection:
        return SourceFailure('SOURCE_RESPONSE_INVALID', log='COLLECTION_MISMATCH')
    version = body_version or header_version
    extra = {}
    if request.resource == 'COLLECTIONS' and binding.collections is not None:
        filtered = filter_catalog(document, binding.collections)
        if filtered is None:
            return SourceFailure('SOURCE_RESPONSE_INVALID', log='CATALOG_REJECTED')
        body, version = filtered
        extra['X-Ouf-Catalog-Filtered'] = 'true'
    out = {'Content-Type': 'application/json', 'X-Ouf-Source-Schema-Version': version, **extra}
    if epoch is not None:
        out['X-Ouf-Source-Epoch'] = epoch
    return Result(200, body, out)


def catalog_digest(pairs):
    """ouf.vertical-mock.v1 section 3: SHA-256 of the JCS of [[collection, schemaVersion], ...] sorted."""
    canonical = json.dumps(sorted(pairs), ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def filter_catalog(document, allowed):
    rows = document.get('collections')
    if not isinstance(rows, list) or any(not isinstance(r, dict) or not isinstance(r.get('collection'), str)
                                         or not COLLECTION.fullmatch(r['collection'])
                                         or not _opaque(r.get('schemaVersion')) for r in rows):
        return None
    kept = [row for row in rows if row['collection'] in allowed]
    digest = catalog_digest([[row['collection'], row['schemaVersion']] for row in kept])
    filtered = dict(document)
    filtered['collections'] = kept
    filtered['schemaVersion'] = digest
    return json.dumps(filtered, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), digest


# --- adapter ----------------------------------------------------------------------------

@dataclass
class Trace:
    correlation: str | None = None
    code: str = 'SOURCE_UNAVAILABLE'
    bytes: int = 0


@dataclass(frozen=True)
class AdapterConfiguration:
    fetch_path: str
    admission: Admission
    receipt_key: str
    registry_file: str
    secrets_directory: str
    trust_directory: str | None
    state_directory: str
    request_timeout_seconds: int

    def validate(self):
        self.admission.validate()
        receipt_key(self.receipt_key)
        if not isinstance(self.fetch_path, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{1,200}', self.fetch_path) \
                or '//' in self.fetch_path or self.fetch_path.endswith('/'):
            raise ConfigurationDenied('ADAPTER_PATH_INVALID')
        if not _int(self.request_timeout_seconds, 2, 120):
            raise ConfigurationDenied('ADAPTER_TIMEOUT_INVALID')
        for directory in (self.secrets_directory, self.state_directory) + \
                ((self.trust_directory,) if self.trust_directory is not None else ()):
            if not isinstance(directory, str) or not os.path.isabs(directory):
                raise ConfigurationDenied('ADAPTER_DIRECTORY_INVALID')

    def registry(self):
        try:
            return load_registry(private_file(self.registry_file, MAX_REGISTRY_BYTES))[1]
        except (ConfigurationDenied, OSError):
            raise SourceFailure('SOURCE_UNAVAILABLE', log='REGISTRY_UNAVAILABLE') from None

    def credential(self, binding):
        try:
            raw = private_file(os.path.join(self.secrets_directory, binding.credential_name), 8192)
            token = raw.decode('ascii').strip()
        except (ConfigurationDenied, OSError, UnicodeError):
            raise SourceFailure('SOURCE_UNAVAILABLE', log='CREDENTIAL_UNAVAILABLE') from None
        if not BEARER.fullmatch(token):
            raise SourceFailure('SOURCE_UNAVAILABLE', log='CREDENTIAL_UNAVAILABLE')
        return token

    def trust(self, binding):
        if binding.trust_name is None:
            return None
        if self.trust_directory is None:
            raise SourceFailure('SOURCE_UNAVAILABLE', log='TRUST_UNAVAILABLE')
        path = os.path.join(self.trust_directory, binding.trust_name)
        try:
            info = os.lstat(path)
        except OSError:
            raise SourceFailure('SOURCE_UNAVAILABLE', log='TRUST_UNAVAILABLE') from None
        if not stat.S_ISREG(info.st_mode):
            raise SourceFailure('SOURCE_UNAVAILABLE', log='TRUST_UNAVAILABLE')
        return path


def dispatch(config, method, target, headers, body, *, trace=None, resolver=socket.getaddrinfo,
             connection_factory=PinnedHTTPSConnection, limiter=None, now=None):
    """Authenticate the exact received bytes, then grammar, binding, limits, secret and transport."""
    trace = trace or Trace()
    if method != 'POST' or target != config.fetch_path:
        raise invalid('ROUTE')
    receipts = headers.get_all(HEADER, []) or []
    if len(receipts) != 1 or headers.get_all('Authorization', []):
        # The caller's bearer stops at APISIX; it must never reach the adapter or the vertical.
        raise SourceFailure('SOURCE_ADMISSION_DENIED', log='RECEIPT_MISSING_OR_BEARER_PRESENT')
    media = headers.get_all('Content-Type', []) or []
    if len(media) != 1 or media[0].split(';', 1)[0].strip().lower() != 'application/json':
        raise invalid('MEDIA')
    try:
        tenant, role = verify_receipt(config.admission, config.receipt_key, receipts[0], method, target, body, now=now)
    except AdmissionDenied as denied:
        raise SourceFailure('SOURCE_ADMISSION_DENIED', log='ADMISSION_' + str(denied)) from None
    request = parse_request(body)
    trace.correlation = request.correlation
    binding = config.registry().get(request.binding_ref)
    if binding is None or not binding.active or tenant not in binding.tenants \
            or role not in RESOURCE_ROLES[request.resource] \
            or (request.collection is not None and not binding.allows(request.collection)):
        raise not_allowed()
    limiter = limiter or BindingLimiter(config.state_directory)
    with limiter.admit(binding):
        token = config.credential(binding)
        upstream = exchange(binding, target_of(request), token, trust_file=config.trust(binding),
                            resolver=resolver, connection_factory=connection_factory)
    outcome = interpret(request, binding, upstream)
    if isinstance(outcome, SourceFailure):
        raise outcome
    return outcome


def log_line(trace, started, stream=None):
    stream = stream or sys.stderr
    correlation = trace.correlation if trace.correlation and CORRELATION.fullmatch(trace.correlation) else '-'
    stream.write('SOURCE_API_FETCH code=%s durationMs=%d bytes=%d correlationId=%s\n' % (
        trace.code, int((time.monotonic() - started) * 1000), trace.bytes, correlation))
    stream.flush()


def handler_for(config, options, log_stream=None):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'OUF'; sys_version = ''; protocol_version = 'HTTP/1.0'

        def log_message(self, *args):
            pass  # Request line, query, receipts and credentials are never logged by the HTTP server.

        def handle_request(self):
            self.close_connection = True
            started, trace = time.monotonic(), Trace()
            extra = {}
            try:
                if len(self.path) > 2048 or self.headers.get_all('Transfer-Encoding', []) \
                        or self.headers.get_all('Content-Encoding', []) or self.headers.get_all('Expect', []):
                    raise invalid('FRAMING')
                lengths = self.headers.get_all('Content-Length', []) or []
                if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,6}', lengths[0]):
                    raise invalid('FRAMING')
                size = int(lengths[0])
                if size > MAX_REQUEST_BYTES:
                    raise invalid('TOO_LARGE')
                body = self.rfile.read(size)
                if len(body) != size:
                    raise invalid('INCOMPLETE')
                result = dispatch(config, self.command, self.path, self.headers, body, trace=trace, **options)
                status, payload, extra = result.status, result.body, result.headers
                trace.code = 'OK'
            except SourceFailure as failure:
                status, payload, extra = failure.status, failure.body(), failure.headers()
                extra['Content-Type'] = 'application/json'
                trace.code = failure.log
            except Exception:
                failure = SourceFailure('SOURCE_UNAVAILABLE')
                status, payload, extra = failure.status, failure.body(), {'Content-Type': 'application/json'}
                trace.code = 'ADAPTER_FAILURE'
            trace.bytes = len(payload)
            self.send_response(status)
            for name, value in extra.items():
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(payload)
            log_line(trace, started, log_stream)

        do_POST = handle_request
        do_GET = handle_request
        do_PUT = handle_request
        do_DELETE = handle_request

        def send_error(self, code, message=None, explain=None):
            self.close_connection = True
            raw = SourceFailure('SOURCE_REQUEST_INVALID').body()
            self.send_response(400); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)

    return Handler


class BoundedTLSServer(ForkingMixIn, HTTPServer):
    """One forked worker per request: SIGALRM deadlines stay in a main thread, limits shared by flock."""
    block_on_close = True
    request_queue_size = 16

    def __init__(self, address, config, context, max_children, *, log_stream=None, **dispatch_options):
        if not _int(max_children, 1, 64):
            raise ConfigurationDenied('WORKER_LIMIT_INVALID')
        config.validate()
        self.config, self.context, self.max_children = config, context, max_children
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler_for(config, dispatch_options, log_stream))

    def finish_request(self, request, client_address):
        request.settimeout(self.config.request_timeout_seconds)
        with request_deadline(self.config.request_timeout_seconds):
            with self.context.wrap_socket(request, server_side=True) as protected:
                self.RequestHandlerClass(protected, client_address, self)

    def handle_error(self, request, client_address):
        pass  # No traceback may disclose query, registry, credential or TLS data.


CONFIG_KEYS = {'listenAddress', 'listenPort', 'maxWorkers', 'requestTimeoutSeconds', 'fetchPath', 'admission',
               'receiptKeyFile', 'registryFile', 'secretsDirectory', 'trustDirectory', 'stateDirectory',
               'tlsCertificateFile', 'tlsPrivateKeyFile'}


def load_configuration(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise ConfigurationDenied('CONFIGURATION_TOO_LARGE')
    cfg = strict_json(raw)
    if not isinstance(cfg, dict) or set(cfg) != CONFIG_KEYS:
        raise ConfigurationDenied('CONFIGURATION_INVALID')
    if not isinstance(cfg['listenAddress'], str) or not cfg['listenAddress'] or not _int(cfg['listenPort'], 1, 65535):
        raise ConfigurationDenied('LISTENER_BINDING_INVALID')
    admission = cfg['admission']
    if not isinstance(admission, dict) or set(admission) != {'installation', 'issuer', 'audience', 'scope', 'workloads'}:
        raise ConfigurationDenied('ADMISSION_INVALID')
    key = private_file(cfg['receiptKeyFile'], 256).decode('ascii').strip()
    config = AdapterConfiguration(cfg['fetchPath'], Admission(**admission), key, cfg['registryFile'],
                                  cfg['secretsDirectory'], cfg['trustDirectory'], cfg['stateDirectory'],
                                  cfg['requestTimeoutSeconds'])
    config.validate()
    state = os.lstat(config.state_directory)
    if not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) & 0o077:
        raise ConfigurationDenied('STATE_DIRECTORY_PRIVATE_REQUIRED')
    # Fail closed at start: an invalid registry never serves.
    load_registry(private_file(config.registry_file, MAX_REGISTRY_BYTES))
    private_file(cfg['tlsPrivateKeyFile'], 32768)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg['tlsCertificateFile'], cfg['tlsPrivateKeyFile'])
    return cfg, config, context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() == 0:
            raise ConfigurationDenied('NON_ROOT_REQUIRED')
        cfg, config, context = load_configuration(args.configuration)
        with BoundedTLSServer((cfg['listenAddress'], cfg['listenPort']), config, context, cfg['maxWorkers']) as server:
            server.serve_forever()
    except Exception:
        print('SOURCE_API_ADAPTER=BLOCKED NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
