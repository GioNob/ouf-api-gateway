"""Purpose-separated Gateway receipts for the bounded provider transport.

Only APISIX after OIDC admission may mint these receipts. Incoming identity
headers and bearer tokens are never an authority at the transport adapter.
"""
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import time

PURPOSE = 'ouf-semantic-provider-owner-v1'
HEADER = 'X-OUF-Semantic-Provider-Receipt'
FIELDS = {'purpose', 'installation', 'issuer', 'audience', 'workload', 'tenant',
          'subject', 'actor', 'scope', 'requestHash', 'iat', 'exp'}


class AdmissionDenied(ValueError):
    pass


def receipt_key(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-fA-F]{64}', value):
        raise AdmissionDenied('RECEIPT_KEY_INVALID')
    # Match the existing Gateway convention: hexadecimal text is the HMAC key.
    return value.encode('ascii')


def request_hash(method, target, body):
    return hashlib.sha256(method.encode('ascii') + b'\n' + target.encode('ascii') + b'\n' + body).hexdigest()


@dataclass(frozen=True)
class AdmissionBinding:
    installation: str
    issuer: str
    audience: str
    workload: str
    scope: str
    tenants: tuple[str, ...]

    def validate(self):
        if not isinstance(self.tenants, (tuple, list)) or not self.tenants:
            raise AdmissionDenied('ADMISSION_BINDING_INVALID')
        values = [self.installation, self.issuer, self.audience, self.workload, self.scope, *self.tenants]
        if any(not isinstance(v, str) or not v or len(v) > 512
                                   or not v.isascii()
                or re.search(r'[\x00-\x20\x7f]', v) for v in values):
            raise AdmissionDenied('ADMISSION_BINDING_INVALID')
        if not self.issuer.startswith('https://'):
            raise AdmissionDenied('ADMISSION_BINDING_INVALID')


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionDenied('RECEIPT_INVALID')
        result[key] = value
    return result


def verify(binding, key, receipt, method, target, body, *, now=None):
    binding.validate()
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
    if not isinstance(claims, dict) or set(claims) != FIELDS:
        raise AdmissionDenied('RECEIPT_INVALID')
    required = {'purpose': PURPOSE, 'installation': binding.installation, 'issuer': binding.issuer,
                'audience': binding.audience, 'workload': binding.workload, 'actor': 'SERVICE',
                'scope': binding.scope, 'requestHash': request_hash(method, target, body)}
    if any(claims[k] != value for k, value in required.items()):
        raise AdmissionDenied('RECEIPT_CONTEXT_REJECTED')
    if claims['tenant'] not in binding.tenants or not isinstance(claims['subject'], str) \
            or not claims['subject'] or len(claims['subject']) > 512 \
            or re.search(r'[\x00-\x20\x7f]', claims['subject']):
        raise AdmissionDenied('RECEIPT_CONTEXT_REJECTED')
    instant = time.time() if now is None else now
    if type(claims['iat']) is not int or type(claims['exp']) is not int \
            or not claims['iat'] <= instant < claims['exp'] \
            or not 0 < claims['exp'] - claims['iat'] <= 30:
        raise AdmissionDenied('RECEIPT_EXPIRED')
    # READ-only transport: bounded receipts can be replayed until their expiry.
    # Rate limits belong to Gateway; these are not mutation/idempotency receipts.
    return claims
