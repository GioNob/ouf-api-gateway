"""D-104 wire validation and the existing Semantic owner receipt format."""
import base64
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tools.mcp_dispatch_contract import SEARCH_BATCH_CONTRACT

TTL_MS = 24 * 60 * 60 * 1000
MAX_REQUEST = 65536
ROOT = Path(__file__).resolve().parents[1]
START_DOMAIN = 'ouf-analysis-batch-start-v1'


class Denied(Exception):
    def __init__(self, status, code, retry_after=None):
        super().__init__(code)
        self.status, self.code, self.retry_after = status, code, retry_after


def require(condition, status=400, code='ANALYSIS_MANDATE_INVALID'):
    if not condition:
        raise Denied(status, code)


def exact(value, fields):
    return isinstance(value, dict) and value.keys() == set(fields.split())


def token(value, pattern=r'[A-Za-z0-9._:-]{1,256}'):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def hash_ref(value):
    return token(value, r'[0-9a-f]{64}')


def identity_value(value):
    return token(value, r'[\x21-\x7e]{1,512}')


def uuid_ref(value, v4=False):
    if not token(value, r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'):
        return False
    return not v4 or uuid.UUID(value).version == 4


def wire(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True, ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def closed(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs))
        return result

    def invalid(_):
        raise Denied(400, 'ANALYSIS_MANDATE_INVALID')

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=closed, parse_constant=invalid)
    except (ValueError, RecursionError) as exc:
        raise Denied(400, 'ANALYSIS_MANDATE_INVALID') from exc


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def mac(key, purpose, encoded):
    # Existing Semantic receipt keys are ASCII hex strings, used as-is.
    return b64(hmac.digest(key, (purpose + '.' + encoded).encode('ascii'), 'sha256'))


def signing_key(value):
    if not token(value, r'[0-9a-fA-F]{64}'):
        raise ValueError('a mounted signing key is required')
    return value.encode('ascii')


def sign_binding(key, domain, value):
    payload = b64(wire(value))
    return payload + '.' + mac(key, domain, payload)


def verify_binding(proof, key, domain, code, limit=16384):
    require(isinstance(proof, str) and len(proof) <= limit + 44
            and token(proof, r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}'), 403, code)
    payload, signature = proof.split('.')
    require(len(payload) % 4 != 1 and hmac.compare_digest(mac(key, domain, payload), signature),
            403, code)
    return parse(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


def verify_start(proof, config, now_ms):
    code = 'ANALYSIS_START_PROOF_DENIED'
    p = verify_binding(proof, config.start_key, START_DOMAIN, code, limit=8192)
    require(exact(p, 'v installation issuer audience workload tenant subject client actor scope iat exp authTime plan')
            and type(p['v']) is int and p['v'] == 1 and p['installation'] == config.installation
            and p['issuer'] == config.issuer and p['audience'] == config.audience and p['workload'] == config.workload
            and p['actor'] == 'HUMAN' and all(identity_value(p[k]) for k in ('tenant', 'subject', 'client'))
            and type(p['iat']) is int and type(p['exp']) is int
            and type(p['authTime']) is int and 0 < p['authTime'] <= p['iat']
            and 0 < p['exp'] - p['iat'] <= 60 and p['iat'] <= now_ms // 1000 < p['exp'], 403, code)
    p['scope'] = scopes(p['scope'], 403, code)
    plan = p['plan']
    require(exact(plan, 'mode assetId profileId schemaHash commandKey') and plan['mode'] == 'BATCH_V1'
            and uuid_ref(plan['assetId']) and uuid_ref(plan['profileId'])
            and hash_ref(plan['schemaHash']) and uuid_ref(plan['commandKey'], v4=True), 403, code)
    return p


def scopes(value, status, code):
    require(token(value, r'[\x20-\x7e]{1,4096}'), status, code)
    values = set(value.split())
    require(values and all(identity_value(scope) for scope in values), status, code)
    return sorted(values)


@dataclass(frozen=True)
class Operation:
    capability: str
    scope: str
    operation_class: str
    family: str
    action: str

    @property
    def path(self):
        channel = 'consultation' if self.family == 'read' else self.family
        return f'/api/internal/v1/semantic/{channel}/{self.action}'

    def receipt(self, key, audience, claims, body, now_ms, expires_ms):
        issued_at = now_ms // 1000
        exp = min(expires_ms // 1000, issued_at + 30)
        require(exp > issued_at, 403, 'ANALYSIS_EVIDENCE_EXPIRED')
        purpose = f'semantic-{self.family}-owner'
        payload = b64(wire(dict(v=1, purpose=purpose, method='POST', path=self.path,
                                bodyHash=digest(body), capability=self.capability, iat=issued_at, exp=exp,
                                issuer=claims['issuer'], audience=audience, workload=claims['workload'],
                                subject=claims['subject'], tenant=claims['tenant'], acr=claims['acr'],
                                scope=' '.join(claims['scope']), roles=' '.join(claims['roles']))))
        return (f'X-OUF-Semantic-{self.family.title()}-Receipt',
                payload + '.' + mac(key, f'ouf-{purpose}-v1', payload))


OPERATIONS = {
    'semantic.search.batch': Operation('ouf.semantic.search.batch', 'ouf.semantic.search', 'READ', 'read', 'search-batch'),
    'semantic.discovery.request': Operation('ouf.semantic.discovery', 'ouf.semantic.discovery', 'COMMAND', 'discovery', 'request'),
    'semantic.discovery.status': Operation('ouf.semantic.discovery.status', 'ouf.semantic.discovery', 'READ', 'discovery', 'status'),
    'semantic.discovery.candidates': Operation('ouf.semantic.discovery.candidates', 'ouf.semantic.discovery', 'READ', 'discovery', 'candidates'),
}


@cache
def argument_validator(name):
    op = OPERATIONS[name]
    if op.family == 'read':
        schema = json.loads(SEARCH_BATCH_CONTRACT.read_bytes())['inputSchema']
    else:
        path = ROOT / 'schemas' / f'mcp-gateway-semantic-discovery-{op.action}-dispatch-v1.json'
        schema = json.loads(path.read_bytes())['properties']['Arguments']
    return Draft202012Validator(schema, format_checker=FormatChecker())


def arguments(name, args):
    code = 'ANALYSIS_ARGUMENTS_INVALID'
    require(argument_validator(name).is_valid(args), 400, code)
    if name == 'semantic.search.batch':
        intents = args['intents']
        require(len({row['intentId'] for row in intents}) == len(intents), 400, code)
        for row in intents:
            languages = row['preferredLanguages']
            require(len({lang.lower() for lang in languages}) == len(languages) and row['intent'].strip(), 400, code)
    elif name == 'semantic.discovery.request':
        require(args['intent'].strip(), 400, code)
    else:
        require(uuid_ref(args['requestId']), 400, code)
    # JSON strings with unpaired UTF-16 surrogates are not Unicode scalar input.
    require(not re.search(r'[\ud800-\udfff]', json.dumps(args, ensure_ascii=False)), 400, code)
    return digest(wire(args))
