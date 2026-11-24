"""Wire contract and pinned execute bindings for ouf.analysis.mandate.v1."""
import base64
import hashlib
import hmac
import json
import re
import uuid

from tools.mcp_dispatch_contract import EXECUTE_PATH, SEARCH_BATCH, capability_contracts, dispatch_input_schema

BASE = '/internal/analysis/v1/mandates/'
CONTRACT = 'ouf.analysis.mandate.v1'
ACTIONS = ('issue', 'dispatch', 'revoke', 'status', 'renewal-check')
RENEWALS = '/internal/analysis/v1/renewals/'
RENEWAL_COMMAND = 'reviewRef proposalVersion proposalHash expectedSeq commandKey decision items'
RENEWAL_REQUEST_MAX = 131072
REVIEW_PREFIX = '/trusted-human/analysis-renewal/'
REVIEW_REF = '[A-Za-z0-9_-]{22,128}'
ASSET_SEGMENT = '[A-Za-z0-9_~-][A-Za-z0-9._~-]*'
REVIEW_GET = '^' + REVIEW_PREFIX + '(?:' + REVIEW_REF + '|(?:' + ASSET_SEGMENT + '/)*' + ASSET_SEGMENT + r'\.(?:js|css))$'
BUDGET_DIMENSIONS = ('Calls', 'Attempts', 'Objects', 'Bytes', 'Millis')
RENEWAL_SELECTORS = {
    'mcp-analysis-mandate-renewal-check': ('POST', BASE + 'renewal-check', None),
    'onboarding-analysis-renewal-read': ('POST', RENEWALS + 'read', None),
    'onboarding-analysis-renewal-decide': ('POST', RENEWALS + 'decide', None),
    'trusted-human-analysis-renewal-read': ('GET', REVIEW_PREFIX + '*', REVIEW_GET),
    'trusted-human-analysis-renewal-decide': ('POST', REVIEW_PREFIX + '*', '^' + REVIEW_PREFIX + REVIEW_REF + '/decision$'),
}
STATUS_MAX_BYTES = 1024
BINDINGS = {
    'source.file.preview': ('ouf.managed-source.preview', '/managed.file/preview'),
    SEARCH_BATCH: (SEARCH_BATCH, '/semantic/consultation/search-batch'),
    'semantic.discovery.request': ('ouf.semantic.discovery', '/semantic/discovery/request'),
    'semantic.discovery.status': ('ouf.semantic.discovery.status', '/semantic/discovery/status'),
    'semantic.discovery.candidates': ('ouf.semantic.discovery.candidates', '/semantic/discovery/candidates'),
}
ERRORS = {400: 'INPUT_INVALID', 403: 'AUTHORITY_DENIED', 404: 'MANDATE_UNKNOWN',
          409: 'STALE_EXECUTION', 410: 'MANDATE_EXPIRED', 429: 'BACKOFF', 503: 'AUTHORITY_UNAVAILABLE'}


class Rejected(Exception):
    def __init__(self, status, code=None, retry_after=None):
        self.status, self.code = status, 'ANALYSIS_' + (code or ERRORS[status])
        self.retry_after = retry_after
        super().__init__(self.code)


def require(condition, status=400, code=None):
    if not condition:
        raise Rejected(status, code)


def wire(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs))
        return result

    def invalid(_):
        raise ValueError('unsupported number')

    try:
        result = json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                            parse_constant=invalid, parse_float=invalid)
        wire(result)  # Also reject unpaired UTF-16 surrogates.
        return result
    except (ValueError, RecursionError) as exc:
        raise Rejected(400) from exc


def exact(obj, fields):
    return type(obj) is dict and set(obj) == set(fields.split())


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def is_digest(value):
    return matches(value, '[0-9a-f]{64}')


def opaque(value):
    return matches(value, '[A-Za-z0-9._:/-]{1,256}')


def is_uuid(value, v4=False):
    if not matches(value, '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'):
        return False
    return not v4 or uuid.UUID(value).version == 4


def seq(value):
    return matches(value, '0|[1-9][0-9]{0,18}') and int(value) <= 2**63 - 1


def proposal_version(value):
    return type(value) is int and 1 <= value <= 2**53 - 1


def validate_items(items):
    require(type(items) is list and len(items) <= 16)
    for item in items:
        require(exact(item, 'field comment') and item['field'] in (*BUDGET_DIMENSIONS, 'general')
                and isinstance(item['comment'], str) and item['comment'].strip() and len(item['comment']) <= 500)


def validate_review(action, b):
    require(exact(b, 'reviewRef' if action == 'read' else RENEWAL_COMMAND))
    require(matches(b['reviewRef'], REVIEW_REF))
    if action != 'read':
        require(proposal_version(b['proposalVersion'])
                and is_digest(b['proposalHash']) and seq(b['expectedSeq']) and is_uuid(b['commandKey'], v4=True)
                and b['decision'] in ('APPROVE', 'CHANGES_REQUESTED', 'CLOSE_PARTIAL'))
        validate_items(b['items'])


def validate(action, b):
    fields = {'issue': 'contract analysisId profile manifestChecksum commandKey',
              'dispatch': 'mandateId generation analysisId intentKey attemptId fence operation arguments',
              'revoke': 'mandateId expectedGeneration commandKey',
              'status': 'mandateId generation',
              'renewal-check': 'mandateId generation analysisId incidentId ' + RENEWAL_COMMAND}
    require(action in fields and exact(b, fields[action]))
    if action in ('issue', 'revoke'):
        require(is_uuid(b['commandKey'], v4=True))
    if action in ('issue', 'dispatch', 'renewal-check'):
        require(is_digest(b['analysisId']))
    if action != 'issue':
        require(is_uuid(b['mandateId']))
    if action == 'issue':
        p = b['profile']
        require(b['contract'] == CONTRACT and is_digest(b['manifestChecksum'])
                and exact(p, 'assetId profileId profileVersion schemaHash columnCount')
                and is_uuid(p['assetId']) and is_uuid(p['profileId'])
                and type(p['profileVersion']) is int and p['profileVersion'] >= 1
                and matches(p['schemaHash'], 'sha256:[0-9a-f]{64}')
                and type(p['columnCount']) is int and 1 <= p['columnCount'] <= 1024)
    elif action == 'dispatch':
        require(seq(b['generation']) and is_digest(b['intentKey']) and is_uuid(b['attemptId'])
                and seq(b['fence']) and isinstance(b['operation'], str) and type(b['arguments']) is dict)
    elif action == 'renewal-check':
        require(seq(b['generation']) and opaque(b['incidentId']))
        validate_review('decide', {k: b[k] for k in RENEWAL_COMMAND.split()})
    elif action == 'status':
        require(seq(b['generation']))
    else:
        require(seq(b['expectedGeneration']))


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def delegation(payload, key):
    encoded = b64(wire(payload))
    signature = hmac.digest(key, ('ouf-mcp-delegation-v1.' + encoded).encode('ascii'), 'sha256')
    return encoded + '.' + b64(signature)


def human_proof(value, key, issuer, audience, workload, tenant, now, *, purpose='mcp-execute'):
    require(isinstance(value, str) and len(value) <= 16384 and
            matches(value, r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}'), 403)
    encoded, signature = value.split('.')
    mac = hmac.digest(key, ('ouf-mcp-delegation-v1.' + encoded).encode('ascii'), 'sha256')
    require(hmac.compare_digest(signature, b64(mac)), 403)
    try:
        p = parse(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    except (ValueError, Rejected) as exc:
        raise Rejected(403) from exc
    require(type(p) is dict and p.get('purpose') == purpose and p.get('actor') == 'HUMAN'
            and p.get('v') == 1 and p.get('iss') == issuer and p.get('aud') == audience
            and p.get('workload') == workload and p.get('tenant') == tenant
            and type(p.get('iat')) is int and type(p.get('exp')) is int
            and p['iat'] <= now < p['exp'] <= p['iat'] + 60
            and all(isinstance(p.get(k), str) and 0 < len(p[k]) <= 4096
                    for k in ('principal', 'client', 'acr', 'scope')), 403)
    return p


class Catalog:
    """Only ACTIVE entries from the exact installation MCP manifest may run."""
    def __init__(self, raw):
        from jsonschema import Draft202012Validator, FormatChecker

        self.checksum = digest(raw)
        self.entries = {}
        rows = parse(raw)['capabilities']
        for op, (cap, suffix) in BINDINGS.items():
            candidates = [r for r in rows if r['capabilityId'] == cap]
            if not candidates:
                continue
            row, = candidates
            expected = capability_contracts()[cap]
            limit = row.get('baseCostEnvelope', {}).get('hardMaxResultBytes')
            if (row.get('publicationState') != 'ACTIVE' or row.get('toolName', cap) != op
                    or row.get('toolEligible') != (op != SEARCH_BATCH)
                    or type(limit) is not int or not 1 <= limit <= expected['baseCostEnvelope']['hardMaxResultBytes']
                    or any(row.get(k) != expected[k] for k in ('gatewayBindingRef', 'owner', 'operationClass',
                                                               'requiredAuthorizationCapability', 'inputSchema'))):
                continue
            schema = dispatch_input_schema(cap, row['inputSchema'])
            self.entries[op] = (row, EXECUTE_PATH + suffix, Draft202012Validator(schema, format_checker=FormatChecker()))

    def resolve(self, b, profile):
        op, args = b['operation'], b['arguments']
        require(op in self.entries, 403)
        row, path, validator = self.entries[op]
        require(validator.is_valid(args))
        if op == 'source.file.preview':
            require(args.get('view') == 'COLUMNS' and all(args.get(k) == profile[k]
                                                         for k in ('assetId', 'profileId')), 403)
        if op == 'semantic.discovery.request':
            require(args['requestedArtifactType'] in ('PROPERTY', 'CLASS')
                    and matches(args['idempotencyKey'], 'analysis:[0-9a-f]{64}'))
        return row, path
