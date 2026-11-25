"""Onboarding's authenticated THS channel to the MCP renewal owner."""
from datetime import datetime

from tools.analysis_clients import InvalidEndpointResponse
from tools.analysis_protocol import (
    BUDGET_DIMENSIONS, ERRORS, RENEWALS, RENEWAL_REQUEST_MAX, Rejected, delegation, digest, exact,
    is_digest, is_uuid, matches, opaque, parse, proposal_version, require, seq, validate_items, validate_review, wire,
)


VERSION_FIELDS = 'proposalVersion reason remainingOrdinals initialMaximum consumed increment totalMaximum expiresAt'
READ_FIELDS = frozenset((VERSION_FIELDS + ' analysisId incidentId expectedSeq mandateId generation proposalHash'
                        ' previous requestedChanges proposalState planLabel').split())
PROPOSAL_STATES = ('OPEN', 'APPROVED', 'CLOSED_PARTIAL', 'CHANGES_REQUESTED', 'SUPERSEDED', 'EXPIRED')
INVALID_READ = 'RENEWAL_RESPONSE_INVALID'
ORDINAL_MAX = 1023


def validate_version(version):
    require(proposal_version(version['proposalVersion']) and version['reason'] == 'ANALYSIS_BUDGET_EXHAUSTED')
    # Ordinals are JSON integers 0..1023, strictly increasing: sorted, unique, at most 1024 entries.
    ordinals = version['remainingOrdinals']
    require(type(ordinals) is list and len(ordinals) <= ORDINAL_MAX + 1
            and all(type(n) is int and 0 <= n <= ORDINAL_MAX for n in ordinals)
            and all(a < b for a, b in zip(ordinals, ordinals[1:])))
    for field in ('initialMaximum', 'consumed', 'increment', 'totalMaximum'):
        budget = version[field]
        require(type(budget) is dict and budget.keys() == set(BUDGET_DIMENSIONS)
                and all(type(n) is int and n >= 0 for n in budget.values()))
    require(all(version['totalMaximum'][dim] == version['initialMaximum'][dim] + version['increment'][dim]
                for dim in BUDGET_DIMENSIONS))
    expires = version['expiresAt']
    require(matches(expires, r'[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|\+00:00)'))
    try:
        datetime.fromisoformat(expires.upper().replace('Z', '+00:00'))
    except ValueError as exc:
        raise Rejected(400) from exc


def validate_read(status, raw, review_ref):
    try:
        data = parse(raw)
        if status != 200:
            require(status in ERRORS and exact(data, 'code'))
            codes = ('STALE_EXECUTION', 'COMMAND_CONFLICT', 'RENEWAL_USED') if status == 409 else (ERRORS[status],)
            require(data['code'] in tuple('ANALYSIS_' + code for code in codes))
            return

        require(type(data) is dict and READ_FIELDS <= data.keys() <= READ_FIELDS | {'contract', 'reviewRef'})
        require(data.get('contract', 'ouf.analysis.renewal.v1') == 'ouf.analysis.renewal.v1'
                and data.get('reviewRef', review_ref) == review_ref
                and is_digest(data['analysisId']) and opaque(data['incidentId']) and is_uuid(data['mandateId'])
                and seq(data['expectedSeq']) and seq(data['generation']) and is_digest(data['proposalHash']))
        validate_version(data)
        previous = data['previous']
        if previous is not None:
            require(exact(previous, VERSION_FIELDS))
            validate_version(previous)
            require(previous['proposalVersion'] < data['proposalVersion'])
        validate_items(data['requestedChanges'])
        require(data['proposalState'] in PROPOSAL_STATES and isinstance(data['planLabel'], str)
                and len(data['planLabel']) <= 200)
    except Rejected as exc:
        raise Rejected(502, INVALID_READ) from exc


class Renewals:
    def __init__(self, api, endpoint, ths_client):
        if endpoint.path not in ('', '/') or not isinstance(ths_client, str) or not ths_client.strip():
            raise ValueError('MCP HTTPS origin and THS OIDC client required')
        if ths_client == api.iam.workload:
            raise ValueError('THS and MCP clients must be distinct')
        self.api, self.endpoint, self.ths_client = api, endpoint, ths_client

    def forward(self, action, raw, bearer):
        require(action in ('read', 'decide'))
        scope = 'ouf.analysis.renewal.' + action
        iam = self.api.iam
        claims = iam.authenticate_ths(bearer, self.api.now(), self.ths_client, scope)
        command = parse(raw)
        validate_review(action, command)
        body = wire(command)
        now = self.api.now()
        expires = min(now + self.api.proof_ttl, claims['exp'])
        require(now < expires, 403)
        proof = delegation(dict(v=1, purpose='analysis-renewal-' + action, aud=iam.audience, iss=iam.issuer,
                                workload=iam.workload, principal=claims['sub'], tenant=claims['tenant_id'],
                                actor='HUMAN', client=claims['client_id'], acr=claims['acr'], scope=scope,
                                iat=now, exp=expires, requestHash=digest(body)), self.api.key)
        # The owner authenticates the Gateway mTLS client. No browser credentials cross this hop.
        owner_headers = {'Content-Type': 'application/json', 'X-OUF-Delegation': proof}
        limit = min(self.api.max_result, RENEWAL_REQUEST_MAX)
        try:
            status, result, retry = self.endpoint.post(body, owner_headers, limit, RENEWALS + action)
        except InvalidEndpointResponse as exc:
            if action == 'read':
                raise Rejected(502, INVALID_READ) from exc
            raise
        if action == 'read':
            validate_read(status, result, command['reviewRef'])
        headers = {'Retry-After': retry} if retry and status in (429, 503) else {}
        return status, result, headers
