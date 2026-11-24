"""Onboarding's authenticated THS channel to the MCP renewal owner."""
from tools.analysis_protocol import RENEWALS, delegation, digest, parse, require, validate_review, wire


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
        status, result, retry = self.endpoint.post(body, owner_headers, self.api.max_result, RENEWALS + action)
        headers = {'Retry-After': retry} if retry and status in (429, 503) else {}
        return status, result, headers
