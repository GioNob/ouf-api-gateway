"""Authenticated Gateway calls. No redirects, automatic retries or inbound header pass-through."""
import http.client
import ssl
import uuid
from urllib.parse import urlencode, urlsplit

from tools.analysis_protocol import Rejected, b64, digest, exact, opaque, parse, require, seq, wire


class InvalidEndpointResponse(Rejected):
    def __init__(self):
        super().__init__(503)


class Endpoint:
    def __init__(self, url, context, timeout):
        u = urlsplit(url)
        if (u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment or u.query
                or not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED
                or type(timeout) is not int or not 1 <= timeout <= 30):
            raise ValueError('verified HTTPS endpoint and finite timeout required')
        self.host, self.port, self.path = u.hostname, u.port, u.path
        self.context, self.timeout = context, timeout

    def post(self, body, headers, limit=65536, suffix=''):
        return self.request('POST', body, headers, limit, suffix)

    def request(self, method, body, headers, limit=65536, suffix=''):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=self.timeout)
        try:
            conn.request(method, self.path.rstrip('/') + suffix or '/', body=body, headers=headers)
            response = conn.getresponse()
            data = response.read(limit + 1)
            if len(data) > limit or 300 <= response.status < 400:
                raise InvalidEndpointResponse()
            retry = response.getheader('Retry-After')
            return response.status, data, retry
        except (OSError, http.client.HTTPException) as exc:
            raise Rejected(503) from exc
        finally:
            conn.close()

    def evidence(self, body, headers):
        status, raw, retry = self.post(body, headers)
        if status in (429, 503):
            raise Rejected(status, retry_after=retry)
        require(status == 200, status if status in (403, 404, 409) else 503)
        try:
            value = parse(raw)
        except Rejected as exc:
            raise Rejected(503) from exc
        require(type(value) is dict, 503)
        return value


JSON_HEADERS = {'Content-Type': 'application/json'}


class KeycloakIdentity(dict):
    """Request-local credential, used only on the configured introspection connection."""
    def __init__(self, claims, bearer):
        super().__init__(claims)
        self.bearer = bearer


class RemoteIAM:
    """RFC 7662 for workload identity plus the installation's current-resource-decision adapter."""
    def __init__(self, introspection, decisions, issuer, audience, workload, *, keycloak=False):
        self.introspection, self.decisions = introspection, decisions
        self.issuer, self.audience, self.workload = issuer, audience, workload
        if type(keycloak) is not bool:
            raise ValueError('invalid Keycloak decision mode')
        self.keycloak = keycloak

    def _claims(self, bearer, now, actor):
        require(isinstance(bearer, str) and bearer.startswith('Bearer ') and 7 < len(bearer) <= 16384, 403)
        c = self.introspection.evidence(urlencode({'token': bearer[7:]}).encode('ascii'),
                                        {'Content-Type': 'application/x-www-form-urlencoded'})
        aud = c.get('aud')
        require(c.get('active') is True and c.get('iss') == self.issuer
                and (aud == self.audience or type(aud) is list and self.audience in aud)
                and c.get('ouf_actor_type') == actor
                and isinstance(c.get('client_id'), str) and bool(c['client_id'])
                and isinstance(c.get('sub'), str) and bool(c['sub'])
                and isinstance(c.get('tenant_id'), str) and bool(c['tenant_id'])
                and type(c.get('exp')) is int and c['exp'] > now, 403)
        return c

    def authenticate(self, bearer, now, *, foreign_workload_status=403):
        claims = self._claims(bearer, now, 'SERVICE')
        require(claims['client_id'] == self.workload, foreign_workload_status)
        return KeycloakIdentity(claims, bearer) if self.keycloak else claims

    def authenticate_ths(self, bearer, now, client, scope):
        claims = self._claims(bearer, now, 'HUMAN')
        require(claims['client_id'] == client and claims.get('azp', client) == client
                and isinstance(claims.get('acr'), str) and claims['acr']
                and isinstance(claims.get('scope'), str) and scope in claims['scope'].split(), 403)
        return claims

    def decide(self, query, now, *, identity=None):
        require(self.decisions is not None, 503)
        body = wire(query)
        if self.keycloak:
            require(isinstance(identity, KeycloakIdentity), 503)
            form = urlencode({'token': identity.bearer[7:], 'ouf_authority_request': b64(body)})
            evidence = self.introspection.evidence(form.encode('ascii'), {'Content-Type': 'application/x-www-form-urlencoded'})
            require(type(evidence.get('active')) is bool, 503)
            require(evidence['active'], 403)
            require(evidence.get('ouf_prepared_request') == digest(body), 503)
        d = self.decisions.evidence(body, JSON_HEADERS)
        require(d.get('requestHash') == digest(body) and type(d.get('allowed')) is bool, 503)
        require(d['allowed'], 403)
        require(exact(d, 'requestHash allowed policyRef grantRef decisionRef validUntil grantExpiresAt '
                         'allowedOperations roles acr client')
                and all(opaque(d[k]) for k in ('policyRef', 'grantRef', 'decisionRef', 'acr', 'client'))
                and type(d['roles']) is list and all(opaque(r) for r in d['roles']) and len(d['roles']) <= 32
                and type(d['allowedOperations']) is list and all(isinstance(op, str) for op in d['allowedOperations'])
                and all(type(d[k]) is int and d[k] > now for k in ('validUntil', 'grantExpiresAt')), 503)
        return d


class Reservations:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def check(self, b, workload, now):
        query = {k: v for k, v in b.items() if k != 'arguments'}
        query.update(contract='ouf.analysis.reservation-check.v1', workload=workload, nonce=str(uuid.uuid4()),
                     argumentsHash=digest(wire(b['arguments'])))
        if 'requestId' in b['arguments']:
            query['requestId'] = b['arguments']['requestId']
        body = wire(query)
        e = self.endpoint.evidence(body, JSON_HEADERS)
        require(exact(e, 'requestHash current issuer tenant subject reservationRef ordinalsRef changeSeq '
                         'manifestChecksum profileHash validUntil requestId'), 503)
        require(e['requestHash'] == digest(body) and type(e['current']) is bool, 503)
        require(e['current'], 409)
        require(all(isinstance(e[k], str) and e[k] for k in ('issuer', 'tenant', 'subject'))
                and opaque(e['reservationRef']) and opaque(e['ordinalsRef']) and seq(e['changeSeq'])
                and type(e['validUntil']) is int, 503)
        require(e['requestId'] == query.get('requestId'), 404)
        require(now < e['validUntil'], 409)
        return e
