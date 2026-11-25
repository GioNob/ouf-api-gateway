"""Private Keycloak RFC 7662 and current UMA assignment verifier for analysis mandates."""
from contextlib import closing
import base64
from email.utils import parsedate_to_datetime
import http
import os
from pathlib import Path
import sqlite3
import ssl
import time
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import uuid4

from tools.analysis_clients import Endpoint
from tools.authority_host import credential
from tools.analysis_protocol import (
    BINDINGS, CONTRACT, RENEWAL_REQUEST_MAX, REVIEW_REF, Rejected, b64, digest, exact, is_digest,
    is_uuid, matches, opaque, parse, proposal_version, require, seq, validate, wire,
)

CHECK = 'ouf.analysis.authority-check.v1'
ACTIONS = ('issue', 'status', 'dispatch', 'revoke', 'admin-revoke', 'renew-budget')
FORM = 'application/x-www-form-urlencoded'
PROTECTION = '/authz/protection'
RESOURCE = PROTECTION + '/resource_set'
TOKEN = '/protocol/openid-connect/token'
SERVICE_FIELDS = 'issuer tenant workload workloadSubject'.split()
PROFILE_ID = '[A-Za-z0-9][A-Za-z0-9_.:-]*'


class InvalidPermissionRequest(Exception):
    """Keycloak can reject a permission parameter after its resource has been deleted."""


def limit(profile):
    if (not exact(profile, 'value default maximum')
            or any(type(v) is not int or v < 1 for v in profile.values())
            or max(profile['value'], profile['default']) > profile['maximum']):
        raise ValueError('invalid IAM limit')
    return profile['value']


def retry_seconds(value, now):
    if value is None or matches(value, '[0-9]+'):
        return value
    try:
        deadline = parsedate_to_datetime(value)
        if deadline.tzinfo is not None:
            return str(max(0, int(deadline.timestamp()) - int(now)))
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    return None


class VerifierStore:
    """Private state shared by the installation's introspection and decision processes."""
    def __init__(self, path):
        self.path = Path(path).resolve().as_uri() + '?mode=rw'
        with closing(self.connect()) as db:
            db.execute('create table if not exists keycloak_rate_v1 '
                       '(kind text primary key, until_epoch integer not null, used integer not null)')
            db.execute('create table if not exists keycloak_permission_v1 '
                       '(binding text primary key, expiry integer not null, grant_id text, scopes blob not null)')
            db.execute('create index if not exists keycloak_expiry_v1 on keycloak_permission_v1(expiry)')

    def connect(self):
        return sqlite3.connect(self.path, uri=True, timeout=1, isolation_level=None)

    def charge(self, kind, maximum, now):
        with closing(self.connect()) as db:
            db.execute('begin immediate')
            row = db.execute('select until_epoch, used from keycloak_rate_v1 where kind=?', (kind,)).fetchone()
            end, used = row if row and row[0] > now else (now + 60, 0)
            if used >= maximum:
                raise Rejected(429, retry_after=str(end - now))
            db.execute('insert or replace into keycloak_rate_v1 values (?,?,?)', (kind, end, used + 1))
            db.commit()

    def prepare(self, binding, expiry, grant_id, scopes, now):
        require(now < expiry, 403)
        with closing(self.connect()) as db:
            db.execute('begin immediate')
            db.execute('delete from keycloak_permission_v1 where expiry<=?', (now,))
            db.execute('insert into keycloak_permission_v1 values (?,?,?,?)', (binding, expiry, grant_id, wire(scopes)))
            db.commit()

    def consume(self, binding, now):
        with closing(self.connect()) as db:
            db.execute('begin immediate')
            row = db.execute('select expiry, grant_id, scopes from keycloak_permission_v1 where binding=?', (binding,)).fetchone()
            db.execute('delete from keycloak_permission_v1 where binding=? or expiry<=?', (binding, now))
            db.commit()
        require(row is not None, 503)
        require(now < row[0], 403)
        return row[0], row[1], parse(row[2])


def validate_query(q):
    common = ('contract nonce action issuer workload workloadSubject tenant subject actor actorRef '
              'analysisId profile manifestChecksum')
    require(type(q) is dict and q.get('action') in ACTIONS)
    action = q['action']
    fields = common
    if action != 'issue':
        fields += ' mandateId grantRef policyRef'
    human = action in ('issue', 'revoke', 'renew-budget')
    if human:
        fields += ' delegatedClient delegatedScope acr'
    if action == 'dispatch':
        fields += ' operation intentKey argumentsHash resourceId'
    if action == 'renew-budget':
        fields += (' generation incidentId proposalVersion proposalHash expectedSeq reviewRef '
                   'commandKey decision commandHash')
    require(exact(q, fields) and q['contract'] == CHECK and is_uuid(q['nonce'], v4=True)
            and all(isinstance(q[k], str) and q[k] for k in (*SERVICE_FIELDS, 'subject'))
            and q['actor'] == ('HUMAN' if human else 'SERVICE')
            and q['actorRef'] == q['subject' if human else 'workloadSubject'])
    # These fields have the issue wire grammar on every action.
    validate('issue', dict(contract=CONTRACT, commandKey=q['nonce'], analysisId=q['analysisId'],
                           profile=q['profile'], manifestChecksum=q['manifestChecksum']))
    if action != 'issue':
        require(is_uuid(q['mandateId']) and safe_id(q['grantRef']) and opaque(q['policyRef']))
    if human:
        require(opaque(q['delegatedClient']) and opaque(q['acr'])
                and isinstance(q['delegatedScope'], str) and bool(q['delegatedScope'].split()))
    if action == 'dispatch':
        require(isinstance(q['operation'], str) and q['operation'] in BINDINGS
                and is_uuid(q['resourceId']) and is_digest(q['intentKey']) and is_digest(q['argumentsHash']))
    if action == 'renew-budget':
        require(seq(q['generation']) and opaque(q['incidentId']) and proposal_version(q['proposalVersion'])
                and is_digest(q['proposalHash']) and seq(q['expectedSeq']) and matches(q['reviewRef'], REVIEW_REF)
                and is_uuid(q['commandKey'], v4=True) and q['decision'] in ('APPROVE', 'CLOSE_PARTIAL', 'CHANGES_REQUESTED')
                and is_digest(q['commandHash']))


def safe_id(value):
    return matches(value, '[A-Za-z0-9_-][A-Za-z0-9._-]{0,255}')


def grant_name(q):
    # One independently provisioned assignment per credential principal in this namespace.
    return 'ouf-analysis-' + digest(wire([q[k] for k in SERVICE_FIELDS]))


def attribute(attrs, key):
    values = attrs.get(key)
    require(type(values) is list and len(values) == 1 and isinstance(values[0], str) and values[0], 503)
    return values[0]


class Verifier:
    def __init__(self, profile, resource_server, secret, endpoint, store, *, gateway_principal, clock=time.time):
        trust, clients, grant = profile['trust'], profile['clients'], profile['grant']
        if (profile['contract'] != 'ouf.iam-profile.v1' or profile['kind'] != 'keycloak-ouf'
                or grant['mechanism'] != 'authorization-resource' or grant['grantRef'] != 'iam-resource-id'
                or grant['lookup'] != 'current-resource-permission' or grant['decisionContract'] != CHECK
                or grant['introspectionProtocol'] != 'RFC7662'
                or grant['revocation'] != 'withdraw-permission-and-invalidate-assignment-credential'
                or not matches(grant['resourceType'], PROFILE_ID) or not secret or not matches(resource_server, PROFILE_ID)
                or resource_server != grant['resourceServer']['clientId']
                or not opaque(gateway_principal)):
            raise ValueError('invalid Keycloak assignment profile')
        self.issuer, self.audience = trust['issuer'], trust['gatewayAudience']
        self.worker, self.ths = clients['mcp']['clientId'], clients['ths']['clientId']
        if (not all(matches(v, PROFILE_ID) for v in (self.worker, self.ths, self.audience))
                or len({resource_server, self.worker, self.ths}) != 3
                or not matches(urlsplit(self.issuer).path, r'(?:/[^/]+)*/realms/[A-Za-z0-9_.-]+')
                or any(clients[k]['audience'] != self.audience for k in ('mcp', 'ths'))):
            raise ValueError('distinct clients, realm issuer and matching audiences required')
        self.paths = {}
        for kind in ('introspection', 'decisions'):
            url = urlsplit(trust[kind])
            if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                    or url.query or url.fragment or not url.path or url.path in self.paths):
                raise ValueError('distinct private endpoint paths required')
            self.paths[url.path] = kind
        self.resource_type, self.client = grant['resourceType'], resource_server
        self.ttl = limit(grant['revocationTtlSeconds'])
        self.limits = {k: limit(profile['iam'][k]) for k in ('introspectionsPerMinute', 'decisionsPerMinute')}
        self.secret, self.endpoint, self.store, self.clock = secret, endpoint, store, clock
        self.gateway_principal = gateway_principal
        self.profile_hash = digest(wire(profile))

    def api(self, method, path, *, form=None, bearer=None, missing=False, uma=False, kind='decisionsPerMinute'):
        self.store.charge(kind, self.limits[kind], int(self.clock()))
        headers, body = {}, None
        if bearer is not None:
            headers['Authorization'] = 'Bearer ' + bearer
        if form is not None:
            headers['Content-Type'] = FORM
            if bearer is None:
                form = {**form, 'client_id': self.client, 'client_secret': self.secret}
            body = urlencode(form).encode('ascii')
        status, raw, retry = self.endpoint.request(method, body, headers, suffix=path)
        if missing and status == 404:
            raise Rejected(403)
        if uma and status == 400:
            raise InvalidPermissionRequest()
        if uma and status == 403:
            try:
                error = parse(raw)
            except Rejected as exc:
                raise Rejected(503) from exc
            require(type(error) is dict and error.get('error') == 'access_denied', 503)
            raise Rejected(403)
        if status != 200:
            raise Rejected(503, retry_after=retry_seconds(retry, self.clock()))
        try:
            return parse(raw)
        except Rejected as exc:
            raise Rejected(503) from exc

    def binding(self, raw):
        return digest(wire([self.profile_hash, self.client, self.gateway_principal, digest(raw)]))

    def introspect(self, raw, principal):
        try:
            pairs = parse_qsl(raw.decode('ascii'), strict_parsing=True, keep_blank_values=True)
        except ValueError as exc:
            raise Rejected(400) from exc
        form = dict(pairs)
        require(len(pairs) == len(form) and form.keys() in ({'token'}, {'token', 'ouf_authority_request'})
                and matches(form['token'], r'[A-Za-z0-9._~+/-]+=*'))
        if 'ouf_authority_request' in form:
            require(principal == self.gateway_principal, 403)
        start = int(self.clock())
        c = self.api('POST', TOKEN + '/introspect', form={'token': form['token']}, kind='introspectionsPerMinute')
        require(type(c) is dict and type(c.get('active')) is bool, 503)
        if not c['active']:
            return {'active': False}
        require(all(isinstance(c.get(k), str) and c[k] for k in ('iss', 'sub', 'tenant_id', 'client_id', 'ouf_actor_type'))
                and (isinstance(c.get('aud'), str) or type(c.get('aud')) is list
                     and all(isinstance(a, str) for a in c['aud']))
                and type(c.get('exp')) is int, 503)
        fields = ('active', 'iss', 'aud', 'sub', 'client_id', 'tenant_id', 'ouf_actor_type', 'exp', 'acr', 'azp', 'scope')
        claims = {k: c[k] for k in fields if k in c}
        if 'ouf_authority_request' in form:
            encoded = form['ouf_authority_request']
            require(matches(encoded, '[A-Za-z0-9_-]+') and len(encoded) % 4 != 1)
            raw_query = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
            q = parse(raw_query)
            validate_query(q)
            require(c['iss'] == q['issuer'] == self.issuer and c['client_id'] == q['workload'] == self.worker
                    and c['sub'] == q['workloadSubject'] and c['tenant_id'] == q['tenant']
                    and self.audience in (c['aud'] if type(c['aud']) is list else [c['aud']])
                    and c['ouf_actor_type'] == 'SERVICE' and c['exp'] > start and 'authorization' not in c, 403)
            grant_id, scopes = None, []
            try:
                grant_id = self.lookup(q) if q['action'] == 'issue' else q['grantRef']
                scopes = self.permissions(grant_id, form['token'], raw_query, q)
            except Rejected as exc:
                if exc.status != 403:
                    raise
            self.store.prepare(self.binding(raw_query), min(c['exp'], start + self.ttl), grant_id, scopes, int(self.clock()))
            claims['ouf_prepared_request'] = digest(raw_query)
        return claims

    def pat(self):
        token = self.api('POST', TOKEN, form={'grant_type': 'client_credentials'})
        require(type(token) is dict and isinstance(token.get('token_type'), str)
                and token['token_type'].lower() == 'bearer'
                and matches(token.get('access_token'), r'[A-Za-z0-9._~+/-]+=*'), 503)
        return token['access_token']

    def lookup(self, q):
        params = urlencode(dict(name=grant_name(q), exactName='true', max=2))
        ids = self.api('GET', RESOURCE + '?' + params, bearer=self.pat())
        require(type(ids) is list and len(ids) <= 1 and all(safe_id(i) for i in ids), 503)
        require(ids, 403)
        return ids[0]

    def assignment(self, q, grant_id):
        r = self.api('GET', RESOURCE + '/' + grant_id, bearer=self.pat(), missing=True)
        require(type(r) is dict and r.get('_id') == grant_id and type(r.get('attributes')) is dict, 503)
        owner = r.get('owner')
        if type(owner) is dict:
            owner = owner.get('id')
        require(isinstance(owner, str) and owner and type(r.get('ownerManagedAccess')) is bool
                and all(isinstance(r.get(k), str) and r[k] for k in ('type', 'name')), 503)
        require(owner == q['subject'] and r['ownerManagedAccess'] and r.get('type') == self.resource_type, 403)
        attrs = r['attributes']
        principal = attribute(attrs, 'workloadSubject')
        require(r.get('name') == grant_name({**q, 'workloadSubject': principal}), 403)
        require(q['action'] == 'admin-revoke' or principal == q['workloadSubject'], 403)
        for key in ('issuer', 'tenant', 'workload', 'analysisId', 'manifestChecksum'):
            require(attribute(attrs, key) == q[key], 403)
        require(attribute(attrs, 'profileHash') == digest(wire(q['profile'])), 403)
        return attrs

    def permissions(self, grant_id, bearer, raw, query):
        # Issue enumerates permitted operations. Other requests ask for their precise scopes.
        permission = grant_id
        if query['action'] != 'issue':
            permission += '#' + query['action']
            if query['action'] == 'dispatch':
                permission += ',' + query['operation']
        context = {'ouf.requestHash': [digest(raw)], 'ouf.authorityRequest': [raw.decode('utf-8')]}
        form = dict(grant_type='urn:ietf:params:oauth:grant-type:uma-ticket', audience=self.client, submit_request='false',
                    permission=permission, response_mode='permissions', claim_token_format='urn:ietf:params:oauth:token-type:jwt',
                    claim_token=b64(wire(context)))
        try:
            permissions = self.api('POST', TOKEN, bearer=bearer, form=form, uma=True)
        except InvalidPermissionRequest:
            # Only an authoritative missing resource proves withdrawal.
            self.api('GET', RESOURCE + '/' + grant_id, bearer=self.pat(), missing=True)
            raise Rejected(503)
        require(type(permissions) is list and len(permissions) <= 1, 503)
        if not permissions:
            return []
        entry = permissions[0]
        require(type(entry) is dict and entry.get('rsid') == grant_id and type(entry.get('scopes')) is list, 503)
        scopes = entry['scopes']
        require(all(isinstance(scope, str) and scope in (*ACTIONS, *BINDINGS) for scope in scopes)
                and len(set(scopes)) == len(scopes), 503)
        return scopes

    def decide(self, raw):
        q = parse(raw)
        validate_query(q)
        require(q['issuer'] == self.issuer and q['workload'] == self.worker, 403)
        expiry, grant_id, scopes = self.store.consume(self.binding(raw), int(self.clock()))
        action = q['action']
        require(grant_id and (action == 'issue' or grant_id == q['grantRef']) and action in scopes
                and (action != 'dispatch' or q['operation'] in scopes), 403)
        attrs = self.assignment(q, grant_id)
        policy, client, acr = (attribute(attrs, k) for k in ('policyRef', 'client', 'acr'))
        deadline = attribute(attrs, 'grantExpiresAt')
        roles = attrs.get('roles', [])
        require(all(opaque(v) for v in (policy, client, acr)) and matches(deadline, '[1-9][0-9]{0,18}')
                and type(roles) is list and len(roles) <= 32 and all(opaque(v) for v in roles), 503)
        require(action == 'issue' or q['policyRef'] == policy, 403)
        if action in ('issue', 'revoke'):
            require(q['delegatedClient'] == client and q['acr'] == acr, 403)
        if action == 'renew-budget':
            require(q['delegatedClient'] == self.ths and 'ouf.analysis.renewal.decide' in q['delegatedScope'].split(), 403)
        if action == 'dispatch':
            require(q['resourceId'] == q['profile']['profileId'], 403)
        ops = sorted(set(scopes).intersection(BINDINGS))
        require(action != 'issue' or ops, 403)
        now = int(self.clock())
        valid = min(expiry, int(deadline), now + self.ttl)
        require(now < valid, 403)
        return dict(requestHash=digest(raw), allowed=True, policyRef=policy, grantRef=grant_id,
                    decisionRef=str(uuid4()), validUntil=valid, grantExpiresAt=int(deadline),
                    allowedOperations=ops, roles=roles, acr=acr, client=client)

    def __call__(self, env, start_response):
        try:
            require(env.get('SSL_CLIENT_VERIFY') == 'SUCCESS', 403)
            kind = self.paths.get(env.get('PATH_INFO'))
            require(kind and env.get('REQUEST_METHOD') == 'POST' and not env.get('QUERY_STRING')
                    and not env.get('HTTP_CONTENT_ENCODING')
                    and env.get('CONTENT_TYPE', '').partition(';')[0] == (FORM if kind == 'introspection' else 'application/json'))
            size = env.get('CONTENT_LENGTH', '')
            require(matches(size, '[1-9][0-9]{0,5}') and int(size) <= RENEWAL_REQUEST_MAX)
            raw = env['wsgi.input'].read(int(size))
            require(len(raw) == int(size))
            if kind == 'introspection':
                value = self.introspect(raw, env.get('REMOTE_USER'))
            else:
                require(env.get('REMOTE_USER') == self.gateway_principal, 403)
                try:
                    value = self.decide(raw)
                except Rejected as exc:
                    if exc.status != 403:
                        raise
                    value = dict(requestHash=digest(raw), allowed=False)
            status, headers = 200, []
        except Rejected as exc:
            status, value = exc.status, {'code': exc.code}
            headers = [('Retry-After', exc.retry_after)] if exc.retry_after else []
        except (sqlite3.Error, OSError):
            status, value, headers = 503, {'code': 'ANALYSIS_AUTHORITY_UNAVAILABLE'}, []
        body = wire(value)
        start_response(f'{status} {http.HTTPStatus(status).phrase}', [
            ('Content-Type', 'application/json'), ('Cache-Control', 'no-store'), ('Content-Length', str(len(body))), *headers])
        return [body]


def application(cfg=None):
    if cfg is None:
        cfg = parse(Path(os.environ['OUF_KEYCLOAK_DECISIONS_CONFIG']).read_bytes())
    required = {'profileFile', 'caFile', 'store', 'gatewayTlsPrincipal'}
    tls_keys = {'clientCertFile', 'clientKeyFile'}
    if (type(cfg) is not dict or not required <= cfg.keys()
            or cfg.keys() - required - tls_keys - {'timeoutSeconds', 'resourceServer', 'secretFile', 'secretEnv'}
            or cfg.keys() & tls_keys not in (set(), tls_keys)):
        raise ValueError('invalid private Keycloak verifier configuration')
    profile = parse(Path(cfg['profileFile']).read_bytes())
    server = profile['grant'].get('resourceServer')
    if (not isinstance(server, dict) or not matches(server.get('clientId'), PROFILE_ID)
            or not isinstance(server.get('secretRef'), str) or not server['secretRef'].strip()
            or cfg.get('resourceServer', server['clientId']) != server['clientId']):
        raise ValueError('invalid resource-server binding for approved profile')
    secret = credential(cfg, 'secretFile', 'secretEnv', reference=server['secretRef'])
    ctx = ssl.create_default_context(cafile=cfg['caFile'])
    if 'clientCertFile' in cfg:
        ctx.load_cert_chain(cfg['clientCertFile'], cfg['clientKeyFile'])
    endpoint = Endpoint(profile['trust']['issuer'], ctx, cfg.get('timeoutSeconds', 5))
    return Verifier(profile, server['clientId'], secret, endpoint, VerifierStore(cfg['store']),
                    gateway_principal=cfg['gatewayTlsPrincipal'])
