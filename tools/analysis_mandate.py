"""Gateway mandate owner. One admission transaction per attempt, with no network I/O under lock."""
from datetime import datetime, timezone
import json
import time
import uuid

from tools.analysis_clients import KeycloakIdentity
from tools.analysis_protocol import (
    ACTIONS, BINDINGS, RENEWAL_COMMAND, SEARCH_BATCH, STATUS_MAX_BYTES, Rejected, delegation, digest,
    human_proof, is_uuid, matches, parse, require, validate, wire,
)


def instant(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace('+00:00', 'Z')


def subject_key(issuer, tenant, subject):
    return digest(wire([issuer, tenant, subject]))


def new_ref():
    return str(uuid.uuid4())


def check_active(m, generation, now):
    require(m['state'] == 'ACTIVE' and m['generation'] == generation, 409)
    require(m['expires'] > now, 410)


def execute_scope(op, row):
    # All three governed discovery routes also check the common discovery scope.
    return 'ouf.semantic.discovery' if op.startswith('semantic.discovery.') else row['requiredAuthorizationCapability']


class Mandates:
    def __init__(self, store, catalog, iam, reservations, execute, key, *, enabled=False,
                 ttl=3600, proof_ttl=30, max_result=1048576, status_reads_per_minute=60, clock=time.time):
        if (type(enabled) is not bool or type(ttl) is not int or not 1 <= ttl <= 86400
                or type(proof_ttl) is not int or not 1 <= proof_ttl <= 30
                or type(max_result) is not int or not 1 <= max_result <= 1048576
                or type(status_reads_per_minute) is not int or not 1 <= status_reads_per_minute <= 3600
                or len(key) != 64 or any(c not in b'0123456789abcdefABCDEF' for c in key)):
            raise ValueError('invalid mandate installation profile')
        self.store, self.catalog, self.iam = store, catalog, iam
        self.reservations, self.execute, self.key = reservations, execute, key
        self.enabled, self.ttl, self.proof_ttl, self.max_result = enabled, ttl, proof_ttl, max_result
        self.clock = clock
        self.status_reads_per_minute = status_reads_per_minute

    def now(self):
        return int(self.clock())

    def handle(self, action, body, bearer, proof=None):
        ref, evidence = new_ref(), {'action': action if action in ACTIONS else 'UNKNOWN'}
        try:
            require(len(body) <= (STATUS_MAX_BYTES if action == 'status' else 131072))
            b = parse(body)
            validate(action, b)
            for k in ('analysisId', 'mandateId', 'generation', 'intentKey', 'attemptId', 'fence'):
                if k in b:
                    evidence[k] = b[k]
            scoped_read = action in ('status', 'renewal-check')
            w = self.iam.authenticate(bearer, self.now(), foreign_workload_status=404 if scoped_read else 403)
            evidence['workloadRef'] = subject_key(self.iam.issuer, w['tenant_id'], w['sub'])
            require(isinstance(w.get('scope'), str) and 'ouf.analysis.mandate.' + action in w['scope'].split(), 403)
            if action == 'renewal-check':
                p = human_proof(proof, self.key, self.iam.issuer, self.iam.audience, self.iam.workload,
                                w['tenant_id'], self.now(), purpose='analysis-renewal-decide')
                return 200, wire(self.renewal_check(b, w, p, digest(body), ref, evidence)), {}
            if action == 'status':
                return 200, wire(self.status(b, w, ref, evidence)), {}
            if action == 'dispatch':
                require(self.enabled, 403)
                return self.dispatch(b, w, bearer, ref, evidence)
            p = None
            if action == 'issue' or proof is not None:
                p = human_proof(proof, self.key, self.iam.issuer, self.iam.audience,
                                self.iam.workload, w['tenant_id'], self.now())
            reply = self.command(action, b, w, p, ref)
            return 200, wire(reply), {}
        except Rejected as exc:
            with self.store.transaction() as db:
                self.store.audit(db, ref, {**evidence, 'outcome': exc.code})
            return exc.status, wire({'code': exc.code}), {'Retry-After': exc.retry_after} if exc.retry_after else {}

    def decision(self, action, b, w, p, m=None):
        target = m if m is not None else b
        query = {'contract': 'ouf.analysis.authority-check.v1', 'action': action,
                 'issuer': self.iam.issuer, 'workload': self.iam.workload, 'workloadSubject': w['sub'],
                 'tenant': w['tenant_id'], 'subject': target['subject'] if m else p['principal'],
                 'actor': 'HUMAN' if p else 'SERVICE', 'actorRef': p['principal'] if p else w['sub'],
                 'analysisId': target['analysisId'], 'profile': target['profile'],
                 'manifestChecksum': target['manifestChecksum'], 'nonce': new_ref()}
        if m:
            query.update(mandateId=m['id'], grantRef=m['grantRef'], policyRef=m['policyRef'])
        if action == 'renew-budget':
            query.update({k: b[k] for k in ('generation', 'incidentId', 'proposalVersion', 'proposalHash',
                                            'expectedSeq', 'reviewRef', 'commandKey', 'decision')})
            query['commandHash'] = p['requestHash']
        if action == 'dispatch':
            query.update(operation=b['operation'], intentKey=b['intentKey'], argumentsHash=digest(wire(b['arguments'])),
                         resourceId=target['profile']['profileId'])
        if p:
            query.update(delegatedClient=p['client'], delegatedScope=p['scope'], acr=p['acr'])
        if isinstance(w, KeycloakIdentity):
            return self.iam.decide(query, self.now(), identity=w)
        return self.iam.decide(query, self.now())

    def renewal_check(self, b, w, p, request_hash, ref, evidence):
        m = self.store.get(b['mandateId'])
        require(m['issuer'] == self.iam.issuer and m['workload'] == w['client_id'] and m['tenant'] == w['tenant_id']
                and m['subject'] == p['principal'] and m['analysisId'] == b['analysisId'], 404)
        command = {k: b[k] for k in RENEWAL_COMMAND.split()}
        require(p.get('requestHash') == digest(wire(command)) and 'ouf.analysis.renewal.decide' in p['scope'].split(), 403)
        check_active(m, b['generation'], self.now())
        decision = self.decision('renew-budget', b, w, p, m)
        require(decision['grantRef'] == m['grantRef'] and decision['policyRef'] == m['policyRef'], 403)
        with self.store.transaction() as db:
            now = self.now()
            current = self.store.read(db, m['id'])
            check_active(current, b['generation'], now)
            valid_until = min(current['expires'], w['exp'], p['exp'], decision['grantExpiresAt'],
                              decision['validUntil'], now + self.proof_ttl)
            require(now < valid_until, 403)
            self.store.audit(db, ref, {**evidence, **self.audit_scope(current), 'outcome': 'RENEWAL_CHECKED',
                                       'requestHash': request_hash, 'iamDecisionRef': decision['decisionRef'],
                                       'incidentRefHash': digest(wire(b['incidentId'])), 'commandHash': p['requestHash'],
                                       'proposalVersion': b['proposalVersion'], 'proposalHash': b['proposalHash'],
                                       'validUntil': valid_until})
            return dict(requestHash=request_hash, decisionRef=decision['decisionRef'],
                        grantRef=current['grantRef'], validUntil=valid_until)

    def status(self, b, w, ref, evidence):
        self.store.charge_status(self.now(), self.status_reads_per_minute)
        m = self.store.get(b['mandateId'])
        require(m['issuer'] == self.iam.issuer and m['tenant'] == w['tenant_id']
                and m['workload'] == w['client_id'], 404)
        # A shared service identity alone does not identify the protected HUMAN.
        # Authorize this read independently of the execution grant and attempt.
        try:
            d = self.decision('status', b, w, None, m)
        except Rejected as exc:
            if exc.status == 403:
                raise Rejected(404) from exc
            raise
        with self.store.transaction() as db:
            now = self.now()
            require(now < w['exp'], 403)
            require(now < min(d['validUntil'], d['grantExpiresAt']), 404)
            m = self.store.read(db, b['mandateId'])
            require(m['generation'] == b['generation'], 409)
            state = m['state']
            if state == 'ACTIVE' and now >= m['expires']:
                state = 'EXPIRED'
            self.store.audit(db, ref, {**evidence, 'outcome': state})
            return dict(mandateId=m['id'], generation=m['generation'], state=state,
                        expiresAt=instant(m['expires']), decisionRef=ref)

    def command(self, action, b, w, p, ref):
        actor = subject_key(self.iam.issuer, w['tenant_id'], p['principal'] if p else w['sub'])
        fingerprint = digest(wire([action, b]))
        m = None
        if action == 'issue':
            require(self.catalog.checksum == b['manifestChecksum'], 409, 'COMMAND_CONFLICT')
        else:
            m = self.store.get(b['mandateId'])
            require(m['issuer'] == self.iam.issuer and m['tenant'] == w['tenant_id']
                    and (not p or m['subject'] == p['principal']), 404)
        try:
            d = self.decision(action if p else 'admin-revoke', b, w, p, m)
        except Rejected as exc:
            if not p and exc.status == 403:
                raise Rejected(404) from exc
            raise
        with self.store.transaction() as db:
            now = self.now()
            require(now < w['exp'] and (not p or now < p['exp']), 403)
            require(now < min(d['validUntil'], d['grantExpiresAt']), 403)
            if action == 'issue':
                scopes = p['scope'].split()
                operations = sorted(op for op, (row, _, _) in self.catalog.entries.items()
                                    if op in d['allowedOperations'] and execute_scope(op, row) in scopes)
                require('source.file.preview' in operations, 403)
            reply = self.store.command(db, actor, b, fingerprint)
            if reply:
                if action == 'issue':
                    require('source.file.preview' in reply['allowedOperations'], 403)
                    if isinstance(w, KeycloakIdentity):
                        original = self.store.read(db, reply['mandateId'])
                        require(original['grantRef'] == d['grantRef'] and original['policyRef'] == d['policyRef'],
                                409, 'COMMAND_CONFLICT')
                return reply
            if action == 'issue':
                existing = db.execute('select record from analysis_mandate_v1 where scope=? and plan=?',
                                      (actor, b['analysisId'])).fetchone()
                if existing:
                    m = json.loads(existing[0])
                    require(all(m[k] == b[k] for k in ('profile', 'manifestChecksum'))
                            and m['policyRef'] == d['policyRef'] and m['grantRef'] == d['grantRef']
                            and m['allowed'] == operations, 409, 'COMMAND_CONFLICT')
                    check_active(m, m['generation'], now)
                else:
                    m = {k: b[k] for k in ('analysisId', 'profile', 'manifestChecksum')}
                    m.update(id=new_ref(), decisionRef=ref, subject=p['principal'], tenant=w['tenant_id'],
                             issuer=self.iam.issuer, workload=self.iam.workload, generation='1', state='ACTIVE',
                             issued=now, expires=min(now+self.ttl, d['grantExpiresAt']), allowed=operations,
                             policyRef=d['policyRef'], grantRef=d['grantRef'])
                    db.execute('insert into analysis_mandate_v1 values (?,?,?,?)',
                               (m['id'], actor, b['analysisId'], wire(m)))
                reply = dict(mandateId=m['id'], generation=m['generation'], decisionRef=m['decisionRef'],
                             issuedAt=instant(m['issued']), expiresAt=instant(m['expires']), allowedOperations=m['allowed'])
                effects = 0
            else:
                m = self.store.read(db, b['mandateId'])
                require(m['generation'] == b['expectedGeneration'] and m['state'] == 'ACTIVE', 409, 'COMMAND_CONFLICT')
                m.update(state='REVOKED', generation=str(int(m['generation']) + 1))
                db.execute('update analysis_mandate_v1 set record=? where id=?', (wire(m), m['id']))
                effects = db.execute("""update analysis_attempt_v1 set crossed_revocation=1
                                        where mandate=? and phase in ('ADMITTED','UNCERTAIN')""", (m['id'],)).rowcount
                reply = dict(mandateId=m['id'], generation=m['generation'], state='REVOKED', decisionRef=ref)
            self.store.save_command(db, actor, b, fingerprint, reply)
            self.store.audit(db, ref, {**self.audit_scope(m), 'actorRef': actor, 'iamDecisionRef': d['decisionRef'],
                                       'outcome': action.upper(), 'inFlightCount': effects})
            return reply

    @staticmethod
    def audit_scope(m):
        return dict(analysisId=m['analysisId'], mandateId=m['id'], generation=m['generation'],
                    tenantRef=digest(wire([m['issuer'], m['tenant']])),
                    subjectRef=subject_key(m['issuer'], m['tenant'], m['subject']),
                    profileHash=digest(wire(m['profile'])), manifestChecksum=m['manifestChecksum'])

    def dispatch(self, b, w, bearer, ref, evidence):
        # MCP derives the subject from the immutable reservation, never from mandateId.
        m = self.store.get(b['mandateId'])
        require(m['issuer'] == self.iam.issuer and m['tenant'] == w['tenant_id']
                and b['analysisId'] == m['analysisId'], 404)
        started = self.now()
        r = self.reservations.check(b, self.iam.workload, started)
        require(r['issuer'] == m['issuer'] == self.iam.issuer and r['subject'] == m['subject']
                and r['tenant'] == m['tenant'] == w['tenant_id'] and b['analysisId'] == m['analysisId']
                and m['workload'] == self.iam.workload, 404)
        evidence.update(self.audit_scope(m))
        evidence.update(reservationRef=r['reservationRef'], ordinalsRef=r['ordinalsRef'], changeSeq=r['changeSeq'])
        check_active(m, b['generation'], self.now())
        require(self.catalog.checksum == r['manifestChecksum'] == m['manifestChecksum']
                and r['profileHash'] == digest(wire(m['profile'])), 409)
        op = b['operation']
        require(op in m['allowed'] and op in BINDINGS, 403)
        row, path = self.catalog.resolve(b, m['profile'])
        args = b['arguments']
        owner_key = args.get('idempotencyKey', b['attemptId'])
        evidence.update(operation=op, decisionRef=ref, ownerKeyHash=digest(owner_key.encode()),
                        argumentsHash=digest(wire(args)))
        if 'requestId' in args:
            evidence['requestId'] = args['requestId']
        d = self.decision('dispatch', b, w, None, m)
        evidence['iamDecisionRef'] = d['decisionRef']
        require(op in d['allowedOperations'] and d['policyRef'] == m['policyRef'] and d['grantRef'] == m['grantRef'], 403)
        limit = min(self.max_result, row['baseCostEnvelope']['hardMaxResultBytes'])
        envelope = dict(CapabilityID=row['capabilityId'], GatewayBindingRef=row['gatewayBindingRef'],
                        Owner=row['owner'], OperationClass=row['operationClass'], Arguments=args,
                        Identity=dict(PrincipalID=m['subject'], TenantID=m['tenant'], ActorType='HUMAN',
                                      AuthenticationContextRef=d['acr'], ServicePrincipalID=d['client']),
                        AuthorizationDecisionRef=ref, CorrelationID=ref, IdempotencyKey=owner_key,
                        AttemptID=b['attemptId'], RequestHash=digest(wire(args)), MaxResultBytes=limit)
        body = wire(envelope)
        require(len(body) <= 65536)
        with self.store.transaction() as db:
            now = self.now()
            check_active(self.store.read(db, m['id']), b['generation'], now)
            lease_end = min(r['validUntil'], started + self.proof_ttl)
            require(started <= now < lease_end, 409)
            exp = min(now + self.proof_ttl, m['expires'], w['exp'], d['validUntil'], d['grantExpiresAt'], lease_end)
            require(exp > now, 403)
            self.store.admit(db, m, b, evidence)
        # This ephemeral proof travels only to the exact governed execute route over verified TLS.
        # The existing route signs its final (possibly rewritten) owner body and strips credentials.
        proof = delegation(dict(v=1, purpose='mcp-execute', actor='HUMAN', iss=m['issuer'], aud=self.iam.audience,
                                workload=m['workload'], principal=m['subject'], tenant=m['tenant'], client=d['client'],
                                acr=d['acr'], scope=execute_scope(op, row), roles=' '.join(sorted(d['roles'])),
                                decisionRef=ref, iat=now, exp=exp), self.key)
        headers = {'Content-Type': 'application/json', 'Authorization': bearer, 'X-OUF-Delegation': proof,
                   'X-Correlation-ID': ref, 'Idempotency-Key': owner_key, 'X-Tool-Attempt-ID': b['attemptId']}
        status, request_id, failure = None, None, None
        try:
            status, result, retry = self.execute.post(body, headers, limit, path)
            if op == 'semantic.discovery.request' and 200 <= status < 300:
                try:
                    owner = json.loads(result)
                    if type(owner) is dict and is_uuid(owner.get('requestId')):
                        request_id = owner['requestId']
                except (ValueError, RecursionError):
                    pass
        except Rejected as exc:
            failure = exc
        finally:
            stale_cause = self.store.finish(evidence, status, request_id)
        metadata = {'X-OUF-Analysis-Decision': ref, 'X-Correlation-ID': ref}
        if stale_cause:
            metadata['X-OUF-Analysis-Effect'] = 'IN_FLIGHT'
            metadata['X-OUF-Analysis-Stale-Cause'] = stale_cause
            return 409, wire({'code': 'ANALYSIS_STALE_EXECUTION'}), metadata
        if failure:
            if failure.retry_after:
                metadata['Retry-After'] = failure.retry_after
            return failure.status, wire({'code': failure.code}), metadata
        if op == SEARCH_BATCH and status == 429:
            try:
                problem = json.loads(result)
            except (ValueError, RecursionError):
                problem = None
            if not isinstance(problem, dict) or problem.get('code') != 'SEM_BATCH_RATE_LIMITED':
                result = wire({'code': 'SEM_BATCH_RATE_LIMITED'})
            if not matches(retry, '[0-9]+'):
                retry = None
        if retry and status in (429, 503):
            metadata['Retry-After'] = retry
        return status, result, metadata
