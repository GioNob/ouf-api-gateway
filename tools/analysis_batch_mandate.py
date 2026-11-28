"""Gateway mediation for the first round of a BATCH_V1 analysis."""
import json
import logging
import sqlite3
import threading
import time
import uuid

from tools.analysis_batch_protocol import (
    Denied, MAX_REQUEST, OPERATIONS, OPERATIONS_WIRE, TTL_MS, arguments, digest, exact,
    hash_ref, identity_value, parse, require, scopes, token, uuid_ref, verify_start, wire,
)

LOG = logging.getLogger(__name__)
UNAVAILABLE = 'ANALYSIS_AUTHORITY_UNAVAILABLE'
CLOCK = 'ANALYSIS_CLOCK_UNVERIFIED'
EVIDENCE = 'ANALYSIS_EVIDENCE_UNVERIFIED'
DISCOVERY_REQUEST = 'semantic.discovery.request'
CLOSED_PHASES = ('FIRST_ROUND_COMPLETE', 'CLOSED', 'CANCELLED')


class Clock:
    def __init__(self, skew_ms, wall=None, monotonic=None):
        self.skew_ms = skew_ms
        self.wall = wall or (lambda: time.time_ns() // 1_000_000)
        self.monotonic = monotonic or (lambda: time.monotonic_ns() // 1_000_000)
        self.lock = threading.Lock()
        self.last = None

    def checked(self):
        with self.lock:
            now, tick = self.wall(), self.monotonic()
            previous = self.last
            self.last = now, tick
            if previous is not None:
                wall_delta, tick_delta = now - previous[0], tick - previous[1]
                require(wall_delta >= 0 and tick_delta >= 0
                        and abs(wall_delta - tick_delta) <= self.skew_ms, 503, CLOCK)
            return now

    def evidence(self, endpoint, query, bearer=None, *, local_clock=True):
        body = wire({**query, 'nonce': str(uuid.uuid4())})
        started = self.monotonic()
        response = endpoint.evidence(body, bearer)
        observed = self.monotonic()
        require(isinstance(response, dict) and response.get('requestHash') == digest(body)
                and response.get('clockSynchronized') is True, 503, EVIDENCE)
        remote, until = response.get('observedAtMs'), response.get('validUntilMs')
        require(type(remote) is int and type(until) is int and 0 < until - remote <= 30_000
                and 0 <= observed - started <= self.skew_ms, 503, EVIDENCE)
        proof = Evidence(response, started, observed)
        proof.check(self, self.checked() if local_clock else None)
        return proof


class Evidence:
    def __init__(self, value, started, observed):
        self.value, self.started, self.observed = value, started, observed

    def check(self, clock, now):
        tick = clock.monotonic()
        remote = self.value['observedAtMs']
        # Observation can occur anywhere during the round trip. Require the
        # entire uncertainty interval to fit the skew and validity limits.
        low = remote + tick - self.observed
        high = remote + tick - self.started
        require(tick >= self.observed and low <= high < self.value['validUntilMs'], 503, EVIDENCE)
        if now is not None:
            require(max(abs(now - low), abs(now - high)) <= clock.skew_ms, 503, CLOCK)

    def local_expiry(self, clock, now):
        return now + self.value['validUntilMs'] - self.value['observedAtMs'] - (clock.monotonic() - self.started)


class BatchMandates:
    def __init__(self, config, store, rights, mcp_state, semantic, clock):
        self.config, self.store, self.clock = config, store, clock
        self.rights, self.mcp_state, self.semantic = rights, mcp_state, semantic

    def event(self, ctx, outcome, reason):
        row = ctx['record'] or {}
        authority = json.loads(row['authority']) if row.get('authority') else {}
        actor = ctx['actor'] or {k: row[k] for k in ('issuer', 'tenant', 'subject') if k in row}
        return dict(installation=self.config.installation, atMs=self.clock.wall(), outcome=outcome, reason=reason,
                    action=ctx['action'], operation=ctx['operation'], actor=actor, workload=row.get('workload'),
                    principal={k: row[k] for k in ('issuer', 'tenant', 'subject') if k in row},
                    analysisId=row.get('analysis_id'), generation=row.get('generation'), version=row.get('version'),
                    policyEpoch=authority.get('policyEpoch'), correlationId=ctx['correlation'])

    def denial(self, ctx, error):
        event = self.event(ctx, 'DENIED', error.code)
        try:
            with self.store.transaction() as db:
                self.store.audit(db, event)
        except sqlite3.Error:
            LOG.warning('%s', wire(event).decode('ascii'))

    def handle(self, action, data, peer, bearer=None):
        ctx = dict(action=action, operation=None, actor=None, record=None, correlation=str(uuid.uuid4()))
        try:
            require(action in ('prepare', 'issue', 'dispatch', 'expire', 'revoke'), 404, 'ANALYSIS_ROUTE_NOT_FOUND')
            if action == 'revoke':
                require(peer in ('mcp', 'human') and isinstance(bearer, str)
                        and token(bearer, r'Bearer [!-~]{1,16384}'), 403, 'ANALYSIS_HUMAN_REQUIRED')
            else:
                require(peer == 'mcp' and bearer is None, 403, 'ANALYSIS_WORKLOAD_PROOF_REQUIRED')
                ctx['actor'] = {'type': 'SERVICE', 'workload': self.config.workload}
            require(0 < len(data) <= MAX_REQUEST, 413, 'ANALYSIS_REQUEST_TOO_LARGE')
            require(self.store.initialized, 503, 'ANALYSIS_REGISTRY_UNAVAILABLE')
            result = getattr(self, action)(parse(data), ctx, bearer)
            return result if action == 'dispatch' else (200, wire(result), {})
        except sqlite3.Error as exc:
            error = Denied(503, 'ANALYSIS_REGISTRY_UNAVAILABLE')
            self.denial(ctx, error)
            raise error from exc
        except Denied as error:
            self.denial(ctx, error)
            raise

    def context(self, row):
        return dict(contract='ouf.analysis.batch.mandate.v1', installation=self.config.installation,
                    version=row['version'], **self.store.binding(row))

    def read_record(self, request, ctx):
        require(uuid_ref(request['mandateRef'], v4=True) and type(request['generation']) is int)
        row = self.store.get(request['mandateRef'])
        ctx['record'] = row
        require(row['storage_epoch'] == self.config.storage_epoch and row['workload'] == self.config.workload
                and row['issuer'] == self.config.issuer and row['operations'] == OPERATIONS_WIRE
                and row['generation'] == request['generation'], 403, 'ANALYSIS_MANDATE_BINDING_MISMATCH')
        return row

    @staticmethod
    def view(row):
        return dict(mandateRef=row['ref'], generation=row['generation'], version=row['version'],
                    state=row['state'], analysisId=row['analysis_id'], expiresAtMs=row['expires_ms'])

    def prepare(self, request, ctx, _):
        require(exact(request, 'startProof'))
        now = self.clock.checked()
        p = verify_start(request['startProof'], self.config, now)
        actor = {k: p[k] for k in ('issuer', 'tenant', 'subject')}
        ctx['actor'] = actor
        record = dict(installation=self.config.installation, storage_epoch=self.config.storage_epoch,
                      ref=str(uuid.uuid4()), **actor, workload=p['workload'], client=p['client'],
                      plan=wire({**p['plan'], 'scope': p['scope']}), command_key=p['plan']['commandKey'],
                      operations=OPERATIONS_WIRE, expires_ms=p['iat'] * 1000 + TTL_MS)
        with self.store.transaction() as db:
            row, _ = self.store.reserve(db, record)
            ctx['record'] = row
            require(all(row[k] == record[k] for k in ('storage_epoch', 'workload', 'client', 'plan')),
                    409, 'ANALYSIS_START_KEY_CONFLICT')
        return self.view(row)

    def state_proof(self, row, action, **extra):
        query = {**self.context(row), 'action': action, **extra}
        proof = self.clock.evidence(self.mcp_state, query)
        e = proof.value
        require(type(e.get('bound')) is bool, 503, EVIDENCE)
        require(e['bound'], 403, 'ANALYSIS_WORK_NOT_BOUND')
        require(e.get('phase') in ('FIRST_ROUND', *CLOSED_PHASES) and hash_ref(e.get('analysisId'))
                and hash_ref(e.get('policyEpoch'))
                and (row['analysis_id'] is None or row['analysis_id'] == e['analysisId']), 503, EVIDENCE)
        return proof

    def rights_proof(self, row, action, **extra):
        proof = self.clock.evidence(self.rights, {**self.context(row), 'action': action, **extra})
        e = proof.value
        require(type(e.get('active')) is bool and type(e.get('allowed')) is bool, 503, EVIDENCE)
        require(e['active'] and e['allowed'], 403, 'ANALYSIS_CURRENT_RIGHTS_DENIED')
        scope = scopes(e.get('scope'), 503, EVIDENCE)
        roles, grants = e.get('roles'), e.get('grants')
        require(hash_ref(e.get('policyEpoch')) and token(e.get('decisionRef')) and identity_value(e.get('acr'))
                and isinstance(roles, list) and len(roles) <= 32
                and all(token(r, r'[A-Za-z0-9_:./-]{1,128}') for r in roles)
                and isinstance(grants, dict) and grants.keys() == OPERATIONS.keys()
                and all(hash_ref(value) for value in grants.values()), 503, EVIDENCE)
        require(scope == json.loads(row['plan'])['scope']
                and all(op.scope in scope for op in OPERATIONS.values()), 403, 'ANALYSIS_SCOPE_CHANGED')
        snapshot = dict(policyEpoch=e['policyEpoch'], grants=grants, scope=scope, roles=sorted(set(roles)), acr=e['acr'])
        return proof, snapshot

    def fence(self, db, row, *proofs):
        current = self.store.read(db, row['ref'])
        require(current == row, 409, 'ANALYSIS_MANDATE_VERSION_CHANGED')
        now = self.clock.checked()
        for proof in proofs:
            proof.check(self.clock, now)
        self.store.observe_clock(db, now)
        return now

    def expire_locked(self, db, ctx, row, reason):
        row = self.store.terminate(db, row, 'EXPIRED')
        ctx['record'] = row
        self.store.audit(db, self.event(ctx, 'EXPIRED', reason))
        return row

    def issue(self, request, ctx, _):
        require(exact(request, 'mandateRef generation commandKey') and uuid_ref(request['commandKey'], v4=True))
        row = self.read_record(request, ctx)
        require(row['command_key'] == request['commandKey'], 403, 'ANALYSIS_START_KEY_CONFLICT')
        if row['state'] != 'PENDING':
            return self.view(row)
        state = self.state_proof(row, 'issue')
        resolved = {**row, 'analysis_id': state.value['analysisId']}
        if state.value['phase'] == 'FIRST_ROUND':
            rights, snapshot = self.rights_proof(resolved, 'issue')
            require(snapshot['policyEpoch'] == state.value['policyEpoch'], 403, 'ANALYSIS_POLICY_EPOCH_CHANGED')
            proofs = state, rights
        else:
            proofs = (state,)
        with self.store.transaction() as db:
            current = self.store.read(db, row['ref'])
            if current['state'] != 'PENDING':
                return self.view(current)
            now = self.fence(db, row, *proofs)
            if now >= row['expires_ms']:
                return self.view(self.expire_locked(db, ctx, row, 'ABSOLUTE_DEADLINE'))
            if state.value['phase'] in CLOSED_PHASES:
                return self.view(self.expire_locked(db, ctx, row, state.value['phase']))
            row = self.store.activate(db, row, resolved['analysis_id'], snapshot, now + TTL_MS)
            ctx.update(record=row, actor={k: row[k] for k in ('issuer', 'tenant', 'subject')})
            self.store.audit(db, self.event(ctx, 'ISSUED', 'VERIFIED_BATCH_PLAN'))
        return self.view(row)

    def terminal(self, request, ctx):
        require(exact(request, 'mandateRef generation expectedVersion') and type(request['expectedVersion']) is int)
        row = self.read_record(request, ctx)
        require(row['version'] == request['expectedVersion'] and row['state'] in ('PENDING', 'ACTIVE'),
                409, 'ANALYSIS_MANDATE_VERSION_CHANGED')
        return row

    def revoke(self, request, ctx, bearer):
        row = self.terminal(request, ctx)
        proof = self.clock.evidence(self.rights, {**self.context(row), 'action': 'revoke'}, bearer, local_clock=False)
        e = proof.value
        require(e.get('active') is True and e.get('allowed') is True and e.get('actorType') == 'HUMAN'
                and e.get('issuer') == row['issuer'] and e.get('tenant') == row['tenant']
                and identity_value(e.get('subject')) and identity_value(e.get('client')), 403, 'ANALYSIS_REVOKE_DENIED')
        require(e['subject'] == row['subject']
                or (e['client'] == self.config.ths_client and e.get('operatorAuthorized') is True),
                403, 'ANALYSIS_REVOKE_DENIED')
        ctx['actor'] = {k: e[k] for k in ('issuer', 'tenant', 'subject')}
        with self.store.transaction() as db:
            proof.check(self.clock, None)
            row = self.store.terminate(db, row, 'REVOKED')
            ctx['record'] = row
            self.store.audit(db, self.event(ctx, 'REVOKED', 'HUMAN_REVOCATION'))
        return self.view(row)

    def expire(self, request, ctx, _):
        require(exact(request, 'mandateRef generation expectedVersion') and type(request['expectedVersion']) is int)
        row = self.read_record(request, ctx)
        if row['state'] in ('REVOKED', 'EXPIRED'):
            return self.view(row)
        require(row['version'] == request['expectedVersion'], 409, 'ANALYSIS_MANDATE_VERSION_CHANGED')
        state = self.state_proof(row, 'expire')
        require(state.value['phase'] in CLOSED_PHASES, 409, 'ANALYSIS_FIRST_ROUND_ACTIVE')
        with self.store.transaction() as db:
            current = self.store.read(db, row['ref'])
            if current['state'] in ('REVOKED', 'EXPIRED'):
                return self.view(current)
            self.fence(db, row, state)
            return self.view(self.expire_locked(db, ctx, row, state.value['phase']))

    def sweep(self):
        self.store.initialize()
        clock = self.clock.evidence(self.rights, dict(action='clock', installation=self.config.installation))
        ctx = dict(action='sweep', operation=None, actor=None, record=None, correlation=str(uuid.uuid4()))
        with self.store.transaction() as db:
            now = self.clock.checked()
            clock.check(self.clock, now)
            self.store.observe_clock(db, now)
            for row in self.store.due(db, now, 128):
                self.expire_locked(db, ctx, row, 'ABSOLUTE_DEADLINE')

    def dispatch(self, request, ctx, _):
        require(exact(request, 'mandateRef generation analysisId operation arguments attemptId correlationId'))
        name = request['operation']
        require(isinstance(name, str) and name in OPERATIONS, 403, 'ANALYSIS_OPERATION_NOT_ALLOWED')
        require(uuid_ref(request['attemptId']) and uuid_ref(request['correlationId']) and hash_ref(request['analysisId']))
        ctx.update(operation=name, correlation=request['correlationId'])
        row = self.read_record(request, ctx)
        require(row['analysis_id'] == request['analysisId'] and row['state'] == 'ACTIVE',
                403, 'ANALYSIS_MANDATE_NOT_ACTIVE')
        args = request['arguments']
        args_hash = arguments(name, args)
        bound = dict(operation=name, argumentsHash=args_hash, attemptId=request['attemptId'])
        if 'requestId' in args:
            bound['requestId'] = args['requestId']
        state = self.state_proof(row, 'dispatch', **bound)
        if self.close_if_due(ctx, row, state):
            raise Denied(403, 'ANALYSIS_MANDATE_EXPIRED')
        saved = json.loads(row['authority'])
        require(state.value['policyEpoch'] == saved['policyEpoch'], 403, 'ANALYSIS_POLICY_EPOCH_CHANGED')
        rights, current = self.rights_proof(row, 'dispatch', **bound)
        require(current == saved, 403, 'ANALYSIS_CURRENT_RIGHTS_CHANGED')
        work_ref = state.value.get('workRef')
        require(name == 'semantic.search.batch' or hash_ref(work_ref), 503, EVIDENCE)
        body, headers = self.owner_call(request, row, rights.value, saved)
        op = OPERATIONS[name]
        with self.store.transaction() as db:
            now = self.fence(db, row, state, rights)
            if now >= row['expires_ms']:
                self.expire_locked(db, ctx, row, 'ABSOLUTE_DEADLINE')
                expired = True
            else:
                expired = False
                if name == DISCOVERY_REQUEST:
                    actor_hash = digest(wire([row[k] for k in ('issuer', 'tenant', 'subject')]))
                    self.store.pin_discovery(db, row['ref'], work_ref, actor_hash,
                                             digest(args['idempotencyKey'].encode('ascii')), args_hash)
                elif op.family == 'discovery':
                    require(self.store.owns_request(db, row['ref'], work_ref, args['requestId']),
                            403, 'ANALYSIS_DISCOVERY_REQUEST_NOT_BOUND')
                expires = min(row['expires_ms'], *(proof.local_expiry(self.clock, now) for proof in (state, rights)))
                key = self.config.owner_keys[op.family]
                header, value = op.receipt(key, self.config, row, saved, body, now, expires)
                headers[header] = value
                self.store.charge(db, name, now, self.config.rates[name])
                self.store.audit(db, self.event(ctx, 'ADMITTED', 'CURRENT_MANDATE'))
        if expired:
            raise Denied(403, 'ANALYSIS_MANDATE_EXPIRED')
        # The committed audit is the admission point. Remote I/O never holds
        # the registry transaction, and a revocation may follow this admission.
        now = self.clock.checked()
        for proof in (state, rights):
            proof.check(self.clock, now)
        require(now // 1000 < expires // 1000, 403, 'ANALYSIS_EVIDENCE_EXPIRED')
        status, data, headers = self.semantic.send(op.path, body, headers, self.config.max_result_bytes)
        if name == DISCOVERY_REQUEST and 200 <= status < 300:
            try:
                result = parse(data)
            except Denied as exc:
                raise Denied(503, 'ANALYSIS_DISCOVERY_RECEIPT_UNVERIFIED') from exc
            require(isinstance(result, dict) and uuid_ref(result.get('requestId')), 503,
                    'ANALYSIS_DISCOVERY_RECEIPT_UNVERIFIED')
            self.store.bind_request(row['ref'], work_ref, result['requestId'])
        return status, data, headers

    def close_if_due(self, ctx, row, state):
        phase = state.value['phase']
        if self.clock.checked() < row['expires_ms'] and phase not in CLOSED_PHASES:
            return False
        with self.store.transaction() as db:
            now = self.fence(db, row, state)
            if now >= row['expires_ms'] or phase in CLOSED_PHASES:
                reason = 'ABSOLUTE_DEADLINE' if now >= row['expires_ms'] else phase
                self.expire_locked(db, ctx, row, reason)
                return True
        return False

    def owner_call(self, request, row, decision, authority):
        op = OPERATIONS[request['operation']]
        args = request['arguments']
        correlation, attempt = request['correlationId'], request['attemptId']
        idem = args.get('idempotencyKey', attempt)
        body = wire(dict(
            GatewayBindingRef='capability://' + op.capability, CapabilityID=op.capability, Owner='semantic',
            OperationClass=op.operation_class, Arguments=args, AuthorizationDecisionRef=decision['decisionRef'],
            Identity=dict(ServicePrincipalID=row['client'], PrincipalID=row['subject'], TenantID=row['tenant'],
                          ActorType='HUMAN', AuthenticationContextRef=authority['acr']),
            CorrelationID=correlation, IdempotencyKey=idem, AttemptID=attempt,
            RequestHash=digest(wire(args)), MaxResultBytes=self.config.max_result_bytes,
        ))
        require(len(body) <= MAX_REQUEST, 413, 'ANALYSIS_OWNER_REQUEST_TOO_LARGE')
        headers = {'Content-Type': 'application/json', 'X-Correlation-ID': correlation,
                   'Idempotency-Key': idem, 'X-Tool-Attempt-ID': attempt}
        return body, headers
