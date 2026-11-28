"""Gateway mediation for the first round of a BATCH_V1 analysis."""
import logging
import sqlite3
import threading
import time
import uuid

from tools.analysis_batch_protocol import (
    Denied, MAX_REQUEST, OPERATIONS, arguments, b64, digest, exact, hash_ref, identity_value,
    mac, parse, require, sign_binding, token, uuid_ref, verify_binding, verify_start, wire,
)

LOG = logging.getLogger(__name__)
UNAVAILABLE = 'ANALYSIS_AUTHORITY_UNAVAILABLE'
AUTHORIZATION_UNAVAILABLE = 'ANALYSIS_AUTHORIZATION_UNAVAILABLE'
AUTHORIZATION_INVALID = 'ANALYSIS_AUTHORIZATION_RESPONSE_INVALID'
AUTHORIZATION_TLS = 'ANALYSIS_AUTHORIZATION_TLS_UNVERIFIED'
CLOCK = 'ANALYSIS_CLOCK_UNVERIFIED'
EVIDENCE = 'ANALYSIS_EVIDENCE_UNVERIFIED'
DISCOVERY_REQUEST = 'semantic.discovery.request'
DISCOVERY_BINDING_HEADER = 'X-OUF-Analysis-Discovery-Binding'
CLOSED_PHASES = ('FIRST_ROUND_COMPLETE', 'CLOSED', 'CANCELLED')
START_BINDING = 'ouf-analysis-batch-prepared-v1'
MANDATE_BINDING = 'ouf-analysis-batch-binding-v1'
DISCOVERY_BINDING = 'ouf-analysis-batch-discovery-v1'


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

    def evidence(self, endpoint, query):
        body = wire({**query, 'nonce': str(uuid.uuid4())})
        started = self.monotonic()
        response = endpoint.evidence(body)
        observed = self.monotonic()
        require(isinstance(response, dict) and response.get('requestHash') == digest(body)
                and response.get('clockSynchronized') is True, 503, EVIDENCE)
        remote, until = response.get('observedAtMs'), response.get('validUntilMs')
        require(type(remote) is int and type(until) is int and 0 < until - remote <= 30_000
                and 0 <= observed - started <= self.skew_ms, 503, EVIDENCE)
        proof = Evidence(response, started, observed)
        proof.check(self, self.checked())
        return proof


class Evidence:
    def __init__(self, value, started, observed):
        self.value, self.started, self.observed = value, started, observed

    def check(self, clock, now):
        tick = clock.monotonic()
        remote = self.value['observedAtMs']
        # The observation can occur anywhere during the round trip.
        low = remote + tick - self.observed
        high = remote + tick - self.started
        require(tick >= self.observed and high < self.value['validUntilMs'], 503, EVIDENCE)
        require(max(abs(now - low), abs(now - high)) <= clock.skew_ms, 503, CLOCK)
        return now + self.value['validUntilMs'] - high


class BatchMandates:
    def __init__(self, config, audit, authorization, receipt_context, mcp_state, semantic, clock):
        self.config, self.audit, self.clock = config, audit, clock
        self.authorization, self.receipt_context = authorization, receipt_context
        self.mcp_state, self.semantic = mcp_state, semantic

    def record_event(self, ctx, outcome, reason):
        event = dict(installation=self.config.installation, atMs=self.clock.wall(),
                     outcome=outcome, reason=reason, **ctx)
        try:
            if self.audit is not None:
                self.audit.write(event)
                return
        except sqlite3.Error:
            LOG.warning('ANALYSIS_LOCAL_AUDIT_UNAVAILABLE')
        LOG.info('%s', wire(event).decode('ascii'))

    def handle(self, action, data, peer, bearer=None):
        ctx = dict(action=action, correlationId=str(uuid.uuid4()))
        try:
            require(action in ('prepare', 'issue', 'dispatch', 'expire', 'revoke', 'read'),
                    404, 'ANALYSIS_ROUTE_NOT_FOUND')
            if action == 'revoke':
                require(peer in ('mcp', 'human') and isinstance(bearer, str) and len(bearer) <= 8192
                        and token(bearer, r'(?i:Bearer) [A-Za-z0-9._~+/-]+=*'), 403, 'ANALYSIS_HUMAN_REQUIRED')
            else:
                require(peer == 'mcp' and bearer is None, 403, 'ANALYSIS_WORKLOAD_PROOF_REQUIRED')
                ctx['workload'] = self.config.workload
            require(0 < len(data) <= MAX_REQUEST, 413, 'ANALYSIS_REQUEST_TOO_LARGE')
            result = getattr(self, action)(parse(data), ctx, bearer)
        except Denied as error:
            self.record_event(ctx, 'DENIED', error.code)
            raise
        return result if action == 'dispatch' else (200, wire(result), {})

    def sign(self, domain, value):
        return sign_binding(self.config.binding_key, domain, value)

    def verify(self, proof, domain):
        return verify_binding(proof, self.config.binding_key, domain, 'ANALYSIS_BINDING_PROOF_DENIED')

    def start_binding(self, p):
        fields = {k: p[k] for k in ('installation', 'issuer', 'audience', 'tenant', 'subject',
                                     'client', 'workload', 'scope')}
        identity = [p[k] for k in ('installation', 'issuer', 'tenant', 'subject')]
        start_ref = uuid.UUID(hex=digest(wire([*identity, p['plan']['commandKey']]))[:32], version=4)
        return dict(**fields, **p['plan'], startRef=str(start_ref))

    def check_installation(self, binding):
        require(all(binding[k] == getattr(self.config, k) for k in ('installation', 'issuer', 'audience', 'workload')),
                403, 'ANALYSIS_MANDATE_BINDING_MISMATCH')

    def prepare(self, request, ctx, _):
        require(exact(request, 'startProof'))
        p = verify_start(request['startProof'], self.config, self.clock.checked())
        binding = self.start_binding(p)
        return dict(mandateRef=binding['startRef'], generation=1, version=0, state='PENDING',
                    analysisId=None, expiresAtMs=p['exp'] * 1000, startBinding=self.sign(START_BINDING, binding))

    def context(self, binding, action):
        return dict(contract='ouf.analysis.batch.mandate.v1', action=action,
                    **{k: binding[k] for k in ('installation', 'issuer', 'tenant', 'subject', 'client', 'workload',
                                               'startRef', 'mode', 'assetId', 'profileId', 'schemaHash', 'commandKey',
                                               'scope', 'analysisId', 'generation', 'version')})

    def state_proof(self, binding, action, **extra):
        proof = self.clock.evidence(self.mcp_state, {**self.context(binding, action), **extra})
        e = proof.value
        require(type(e.get('bound')) is bool, 503, EVIDENCE)
        require(e['bound'], 403, 'ANALYSIS_WORK_NOT_BOUND')
        require(e.get('phase') in ('FIRST_ROUND', *CLOSED_PHASES) and hash_ref(e.get('analysisId'))
                and hash_ref(e.get('policyEpoch'))
                and (binding['analysisId'] is None or binding['analysisId'] == e['analysisId']), 503, EVIDENCE)
        return proof

    def issue(self, request, ctx, _):
        fields = 'mandateRef generation commandKey analysisId policyEpoch startBinding'
        require(exact(request, fields) or exact(request, fields + ' startProof'))
        require(type(request['generation']) is int and request['generation'] == 1
                and hash_ref(request['analysisId']) and hash_ref(request['policyEpoch']))
        start = self.verify(request['startBinding'], START_BINDING)
        self.check_installation(start)
        require(start['startRef'] == request['mandateRef'] and start['commandKey'] == request['commandKey'],
                403, 'ANALYSIS_MANDATE_BINDING_MISMATCH')
        binding = dict(start, analysisId=request['analysisId'], generation=1, version=0)
        payload = {k: binding[k] for k in ('analysisId', 'assetId', 'profileId', 'schemaHash', 'issuer', 'tenant',
                                         'subject', 'client', 'workload', 'startRef', 'commandKey', 'scope', 'generation')}
        payload.update(issueKey=start['commandKey'], expectedVersion=0, policyEpoch=request['policyEpoch'])
        ctx.update(analysisId=payload['analysisId'], generation=1, policyEpoch=payload['policyEpoch'])
        if 'startProof' in request:
            state = self.state_proof(binding, 'issue')
            now = self.clock.checked()
            expires = state.check(self.clock, now)
            p = verify_start(request['startProof'], self.config, now)
            require(start == self.start_binding(p), 403, 'ANALYSIS_MANDATE_BINDING_MISMATCH')
            require(state.value['phase'] == 'FIRST_ROUND', 403, 'ANALYSIS_MANDATE_EXPIRED')
            require(state.value['policyEpoch'] == payload['policyEpoch'], 403, 'ANALYSIS_POLICY_EPOCH_CHANGED')
            payload['proof'] = dict(actorType='HUMAN', mode='BATCH_V1', phase='FIRST_ROUND',
                                    authenticatedAtMs=p['authTime'] * 1000, observedAtMs=now,
                                    validUntilMs=min(expires, now + 30_000, p['exp'] * 1000))
        view = self.authorization.command('issue', payload)
        if view['state'] == 'ACTIVE':
            view = dict(view, mandateBinding=self.sign(MANDATE_BINDING, {**start, **view,
                                                                        'policyEpoch': payload['policyEpoch']}))
        self.record_event(ctx, 'VERIFIED', 'AUTHORIZATION_ISSUE_RESULT')
        return view

    def mandate_binding(self, request, ctx):
        binding = self.verify(request['mandateBinding'], MANDATE_BINDING)
        self.check_installation(binding)
        require(all(binding[k] == request[k] for k in ('mandateRef', 'generation', 'analysisId') if k in request),
                403, 'ANALYSIS_MANDATE_BINDING_MISMATCH')
        ctx.update(analysisId=binding['analysisId'], generation=binding['generation'], policyEpoch=binding['policyEpoch'])
        return binding

    def read(self, request, ctx, _):
        require(exact(request, 'mandateRef generation mandateBinding') and type(request['generation']) is int)
        binding = self.mandate_binding(request, ctx)
        return self.authorization.command('read', {k: binding[k] for k in ('mandateRef', 'generation')})

    def revoke(self, request, ctx, bearer):
        require(exact(request, 'mandateRef generation expectedVersion'))
        require(uuid_ref(request['mandateRef'], v4=True) and type(request['generation']) is int
                and request['generation'] > 0 and type(request['expectedVersion']) is int
                and request['expectedVersion'] > 0)
        try:
            result = self.authorization.command('revoke', {**request, 'correlationId': ctx['correlationId']}, bearer)
        except Denied as error:
            if error.code in (AUTHORIZATION_UNAVAILABLE, AUTHORIZATION_INVALID, AUTHORIZATION_TLS,
                              'REGISTRY_FAILURE'):
                # A primary read can resolve the row state for audit. It cannot
                # attribute a terminal transition to this HUMAN's failed call.
                try:
                    view = self.authorization.command('read', {k: request[k] for k in ('mandateRef', 'generation')})
                    self.record_event(ctx, 'RECONCILED', 'AUTHORIZATION_STATE_' + view['state'])
                except Denied:
                    self.record_event(ctx, 'UNCERTAIN', 'AUTHORIZATION_READ_FAILED')
                raise Denied(error.status, 'ANALYSIS_REVOCATION_OUTCOME_UNCERTAIN', error.retry_after) from error
            raise
        self.record_event(ctx, 'VERIFIED', 'AUTHORIZATION_REVOCATION')
        return result

    def expire(self, request, ctx, _):
        require(exact(request, 'mandateRef generation expectedVersion mandateBinding')
                and type(request['generation']) is int and type(request['expectedVersion']) is int
                and request['expectedVersion'] > 0)
        binding = self.mandate_binding(request, ctx)
        state = self.state_proof(binding, 'expire')
        reason = state.value['phase']
        if reason not in CLOSED_PHASES:
            require(self.clock.checked() >= binding['expiresAtMs'], 409, 'ANALYSIS_FIRST_ROUND_ACTIVE')
            reason = 'ABSOLUTE_DEADLINE'
        state.check(self.clock, self.clock.checked())
        return self.expire_at_owner(binding, request['expectedVersion'], reason, ctx['correlationId'])

    def expire_at_owner(self, binding, version, reason, correlation):
        payload = {k: binding[k] for k in ('mandateRef', 'generation', 'analysisId')}
        return self.authorization.command('expire', dict(payload, expectedVersion=version, reason=reason,
                                                         correlationId=correlation))

    def admitted_claims(self, admitted, binding):
        claims = admitted['receiptContext']
        identity = ('issuer', 'tenant', 'subject', 'client', 'workload')
        require(admitted['expiresAtMs'] == binding['expiresAtMs']
                and exact(claims, 'issuer tenant subject client workload actorType decisionRef acr scope roles validUntilMs')
                and all(claims[k] == binding[k] for k in identity) and claims['actorType'] == 'HUMAN'
                and token(claims['decisionRef']) and identity_value(claims['acr'])
                and isinstance(claims['scope'], list) and all(identity_value(s) for s in claims['scope'])
                and sorted(claims['scope']) == binding['scope']
                and isinstance(claims['roles'], list) and len(claims['roles']) <= 32
                and all(token(r, r'[A-Za-z0-9_:./-]{1,128}') for r in claims['roles'])
                and len(set(claims['roles'])) == len(claims['roles'])
                and type(claims['validUntilMs']) is int and 0 < claims['validUntilMs'] <= 2**63 - 1,
                502, AUTHORIZATION_INVALID)
        return claims

    def discovery_work(self, binding, state, name, bound):
        work_ref = state.get('workRef')
        require(hash_ref(work_ref), 503, EVIDENCE)
        work = {k: binding[k] for k in ('installation', 'analysisId', 'mandateRef', 'generation')}
        work.update(workRef=work_ref)
        create_hash = state.get('discoveryArgumentsHash')
        require(hash_ref(create_hash), 503, EVIDENCE)
        work['argumentsHash'] = create_hash
        if name == DISCOVERY_REQUEST:
            require(create_hash == bound['argumentsHash'], 409, 'ANALYSIS_DISCOVERY_KEY_CONFLICT')
        else:
            discovery = self.verify(state.get('discoveryBinding'), DISCOVERY_BINDING)
            require(discovery == dict(work, requestId=bound['requestId']),
                    403, 'ANALYSIS_DISCOVERY_REQUEST_NOT_BOUND')
        return work

    def dispatch(self, request, ctx, _):
        require(exact(request, 'mandateRef generation analysisId mandateBinding operation arguments attemptId correlationId'))
        name = request['operation']
        require(isinstance(name, str) and name in OPERATIONS, 403, 'ANALYSIS_OPERATION_NOT_ALLOWED')
        require(uuid_ref(request['attemptId'], v4=True) and uuid_ref(request['correlationId'], v4=True)
                and type(request['generation']) is int and hash_ref(request['analysisId']))
        ctx.update(operation=name, correlationId=request['correlationId'])
        binding = self.mandate_binding(request, ctx)
        op = OPERATIONS[name]
        args = request['arguments']
        bound = dict(operation=name, argumentsHash=arguments(name, args), attemptId=request['attemptId'])
        if 'requestId' in args:
            bound['requestId'] = args['requestId']
        state = self.state_proof(binding, 'dispatch', **bound)
        phase = state.value['phase']
        if phase in CLOSED_PHASES:
            state.check(self.clock, self.clock.checked())
            self.expire_at_owner(binding, binding['version'], phase, request['correlationId'])
            raise Denied(403, 'ANALYSIS_MANDATE_EXPIRED')
        require(state.value['policyEpoch'] == binding['policyEpoch'], 403, 'ANALYSIS_POLICY_EPOCH_CHANGED')
        work = self.discovery_work(binding, state.value, name, bound) if op.family == 'discovery' else None
        idem = request['attemptId']
        owner_arguments_hash = bound['argumentsHash']
        if name == DISCOVERY_REQUEST:
            # Namespace Semantic deduplication by admitted analysis/work.
            namespace = [work[k] for k in ('installation', 'analysisId', 'mandateRef', 'workRef')]
            idem = 'analysis-batch-v1:' + mac(self.config.binding_key, 'ouf-analysis-discovery-key-v1', b64(wire(namespace)))
            args = dict(args, idempotencyKey=idem)
            owner_arguments_hash = digest(wire(args))
        admission = {k: binding[k] for k in ('mandateRef', 'generation', 'analysisId', 'workload', 'policyEpoch')}
        admission.update(bound, argumentsHash=owner_arguments_hash,
                         expectedVersion=binding['version'], correlationId=request['correlationId'])
        state.check(self.clock, self.clock.checked())
        admitted = self.authorization.command('admit', admission)
        claims = self.admitted_claims(admitted, binding)
        body, headers = self.owner_call(op, args, idem, admission, claims)
        now = self.clock.checked()
        expires = min(admitted['expiresAtMs'], state.check(self.clock, now), claims['validUntilMs'])
        header, value = op.receipt(self.config.owner_keys[op.family], self.config.audience, claims, body, now, expires)
        headers[header] = value
        status, data, headers = self.semantic.send(op.path, body, headers, self.config.max_result_bytes)
        if name == DISCOVERY_REQUEST and 200 <= status < 300:
            try:
                result = parse(data)
            except Denied as exc:
                raise Denied(503, 'ANALYSIS_DISCOVERY_RECEIPT_UNVERIFIED') from exc
            require(isinstance(result, dict) and uuid_ref(result.get('requestId')), 503,
                    'ANALYSIS_DISCOVERY_RECEIPT_UNVERIFIED')
            headers = {**headers, DISCOVERY_BINDING_HEADER: self.sign(DISCOVERY_BINDING,
                                                                     dict(work, requestId=result['requestId']))}
        return status, data, headers

    def owner_call(self, op, args, idem, admission, claims):
        correlation, attempt = admission['correlationId'], admission['attemptId']
        body = wire(dict(
            GatewayBindingRef='capability://' + op.capability, CapabilityID=op.capability, Owner='semantic',
            OperationClass=op.operation_class, Arguments=args, AuthorizationDecisionRef=claims['decisionRef'],
            Identity=dict(ServicePrincipalID=claims['client'], PrincipalID=claims['subject'], TenantID=claims['tenant'],
                          ActorType=claims['actorType'], AuthenticationContextRef=claims['acr']),
            CorrelationID=correlation, IdempotencyKey=idem, AttemptID=attempt,
            RequestHash=admission['argumentsHash'], MaxResultBytes=self.config.max_result_bytes,
        ))
        require(len(body) <= MAX_REQUEST, 413, 'ANALYSIS_OWNER_REQUEST_TOO_LARGE')
        headers = {'Content-Type': 'application/json', 'X-Correlation-ID': correlation,
                   'Idempotency-Key': idem, 'X-Tool-Attempt-ID': attempt}
        return body, headers
