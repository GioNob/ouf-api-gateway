"""Per-candidate durable evidence consumption using the existing guard lock.

The installer provisions the journal. No reset, implicit reconciliation, issuer
or runtime operation exists here. consume_locked is called only from the sealed
driver inside Preexec's common-lock critical section.
"""
import copy
import time

from tools.semantic_provider_preexec import PreexecDenied, digest
from tools.semantic_provider_deployment_protocol import validate_intent, validate_final, hashed, identity


def require(value, reason):
    if not value: raise PreexecDenied(reason)


def generation(value):
    require(type(value) is dict and set(value) == {'pid', 'startTicks', 'namespaceInode'}
            and all(type(v) is int and v > 0 for v in value.values()) and value['pid'] > 1,
            'CONSUMPTION_GENERATION_REQUIRED')
    return copy.deepcopy(value)


class Consumption:
    STATES = {'STAGED', 'CREATING', 'CREATED', 'READY', 'STARTING', 'STARTED'}

    def __init__(self, binding, journal, hold_lock):
        require(type(binding) is dict and set(binding) == {'installationRef', 'entityRef',
                'containerId', 'transactionId', 'intentHash', 'configurationHash'}
                and all(identity(binding[k]) for k in ('installationRef', 'entityRef'))
                and all(hashed(binding[k]) for k in ('containerId', 'transactionId', 'intentHash', 'configurationHash')),
                'EXACT_CONSUMPTION_BINDING_REQUIRED')
        self.binding = copy.deepcopy(binding)
        self.journal, self.hold_lock = journal, hold_lock

    def record(self):
        value = self.journal.read()
        require(type(value) is dict and set(value) == {'schema', *self.binding, 'state',
                'bundleHash', 'generation', 'evidenceHash', 'approvalHash', 'driverHash'}
                and value['schema'] == 'ouf.semantic-deployment-consumption.v1'
                and all(value[k] == v for k, v in self.binding.items())
                and value['state'] in self.STATES, 'FOREIGN_CONSUMPTION_JOURNAL')
        fields = ('bundleHash', 'generation', 'evidenceHash', 'approvalHash', 'driverHash')
        if value['state'] in ('STAGED', 'CREATING'):
            require(all(value[k] is None for k in fields), 'INCOMPLETE_CONSUMPTION_PHASE')
        else:
            require(hashed(value['bundleHash']), 'CREATED_BUNDLE_HASH_REQUIRED')
            generation(value['generation'])
            if value['state'] == 'CREATED':
                require(all(value[k] is None for k in fields[2:]), 'INCOMPLETE_CONSUMPTION_PHASE')
            else:
                require(hashed(value['evidenceHash']) and hashed(value['approvalHash'])
                        and (value['driverHash'] is None or hashed(value['driverHash'])),
                        'FINAL_CONSUMPTION_EVIDENCE_REQUIRED')
                if value['state'] in ('STARTING', 'STARTED'):
                    require(hashed(value['driverHash']), 'SEALED_CONSUMPTION_DRIVER_REQUIRED')
        return copy.deepcopy(value)

    def publish(self, old, **changes):
        require(self.record() == old, 'CONSUMPTION_CHANGED_UNDER_LOCK')
        value = {**old, **copy.deepcopy(changes)}
        self.journal.write(old, value)
        require(self.record() == value, 'CONSUMPTION_PUBLICATION_UNPROVEN')
        return copy.deepcopy(value)

    def authorize_create(self, intent_raw, authorities, authenticate, clock=time.time):
        import hashlib
        with self.hold_lock():
            old = self.record()
            require(old['state'] == 'STAGED', 'DO_NOT_REPLAY_DEPLOYMENT_CREATE')
            intent = validate_intent(intent_raw, authorities, authenticate, clock)
            require(hashlib.sha256(intent_raw).hexdigest() == self.binding['intentHash']
                    and all(intent[k] == self.binding[k] for k in
                            ('installationRef', 'entityRef', 'containerId', 'transactionId')),
                    'CONSUMPTION_INTENT_SCOPE_DRIFT')
            return self.publish(old, state='CREATING')

    def created(self, bundle_hash, live_generation):
        with self.hold_lock():
            old = self.record()
            require(old['state'] == 'CREATING' and hashed(bundle_hash), 'OWNED_CREATION_REQUIRED')
            return self.publish(old, state='CREATED', bundleHash=bundle_hash,
                                generation=generation(live_generation))

    def ready(self, intent_raw, attestation_raw, approval_raw, authorities, authenticate, clock=time.time):
        with self.hold_lock():
            return self.ready_locked(intent_raw, attestation_raw, approval_raw, authorities, authenticate, clock)

    def ready_locked(self, intent_raw, attestation_raw, approval_raw, authorities, authenticate, clock=time.time):
        """Internal composition point: caller already owns the common lock."""
        old = self.record()
        require(old['state'] == 'CREATED', 'DO_NOT_REPLAY_FINAL_EVIDENCE')
        evidence = validate_final(intent_raw, attestation_raw, approval_raw, authorities, authenticate, clock)
        require(evidence['intentHash'] == self.binding['intentHash']
                and all(evidence['scope'][k] == self.binding[k] for k in
                        ('installationRef', 'entityRef', 'containerId', 'transactionId'))
                and evidence['scope']['applicationHash'] == old['bundleHash']
                and evidence['generation'] == old['generation'], 'CREATED_EVIDENCE_GENERATION_DRIFT')
        self.publish(old, state='READY', evidenceHash=digest(evidence), approvalHash=evidence['approvalHash'])
        return evidence

    def seal_driver(self, driver_hash):
        with self.hold_lock():
            return self.seal_driver_locked(driver_hash)

    def seal_driver_locked(self, driver_hash):
        """Internal composition point: caller already owns the common lock."""
        old = self.record()
        require(old['state'] == 'READY' and old['driverHash'] is None and hashed(driver_hash),
                'DO_NOT_REBIND_CONSUMPTION_DRIVER')
        return self.publish(old, driverHash=driver_hash)

    def consume_locked(self, evidence_hash, driver_hash, live_generation, reauthorize, starter):
        """Caller already holds the common lock; persist before FIFO release.

        Any failure after STARTING leaves that durable state for explicit recovery.
        Success records a completed native start attempt, not application readiness.
        """
        old = self.record()
        require(old['state'] == 'READY', 'DO_NOT_REPLAY_DEPLOYMENT_START')
        require(old['evidenceHash'] == evidence_hash and old['driverHash'] == driver_hash
                and hashed(driver_hash) and generation(live_generation) == old['generation'],
                'SEALED_START_EVIDENCE_DRIFT')
        require(callable(reauthorize) and callable(starter), 'EXPLICIT_GUARDED_START_REQUIRED')
        reauthorize()
        pending = self.publish(old, state='STARTING')
        reauthorize()
        require(self.record() == pending, 'CONSUMPTION_CHANGED_BEFORE_START')
        starter()
        self.publish(pending, state='STARTED')
