"""Shared-table install/recovery and synchronous OCI createRuntime gate.

The trusted driver supplies sealed profile, bounded native backend, common lock,
owned journal and Coordinator. No OCI bundle mutation, runtime registration,
container start, namespace creation or lease activation exists here.
"""
import copy
import hashlib
import json
import re

from tools.materialize_semantic_shared_faces import materialize


class PreexecDenied(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def rules(profile):
    value = materialize(profile['policy'])['nftRules']
    table = profile['policy']['tableName']
    for family in ('inet', 'bridge'):
        value = value.replace('table '+family+' '+table+' {', 'table '+family+' '+table+' {\n comment "ouf-preexec:'+profile['transactionId']+'"')
    return value


class Preexec:
    STATES = {'STAGED', 'INSTALLING', 'PROTECTED', 'REMOVING', 'ROLLED_BACK'}

    def __init__(self, profile, backend, coordinator, journal):
        fields = {'schema', 'transactionId', 'containerId', 'bundlePath', 'bundleHash',
                'namespacePath', 'namespaceInode', 'namespaceLinks', 'policy', 'expectedFootprint',
                'applicationStartAuthorized', 'infrastructureAuthorityComplete'}
        if profile.get('schema') == 'ouf.semantic-preexec-profile.v2': fields.add('namespaceOrigin')
        if set(profile) != fields or profile['schema'] not in ('ouf.semantic-preexec-profile.v1','ouf.semantic-preexec-profile.v2') \
                or any(not re.fullmatch('[0-9a-f]{64}', profile[k])
                       for k in ('transactionId', 'bundleHash', 'expectedFootprint')) \
                or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', profile['containerId']) \
                or type(profile['namespaceInode']) is not int or profile['namespaceInode'] <= 0 \
                or any(type(profile[k]) is not bool for k in ('applicationStartAuthorized', 'infrastructureAuthorityComplete')):
            raise ValueError('exact sealed preexec profile required')
        if profile['schema'] == 'ouf.semantic-preexec-profile.v2' and profile['namespaceOrigin'] not in ('PREPARED','OCI_CREATED'):
            raise ValueError('explicit namespace origin required')
        for k in ('bundlePath', 'namespacePath'):
            if not isinstance(profile[k], str) or not re.fullmatch('/[A-Za-z0-9_./-]+', profile[k]) \
                    or '..' in profile[k].split('/'):
                raise ValueError('explicit safe runtime path required')
        self.rules = rules(profile)
        if profile['policy']['tableName'] == coordinator.owner.configuration['tableName']:
            raise ValueError('distinct shared and lease tables required')
        links = profile['namespaceLinks']
        if not isinstance(links, list) or len(links) != len(profile['policy']['attachments']):
            raise ValueError('complete namespace attachment bindings required')
        for link, attachment in zip(links, profile['policy']['attachments']):
            if set(link) != {'interface', 'ifindex', 'hostIfindex'} \
                    or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', link['interface']) \
                    or type(link['ifindex']) is not int or link['ifindex'] <= 0 \
                    or type(link['hostIfindex']) is not int or link['hostIfindex'] != attachment['ifindex']:
                raise ValueError('exact namespace peer linkage required')
        if len({v['interface'] for v in links}) != len(links):
            raise ValueError('duplicate namespace interface binding')
        self.profile = copy.deepcopy(profile); self.config_hash = digest(self.profile)
        self.backend, self.coord, self.journal = backend, coordinator, journal

    def record(self):
        if digest(self.profile) != self.config_hash or self.rules != rules(self.profile):
            raise PreexecDenied('SEALED_PROFILE_DRIFT')
        value = self.journal.read()
        if not isinstance(value, dict) or set(value) != {'schema', 'transactionId', 'configurationHash',
                'state', 'sharedStructureHash', 'containerGeneration'} \
                or value['schema'] != 'ouf.semantic-preexec-journal.v1' \
                or value['transactionId'] != self.profile['transactionId'] \
                or value['configurationHash'] != self.config_hash or value['state'] not in self.STATES:
            raise PreexecDenied('FOREIGN_OR_INCOMPLETE_JOURNAL')
        hash_value = value['sharedStructureHash']
        generation = value['containerGeneration']
        if hash_value is not None and (not isinstance(hash_value, str)
                or not re.fullmatch('[0-9a-f]{64}', hash_value)):
            raise PreexecDenied('INVALID_STRUCTURE_RECEIPT')
        if generation is not None and (not isinstance(generation, dict)
                or set(generation) != {'pid', 'startTicks', 'namespaceInode'}
                or any(type(generation[k]) is not int or generation[k] <= 0 for k in generation)
                or generation['pid'] <= 1
                or generation['namespaceInode'] != self.profile['namespaceInode']):
            raise PreexecDenied('INVALID_GENERATION_RECEIPT')
        if (value['state'] == 'STAGED' and (hash_value is not None or generation is not None)) \
                or (value['state'] == 'INSTALLING' and generation is not None) \
                or (value['state'] == 'PROTECTED' and hash_value is None):
            raise PreexecDenied('INCONSISTENT_PHASE_RECEIPT')
        return copy.deepcopy(value)

    def publish(self, old, new):
        if self.record() != old: raise PreexecDenied('JOURNAL_DRIFT')
        self.journal.write(old, new)
        if self.record() != new: raise PreexecDenied('JOURNAL_PUBLICATION_UNPROVEN')

    def quiesced(self):
        # Called while already holding Coordinator's common lock: no recursive
        # flock acquisition and no automatic quiesce/refresh/authority changes.
        value = self.coord.journal()
        if value['state'] != 'QUIESCED' or value['leaseAuthorized'] or any(self.coord.sets()):
            raise PreexecDenied('LEASE_QUIESCENCE_REQUIRED')
        if self.coord.journal() != value: raise PreexecDenied('LEASE_JOURNAL_DRIFT')

    def verified(self, value, check_bindings=True):
        current = self.backend.tables()
        if current is None or self.backend.footprint(current) != self.profile['expectedFootprint'] \
                or self.backend.structure_hash(current) != value['sharedStructureHash']:
            raise PreexecDenied('SHARED_STRUCTURE_RECONCILIATION_REQUIRED')
        if check_bindings: self.backend.bindings(self.profile, None)

    def operate(self, mode):
        if mode not in ('plan', 'apply', 'verify', 'reconcile', 'rollback'):
            raise ValueError('explicit install mode required')
        with self.coord.hold_lock():
            self.quiesced(); value = self.record()
            if mode != 'rollback': self.backend.bindings(self.profile, None)
            current = self.backend.tables()
            if mode == 'plan':
                if value['state'] != 'STAGED' or current is not None:
                    raise PreexecDenied('INITIAL_OWNERSHIP_REQUIRED')
                return {'state': 'STAGED', 'hostRulesChanged': False, 'startAuthorized': False}
            if mode == 'verify':
                if value['state'] != 'PROTECTED': raise PreexecDenied('INCOMPLETE_INSTALL')
                self.verified(value)
            elif mode == 'rollback':
                if value['state'] not in ('INSTALLING', 'PROTECTED', 'REMOVING'):
                    raise PreexecDenied('OWNED_ROLLBACK_REQUIRED')
                if value['containerGeneration'] is not None and self.backend.generation_alive(value['containerGeneration']) is not False:
                    raise PreexecDenied('LIVE_GENERATION_ROLLBACK_DENIED')
                if current is not None:
                    if value['sharedStructureHash'] is None:
                        raise PreexecDenied('UNCOMMITTED_TABLES_REQUIRE_RECONCILE')
                    self.verified(value, check_bindings=False)
                pending = {**value, 'state': 'REMOVING'}; self.publish(value, pending)
                if current is not None: self.backend.remove()
                if self.backend.tables() is not None: raise PreexecDenied('REMOVAL_UNPROVEN')
                value = {**pending, 'state': 'ROLLED_BACK'}; self.publish(pending, value)
            else:
                if mode == 'apply' and (value['state'] != 'STAGED' or current is not None):
                    raise PreexecDenied('DO_NOT_REPLAY_APPLY')
                if mode == 'reconcile' and value['state'] not in ('INSTALLING', 'PROTECTED'):
                    raise PreexecDenied('EXPLICIT_RECOVERY_PHASE_REQUIRED')
                if value['containerGeneration'] is not None and self.backend.generation_alive(value['containerGeneration']) is not False:
                    raise PreexecDenied('LIVE_GENERATION_RECONCILE_DENIED')
                if not self.profile['infrastructureAuthorityComplete']:
                    raise PreexecDenied('INFRASTRUCTURE_AUTHORITY_REQUIRED')
                if current is not None:
                    # Recovery after atomic creation but before hash publication
                    # requires an explicit reconcile and the sealed footprint,
                    # including the unique transaction comment on both tables.
                    if mode == 'reconcile' and value['state'] == 'INSTALLING' and value['sharedStructureHash'] is None:
                        if self.backend.footprint(current) != self.profile['expectedFootprint']:
                            raise PreexecDenied('SEALED_TAGGED_TEMPLATE_REQUIRED')
                        owned = {**value, 'sharedStructureHash': self.backend.structure_hash(current)}
                        self.publish(value, owned); value = owned
                    self.verified(value)
                pending = {**value, 'state': 'INSTALLING', 'containerGeneration': None}
                self.publish(value, pending)
                if current is None:
                    self.backend.create(self.rules)
                    current = self.backend.tables()
                    if current is None or self.backend.footprint(current) != self.profile['expectedFootprint']:
                        raise PreexecDenied('NATIVE_READBACK_REQUIRED')
                    # Persist the observed generation before declaring PROTECTED.
                    owned = {**pending, 'sharedStructureHash': self.backend.structure_hash(current)}
                    self.publish(pending, owned); pending = owned
                value = {**pending, 'state': 'PROTECTED'}; self.publish(pending, value)
                self.verified(value)
            return {'state': value['state'], 'hostRulesChanged': mode != 'verify', 'startAuthorized': False}

    def before_process(self, state, starter=None):
        # Runtime failure must prevent OCI create/start. This is a synchronous
        # createRuntime hook, not a post-start event callback.
        if not isinstance(state, dict) or state.get('id') != self.profile['containerId'] \
                or state.get('bundle') != self.profile['bundlePath'] \
                or state.get('status') not in ('creating', 'created') \
                or type(state.get('pid')) is not int or not 1 < state['pid'] < 2147483647:
            raise PreexecDenied('OCI_RUNTIME_STATE_UNPROVEN')
        if not self.profile['applicationStartAuthorized'] or not self.profile['infrastructureAuthorityComplete']:
            raise PreexecDenied('APPLICATION_START_NOT_AUTHORIZED')
        with self.coord.hold_lock():
            self.quiesced(); value = self.record()
            if value['state'] != 'PROTECTED': raise PreexecDenied('PREEXEC_PROTECTION_INCOMPLETE')
            self.verified(value)
            generation = self.backend.bindings(self.profile, state)
            if not isinstance(generation, dict) or set(generation) != {'pid', 'startTicks', 'namespaceInode'} \
                    or any(type(generation[k]) is not int or generation[k] <= 0 for k in generation) \
                    or generation['pid'] != state['pid'] or generation['namespaceInode'] != self.profile['namespaceInode']:
                raise PreexecDenied('OCI_GENERATION_BINDING_UNPROVEN')
            if value['containerGeneration'] not in (None, generation):
                raise PreexecDenied('OCI_GENERATION_RECONCILIATION_REQUIRED')
            self.publish(value, {**value, 'containerGeneration': generation})
            self.verified(value)
            if self.backend.bindings(self.profile, state) != generation:
                raise PreexecDenied('OCI_GENERATION_CHANGED')
            if starter is not None:
                if state['status'] != 'created':
                    raise PreexecDenied('CREATED_PROCESS_REQUIRED_FOR_START')
                # The trusted v2 driver supplies the runtime starter. Keep the
                # common lock through the FIFO release, not only the readback.
                starter()
            return {'protectedBeforeProcess': True, 'leaseActivated': False, 'notReleaseAcceptance': True}
