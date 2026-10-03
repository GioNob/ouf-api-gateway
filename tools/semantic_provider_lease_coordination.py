"""Guard/lease protocol core, using an existing common lock and sealed journal.

The installer supplies trusted journal readers/atomic writers, immutable binding
and a verified owner/backend. This module never installs services, creates tables,
rebinds a structure hash or grants startup authority. Refresh holds the common
lock across fresh DNS, atomic apply and readback; no cooperating restore can race.
"""
import copy
import ipaddress
import math
import re


class CoordinationDenied(RuntimeError):
    pass


class Coordinator:
    STATES = {'LEASE_READY', 'LEASE_UPDATING', 'QUIESCING', 'QUIESCED', 'BLOCKED'}

    def __init__(self, owner, binding, hold_lock, read_journal, write_journal):
        if set(binding) != {'transactionId', 'configurationHash', 'leaseStructureHash'} \
                or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v)
                       for v in binding.values()) \
                or owner.backend.expected != binding['leaseStructureHash']:
            raise ValueError('sealed installation binding required')
        self.owner, self.binding = owner, copy.deepcopy(binding)
        self.hold_lock, self.read, self.write = hold_lock, read_journal, write_journal

    def journal(self):
        value = self.read()
        if not isinstance(value, dict) or set(value) != {'schema', *self.binding, 'state',
                'leaseAuthorized', 'startAuthorized', 'leaseAddresses'} \
                or value['schema'] != 'ouf.semantic-lease-coordination.v1' \
                or any(value[k] != v for k, v in self.binding.items()) \
                or value['state'] not in self.STATES or type(value['leaseAuthorized']) is not bool \
                or value['startAuthorized'] is not False:
            raise CoordinationDenied('JOURNAL_OR_AUTHORITY_BINDING_UNPROVEN')
        addresses = value['leaseAddresses']; flows = self.owner.configuration['providerFlows']
        if not isinstance(addresses, list) or len(addresses) != len(flows):
            raise CoordinationDenied('LEASE_RECEIPT_UNPROVEN')
        for row, flow in zip(addresses, flows):
            if not isinstance(row, list) or len(row) > 32 or any(not isinstance(v, str) for v in row) \
                    or len(set(row)) != len(row):
                raise CoordinationDenied('LEASE_RECEIPT_UNPROVEN')
            for text in row:
                address = ipaddress.ip_address(text)
                if str(address) != text or address.version != ipaddress.ip_address(flow['source']).version \
                        or address.is_loopback or address.is_link_local or address.is_multicast \
                        or address.is_unspecified or address.is_reserved \
                        or (not address.is_global and text not in flow['allowedPrivateAddresses']):
                    raise CoordinationDenied('LEASE_RECEIPT_ADDRESS_UNPROVEN')
        return copy.deepcopy(value)

    def sets(self):
        self.owner.backend.verify_ownership(self.owner.configuration)
        values = self.owner.backend.read_sets(self.owner.configuration)
        flows = self.owner.configuration['providerFlows']
        if set(values) != {(family, i) for family in ('inet', 'bridge') for i in range(len(flows))}:
            raise CoordinationDenied('LEASE_SET_BINDING_UNPROVEN')
        for i, flow in enumerate(flows):
            left, right = values['inet', i], values['bridge', i]
            if set(left) != set(right) or len(left) > 32:
                raise CoordinationDenied('LEASE_FAMILY_MEMBERSHIP_UNPROVEN')
            for text in left:
                address = ipaddress.ip_address(text)
                if str(address) != text or address.version != ipaddress.ip_address(flow['source']).version \
                        or address.is_loopback or address.is_link_local or address.is_multicast \
                        or address.is_unspecified or address.is_reserved \
                        or (not address.is_global and text not in flow['allowedPrivateAddresses']):
                    raise CoordinationDenied('LEASE_SET_ADDRESS_UNPROVEN')
            for ttl in (*left.values(), *right.values()):
                if type(ttl) not in (int, float) or not math.isfinite(ttl) or not 0 < ttl <= flow['leaseSeconds']:
                    raise CoordinationDenied('LEASE_FINITE_EXPIRY_UNPROVEN')
        self.owner.backend.verify_ownership(self.owner.configuration)
        return [sorted(values['inet', i]) for i in range(len(flows))]

    def publish(self, previous, value):
        # The trusted writer must compare-and-replace/fsync under the same lock.
        # Refuse an external journal mutation before asking it to publish.
        if self.journal() != previous:
            raise CoordinationDenied('JOURNAL_CHANGED_DURING_OPERATION')
        self.write(copy.deepcopy(previous), copy.deepcopy(value))
        if self.journal() != value:
            raise CoordinationDenied('JOURNAL_PUBLICATION_UNPROVEN')

    def guard(self):
        with self.hold_lock():
            value = self.journal(); actual = self.sets()
            if value['state'] == 'QUIESCED':
                if any(actual): raise CoordinationDenied('QUIESCENCE_UNPROVEN')
            elif value['state'] == 'LEASE_READY' and value['leaseAuthorized']:
                if any(not set(row).issubset(set(approved))
                       for row, approved in zip(actual, value['leaseAddresses'])):
                    raise CoordinationDenied('LEASE_MEMBERSHIP_RECEIPT_DRIFT')
            else:
                raise CoordinationDenied('LIFECYCLE_INCOMPLETE')
            if self.journal() != value: raise CoordinationDenied('JOURNAL_CHANGED_DURING_GUARD')
            return {'state': value['state'], 'tablesRecreated': False, 'startAuthorized': False,
                    'dockerPrestartStructuralGate': value['state'] == 'QUIESCED',
                    'notReleaseAcceptance': True}

    def refresh(self):
        with self.hold_lock():
            value = self.journal()
            if value['state'] != 'LEASE_READY' or not value['leaseAuthorized']:
                raise CoordinationDenied('LEASE_REFRESH_NOT_AUTHORIZED')
            actual = self.sets()
            if any(not set(row).issubset(set(approved))
                   for row, approved in zip(actual, value['leaseAddresses'])):
                raise CoordinationDenied('LEASE_MEMBERSHIP_RECEIPT_DRIFT')
            pending = {**value, 'state': 'LEASE_UPDATING'}
            self.publish(value, pending)
            try:
                result = self.owner.refresh()  # fresh DNS; no cached observation replay
                actual = self.sets()
                ready = {**pending, 'state': 'LEASE_READY', 'leaseAddresses': actual}
                self.publish(pending, ready)
                return {**result, 'commonLockHeld': True, 'startAuthorized': False}
            except Exception:
                # Revoke only through the ownership-checking backend. Even if
                # this fails, the gate remains incomplete and finite TTL denies.
                try: self.owner.revoke()
                except Exception: pass  # incomplete gate + finite expiry remain
                try:
                    if self.journal() == pending:
                        self.publish(pending, {**pending, 'state': 'BLOCKED', 'leaseAuthorized': False})
                except Exception: pass  # never overwrite an unknown journal
                raise CoordinationDenied('REFRESH_FAILED_GATE_BLOCKED') from None

    def quiesce(self):
        with self.hold_lock():
            value = self.journal()
            # Persist refusal of refresh/pre-start before the first revocation.
            pending = {**value, 'state': 'QUIESCING', 'leaseAuthorized': False}
            self.publish(value, pending)
            self.owner.revoke()
            if any(self.sets()): raise CoordinationDenied('QUIESCENCE_READBACK_FAILED')
            complete = {**pending, 'state': 'QUIESCED',
                        'leaseAddresses': [[] for _ in self.owner.configuration['providerFlows']]}
            self.publish(pending, complete)
            return {'state': 'QUIESCED', 'setsRevoked': True, 'startAuthorized': False}
