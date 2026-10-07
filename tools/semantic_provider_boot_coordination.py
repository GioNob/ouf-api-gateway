"""Compose coordinated revocation with the sealed empty-only boot restorer.

The trusted installer supplies membership and restoration callbacks bound to
the ORIGINAL sealed boot configuration. This is a protocol core, not a service
installer. It never changes configuration hashes or grants provider authority.
"""
from tools.semantic_provider_lease_coordination import CoordinationDenied


def prepare_docker_boot(coordinator, membership, restore_empty):
    """Hold the original lock across revocation, restore and empty readback.

    Missing tables mean a lost kernel generation: revoke the journal's authority
    before restoration, keep it BLOCKED and require explicit reconciliation.
    The old restorer proves the empty footprint and preserves unrelated rules.
    A provider failure does not justify deleting partial/foreign tables.
    """
    with coordinator.hold_lock():
        previous = coordinator.journal()
        present = membership()
        if not isinstance(present, set) or present not in (set(), {'inet', 'bridge'}):
            raise CoordinationDenied('PARTIAL_OR_FOREIGN_BOOT_TABLES')
        if not present or previous['state'] == 'BLOCKED':
            blocked = {**previous, 'state': 'BLOCKED', 'leaseAuthorized': False,
                       'leaseAddresses': [[] for _ in coordinator.configuration['providerFlows']]}
            coordinator.publish(previous, blocked)
            # This callback MUST refuse partial, foreign or nonempty tables.
            # No cached address or relative TTL is restored.
            result = restore_empty()
            if coordinator.journal() != blocked:
                raise CoordinationDenied('BOOT_JOURNAL_CHANGED')
            reconciliation = True
        else:
            # The backend verifies the current sealed handles before revoking.
            pending = {**previous, 'state': 'QUIESCING', 'leaseAuthorized': False}
            coordinator.publish(previous, pending)
            coordinator.owner.revoke()
            if any(coordinator.sets()):
                raise CoordinationDenied('BOOT_QUIESCENCE_UNPROVEN')
            quiesced = {**pending, 'state': 'QUIESCED',
                        'leaseAddresses': [[] for _ in coordinator.configuration['providerFlows']]}
            coordinator.publish(pending, quiesced)
            result = restore_empty()
            if coordinator.journal() != quiesced:
                raise CoordinationDenied('BOOT_JOURNAL_CHANGED')
            reconciliation = False
        if not isinstance(result, dict) or result.get('startAuthorized') is not False \
                or type(result.get('restored')) is not bool \
                or type(result.get('leaseStructureReconciliationRequired')) is not bool \
                or not isinstance(result.get('leaseStructureHash'), str):
            raise CoordinationDenied('SEALED_EMPTY_RESTORE_UNPROVEN')
        reconciliation = reconciliation or result['restored'] \
            or result['leaseStructureReconciliationRequired'] \
            or result['leaseStructureHash'] != coordinator.binding['leaseStructureHash']
        if reconciliation and coordinator.journal()['state'] != 'BLOCKED':
            value = coordinator.journal()
            coordinator.publish(value, {**value, 'state': 'BLOCKED', 'leaseAuthorized': False})
        return {'dockerPrestartStructuralGate': True, 'startAuthorized': False,
                'leaseAuthorized': False, 'providerRestartAuthorized': False,
                'leaseStructureReconciliationRequired': reconciliation,
                'tablesRestored': result['restored'], 'notReleaseAcceptance': True}
