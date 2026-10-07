import copy
import unittest

from tests import test_semantic_shared_coordination as fixtures
from tools.semantic_provider_boot_coordination import prepare_docker_boot
from tools.semantic_provider_lease_coordination import CoordinationDenied


class BootTest(unittest.TestCase):
    setUp = fixtures.CoordinationTest.setUp

    def restore(self):
        self.assertTrue(self.held)
        self.assertFalse(self.record['leaseAuthorized'])
        self.assertFalse(self.current)
        self.events.append('restore')
        return {'restored': False, 'startAuthorized': False,
                'leaseStructureHash': 'c'*64, 'leaseStructureReconciliationRequired': False}

    def test_active_lease_revoked_before_restore_and_no_rearm(self):
        self.coord.refresh(); self.events.clear()
        result = prepare_docker_boot(self.coord, lambda: {'inet', 'bridge'}, self.restore)
        self.assertEqual(self.events, ['QUIESCING', 'revoke', 'QUIESCED', 'restore'])
        self.assertTrue(result['dockerPrestartStructuralGate'])
        self.assertFalse(result['providerRestartAuthorized'])
        with self.assertRaises(CoordinationDenied): self.coord.fresh_start()

    def test_missing_generation_disables_authority_before_restore(self):
        result = prepare_docker_boot(self.coord, set, self.restore)
        self.assertEqual(self.events, ['BLOCKED', 'restore'])
        self.assertTrue(result['leaseStructureReconciliationRequired'])
        self.assertEqual(self.record['state'], 'BLOCKED')
        self.assertFalse(self.record['leaseAuthorized'])

    def test_partial_tables_and_foreign_binding_preserved(self):
        previous = copy.deepcopy(self.record)
        with self.assertRaises(CoordinationDenied):
            prepare_docker_boot(self.coord, lambda: {'inet'}, self.restore)
        self.assertEqual(self.record, previous); self.assertFalse(self.events)
        self.record['transactionId'] = 'd'*64
        with self.assertRaises(CoordinationDenied): prepare_docker_boot(self.coord, set, self.restore)
        self.assertFalse(self.events)

    def test_failed_restore_never_retains_old_lease_authority(self):
        def fail(): raise RuntimeError('restore denied')
        with self.assertRaises(RuntimeError): prepare_docker_boot(self.coord, set, fail)
        self.assertEqual(self.record['state'], 'BLOCKED')
        self.assertFalse(self.record['leaseAuthorized'])

    def test_changed_handles_require_reconciliation_without_hash_adoption(self):
        def restored(): return {**self.restore(), 'restored': True, 'leaseStructureHash': 'd'*64}
        result = prepare_docker_boot(self.coord, lambda: {'inet', 'bridge'}, restored)
        self.assertTrue(result['leaseStructureReconciliationRequired'])
        self.assertEqual(self.coord.binding['leaseStructureHash'], 'c'*64)
        self.assertEqual(self.record['state'], 'BLOCKED')

    def test_foreign_handles_not_deleted(self):
        self.foreign = True
        with self.assertRaises(RuntimeError):
            prepare_docker_boot(self.coord, lambda: {'inet', 'bridge'}, self.restore)
        self.assertNotIn('restore', self.events)
        self.assertEqual(self.record['state'], 'QUIESCING')
        self.assertFalse(self.record['leaseAuthorized'])


if __name__ == '__main__': unittest.main()
