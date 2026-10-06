import copy
import unittest
from unittest.mock import patch

from tools.semantic_provider_lease_owner import LeaseOwner, LeaseDenied
from tests.test_southbound_kernel import configuration


class Backend:
    def __init__(self):
        self.writes = []; self.current = {}; self.ownership = True; self.after_apply = lambda: None
    def verify_ownership(self, config):
        if not self.ownership: raise RuntimeError('unknown owner')
    def apply(self, transaction, deadline):
        self.writes.append(transaction)
        self.current = {(f, 0): {'10.90.0.2': 1} if 'add element' in transaction else {}
                        for f in ('inet', 'bridge')}
        self.after_apply()
    def read_sets(self, config): return self.current


class OwnerTest(unittest.TestCase):
    def setUp(self):
        self.now = 100; self.backend = Backend()
        self.owner = LeaseOwner(configuration(), {'resolvers': ['127.0.0.1'], 'resolverPort': 53,
            'timeoutSeconds': 2, 'maxLeaseSeconds': 20, 'applyBudgetSeconds': 2},
            self.backend, clock=lambda: self.now)
        self.result = {'usableAddresses': ['10.90.0.2'], 'remainingLeaseSecondsAtObservation': 10}
    def test_every_cycle_queries_again_and_reads_both_sets(self):
        with patch('tools.semantic_provider_lease_owner.dns.observe', return_value=self.result) as observe:
            self.assertTrue(self.owner.refresh()['freshDnsQueried']); self.owner.refresh()
            self.assertEqual(observe.call_count, 2)
        self.assertEqual(len(self.backend.writes), 2)
    def test_failed_dns_revokes_both_sets_without_refresh_retry(self):
        with patch('tools.semantic_provider_lease_owner.dns.observe', side_effect=OSError('failed')):
            with self.assertRaisesRegex(LeaseDenied, 'SETS_REVOKED'): self.owner.refresh()
        self.assertEqual(len(self.backend.writes), 1)
        self.assertNotIn('add element', self.backend.writes[0])
    def test_delay_before_apply_exhausts_dns_deadline(self):
        def delayed(*args): self.now += 12; return self.result
        with patch('tools.semantic_provider_lease_owner.dns.observe', side_effect=delayed):
            with self.assertRaisesRegex(LeaseDenied, 'SETS_REVOKED'): self.owner.refresh()
        self.assertNotIn('add element', self.backend.writes[0])
    def test_late_apply_revokes_instead_of_retrying_relative_ttl(self):
        def delayed(): self.now += 3
        self.backend.after_apply = delayed
        with patch('tools.semantic_provider_lease_owner.dns.observe', return_value=self.result):
            with self.assertRaisesRegex(LeaseDenied, 'SETS_REVOKED'): self.owner.refresh()
        self.assertEqual(len(self.backend.writes), 2)
        self.assertIn('add element', self.backend.writes[0]); self.assertNotIn('add element', self.backend.writes[1])
    def test_kernel_address_or_ttl_extension_is_revoked(self):
        for bad in ({'10.90.0.3': 1}, {'10.90.0.2': 1000}, {'10.90.0.2': float('nan')}):
            self.backend.after_apply = lambda: self.backend.current.update({('bridge', 0): bad}) \
                if 'add element' in self.backend.writes[-1] else None
            with patch('tools.semantic_provider_lease_owner.dns.observe', return_value=self.result):
                with self.assertRaisesRegex(LeaseDenied, 'SETS_REVOKED'): self.owner.refresh()
            self.assertFalse(any(self.backend.current.values()))
    def test_unknown_ownership_never_writes_and_failed_revocation_never_passes(self):
        self.backend.ownership = False
        with self.assertRaises(RuntimeError): self.owner.refresh()
        self.assertEqual(self.backend.writes, [])
        self.backend.ownership = True
        def changed(): self.backend.ownership = False
        self.backend.after_apply = changed
        with patch('tools.semantic_provider_lease_owner.dns.observe', return_value=self.result):
            with self.assertRaisesRegex(LeaseDenied, 'REVOCATION_UNPROVEN'): self.owner.refresh()
        self.assertEqual(len(self.backend.writes), 1)
