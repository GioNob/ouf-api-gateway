import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools.materialize_semantic_shared_faces import materialize
from tools.semantic_provider_lease_coordination import Coordinator, CoordinationDenied, PrivateJournal, hold_common_lock


def policy():
    return {'schema': 'ouf.semantic-shared-faces.v1', 'tableName': 'shared_owned',
        'attachments': [{'workloadRef': 'southbound', 'interface': 'vethwork', 'ifindex': 7,
            'bridge': 'shared', 'mac': '02:00:00:00:00:02', 'ipv4': '10.77.0.2', 'bindingRef': 'sealed-port'}],
        'flows': [{'purpose': 'WORKLOAD_GATEWAY', 'authorityRef': 'approved-workload',
            'source': '10.77.0.3', 'destination': '10.77.0.2', 'protocol': 'tcp', 'port': 9443,
            'peerIngress': {'kind': 'BRIDGE_PORT', 'ifindex': 8}}]}


class SharedCompilerTest(unittest.TestCase):
    def test_no_whole_shared_bridge_dispatch_and_explicit_ingress_port(self):
        rules = materialize(policy())['nftRules']
        self.assertIn('meta iif 7 jump from_0', rules)
        self.assertIn('meta iif 8 ip saddr 10.77.0.3', rules)
        self.assertIn('meta ibrname != "shared" counter drop', rules)
        self.assertNotIn('meta ibrname "shared" jump', rules)
        self.assertNotIn('flush ruleset', rules)

    def test_ambiguous_or_injected_bindings_and_unapproved_flow_types_rejected(self):
        for key, bad in [('ifindex', True), ('mac', 'ff:ff:ff:ff:ff:ff'),
                         ('interface', 'veth\naccept'), ('ipv4', '::1'), ('bindingRef', '')]:
            value = policy(); value['attachments'][0][key] = bad
            with self.assertRaises(ValueError): materialize(value)
        for key, bad in [('purpose', 'PROVIDER'), ('authorityRef', ''), ('protocol', 'udp'),
                         ('peerIngress', {'kind': 'HOST', 'ifindex': 8}), ('port', 0)]:
            value = policy(); value['flows'][0][key] = bad
            with self.assertRaises(ValueError): materialize(value)
        value = policy(); value['attachments'] *= 2
        with self.assertRaises(ValueError): materialize(value)


class CoordinationTest(unittest.TestCase):
    def setUp(self):
        self.binding = {'transactionId': 'a'*64, 'configurationHash': 'b'*64, 'leaseStructureHash': 'c'*64}
        self.record = {'schema': 'ouf.semantic-lease-coordination.v1', **self.binding,
            'state': 'LEASE_READY', 'leaseAuthorized': True, 'startAuthorized': False, 'leaseAddresses': [[]]}
        self.current = []; self.held = False; self.events = []; self.foreign = False
        test = self
        class Backend:
            expected = 'c'*64
            def verify_ownership(self, config):
                test.assertTrue(test.held)
                if test.foreign: raise RuntimeError('foreign table')
            def read_sets(self, config):
                return {(family, 0): {address: 5 for address in test.current} for family in ('inet', 'bridge')}
        class Owner:
            backend = Backend()
            profile = {'resolvers': ['192.0.2.53']}
            configuration = {'providerFlows': [{'source': '10.77.0.2', 'leaseSeconds': 30,
                                               'allowedPrivateAddresses': ['10.78.0.2']}]}
            def refresh(self):
                test.assertTrue(test.held); test.assertEqual(test.record['state'], 'LEASE_UPDATING')
                test.events.append('fresh'); test.current = ['10.78.0.2']
                return {'freshDnsQueried': True, 'bothFamiliesReadBack': True}
            def revoke(self):
                test.assertTrue(test.held); test.events.append('revoke')
                self.backend.verify_ownership(self.configuration); test.current = []
        @contextmanager
        def hold():
            if self.held: raise RuntimeError('common lock busy')
            self.held = True
            try: yield
            finally: self.held = False
        def write(previous, value):
            self.assertTrue(self.held); self.assertEqual(previous, self.record)
            self.record = copy.deepcopy(value); self.events.append(value['state'])
        self.owner = Owner(); self.hold = hold
        self.coord = Coordinator(self.owner, self.binding, hold, lambda: copy.deepcopy(self.record), write)

    def test_refresh_guard_quiesce_and_refresh_denied_without_reactivation(self):
        result = self.coord.refresh(); self.assertTrue(result['freshDnsQueried'])
        self.assertEqual(self.events, ['LEASE_UPDATING', 'fresh', 'LEASE_READY'])
        self.assertFalse(self.coord.guard()['dockerPrestartStructuralGate'])
        self.coord.quiesce(); self.assertFalse(self.current)
        self.assertEqual(self.events[-3:], ['QUIESCING', 'revoke', 'QUIESCED'])
        self.assertTrue(self.coord.guard()['dockerPrestartStructuralGate'])
        self.assertFalse(self.coord.guard()['startAuthorized'])
        with self.assertRaises(CoordinationDenied): self.coord.refresh()

    def test_incomplete_transition_and_old_empty_only_journal_never_enable_owner(self):
        for state in ('BLOCKED', 'LEASE_UPDATING', 'QUIESCING', 'QUIESCED', 'RUNTIME_EMPTY'):
            self.record['state'] = state
            with self.assertRaises(CoordinationDenied): self.coord.refresh()
        self.assertEqual(self.events, [])
        self.record['schema'] = 'ouf.semantic-runtime-transition.v1'
        with self.assertRaises(CoordinationDenied): self.coord.guard()

    def test_foreign_handle_and_unreceipted_membership_never_adopted(self):
        self.foreign = True
        with self.assertRaises(RuntimeError): self.coord.quiesce()
        self.assertEqual(self.record['state'], 'QUIESCING')
        self.assertFalse(self.record['leaseAuthorized'])
        self.foreign = False; self.record['state'] = 'LEASE_READY'; self.record['leaseAuthorized'] = True
        self.current = ['10.78.0.2']
        with self.assertRaises(CoordinationDenied): self.coord.refresh()
        with self.assertRaises(CoordinationDenied): self.coord.guard()
        self.assertEqual(self.current, ['10.78.0.2'])

    def test_failed_refresh_or_revoke_preserves_incomplete_gate_and_no_recreation(self):
        def failed(): self.current = ['10.78.0.2']; raise RuntimeError('DNS/readback failed')
        self.owner.refresh = failed
        with self.assertRaises(CoordinationDenied): self.coord.refresh()
        self.assertEqual(self.record['state'], 'BLOCKED'); self.assertFalse(self.current)
        self.record['state'] = 'LEASE_READY'; self.record['leaseAuthorized'] = True
        def failed_revoke(): raise RuntimeError('revocation failed')
        self.owner.revoke = failed_revoke
        with self.assertRaises(RuntimeError): self.coord.quiesce()
        self.assertEqual(self.record['state'], 'QUIESCING')
        with self.assertRaises(CoordinationDenied): self.coord.guard()

    def test_guard_contention_denies_and_start_authority_cannot_be_smuggled(self):
        with self.hold():
            with self.assertRaises(RuntimeError): self.coord.guard()
            with self.assertRaises(RuntimeError): self.coord.refresh()
        self.record['startAuthorized'] = True
        with self.assertRaises(CoordinationDenied): self.coord.refresh()
        self.assertEqual(self.events, [])

    def test_configuration_dns_and_expected_handle_hash_drift_deny_before_dns(self):
        original = copy.deepcopy(self.owner.configuration)
        self.owner.configuration['providerFlows'][0]['leaseSeconds'] = 3600
        with self.assertRaises(CoordinationDenied): self.coord.refresh()
        self.owner.configuration = original
        self.owner.profile['resolvers'] = ['198.51.100.53']
        with self.assertRaises(CoordinationDenied): self.coord.refresh()
        self.owner.profile['resolvers'] = ['192.0.2.53']
        self.owner.backend.expected = 'd'*64
        with self.assertRaises(CoordinationDenied): self.coord.guard()
        self.assertEqual(self.events, [])


@unittest.skipUnless(os.geteuid() == 0, 'root private journal fixture')
class PrivateJournalTest(unittest.TestCase):
    def test_atomic_owned_write_duplicate_foreign_mode_and_lock_inode_checks(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT', str(Path.cwd()))) as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700)
            path = root/'journal.json'; path.write_text('{"state":"LEASE_READY"}'); path.chmod(0o600)
            journal = PrivateJournal(path); original = journal.read()
            journal.write(original, {'state': 'QUIESCING'}); self.assertEqual(journal.read()['state'], 'QUIESCING')
            with self.assertRaises(CoordinationDenied): journal.write(original, {'state': 'FOREIGN'})
            path.write_text('{"state":1,"state":2}')
            with self.assertRaises(CoordinationDenied): journal.read()
            path.write_text('{}'); path.chmod(0o644)
            with self.assertRaises(CoordinationDenied): journal.read()
            lock = root/'common.lock'; lock.touch(mode=0o600); inode = lock.stat().st_ino
            with hold_common_lock(lock):
                with self.assertRaises(BlockingIOError):
                    with hold_common_lock(lock): pass
            self.assertEqual(lock.stat().st_ino, inode)
            alias = root/'alias'; os.link(lock, alias)
            with self.assertRaises(CoordinationDenied):
                with hold_common_lock(lock): pass


if __name__ == '__main__': unittest.main()
