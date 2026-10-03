"""Protocol tests. The injected backend is not a production OCI integration."""
import copy
from contextlib import contextmanager
import unittest

from tests.test_semantic_shared_coordination import policy
from tools.semantic_provider_preexec import Preexec, PreexecDenied, digest, rules


def profile():
    return {'schema': 'ouf.semantic-preexec-profile.v1', 'transactionId': 'a'*64,
        'containerId': 'fixture', 'bundlePath': '/sealed/bundle', 'bundleHash': 'b'*64,
        'namespacePath': '/run/netns/fixture', 'namespaceInode': 123,
        'namespaceLinks': [{'interface': 'eth0', 'ifindex': 2, 'hostIfindex': 7}],
        'policy': policy(), 'expectedFootprint': 'c'*64,
        'applicationStartAuthorized': False, 'infrastructureAuthorityComplete': True}


class PreexecTest(unittest.TestCase):
    def setUp(self):
        self.profile = profile(); self.held = False; self.events = []
        self.current = None; self.binding_ok = True; self.live = False
        self.leases = []; self.phase = 'QUIESCED'; self.authorized = False
        self.fail_create_after_commit = False; self.fail_remove_after_commit = False
        self.fail_publish = None; self.generations = [{'pid': 42, 'startTicks': 567, 'namespaceInode': 123}]
        test = self
        class Backend:
            def tables(self): test.assertTrue(test.held); return copy.deepcopy(test.current)
            def footprint(self, value): return value['footprint']
            def structure_hash(self, value): return value['hash']
            def bindings(self, config, state):
                test.assertTrue(test.held)
                if not test.binding_ok: raise PreexecDenied('BINDING_CHANGED')
                if state is None: return None
                return copy.deepcopy(test.generations.pop(0) if len(test.generations) > 1 else test.generations[0])
            def create(self, raw):
                test.assertTrue(test.held); test.assertIsNone(test.current)
                test.assertIn('comment "ouf-preexec:'+test.profile['transactionId']+'"', raw)
                test.events.append('create'); test.current = {'footprint': 'c'*64, 'hash': 'd'*64}
                if test.fail_create_after_commit: raise RuntimeError('crash after atomic create')
            def remove(self):
                test.assertTrue(test.held); test.events.append('remove'); test.current = None
                if test.fail_remove_after_commit: raise RuntimeError('crash after atomic removal')
            def generation_alive(self, value): return test.live
        class Owner:
            configuration = {'tableName': 'lease_owned'}
        class Coord:
            owner = Owner()
            @contextmanager
            def hold_lock(self):
                if test.held: raise BlockingIOError('contended')
                test.held = True
                try: yield
                finally: test.held = False
            def journal(self):
                test.assertTrue(test.held)
                return {'state': test.phase, 'leaseAuthorized': test.authorized}
            def sets(self): test.assertTrue(test.held); return test.leases
        class Journal:
            def read(self): return copy.deepcopy(test.record)
            def write(self, old, value):
                test.assertTrue(test.held); test.assertEqual(old, test.record)
                if value['state'] == test.fail_publish: raise RuntimeError('publication interrupted')
                test.record = copy.deepcopy(value); test.events.append(value['state'])
        self.backend, self.coord, self.journal = Backend(), Coord(), Journal()
        self.gate = Preexec(self.profile, self.backend, self.coord, self.journal)
        self.record = {'schema': 'ouf.semantic-preexec-journal.v1', 'transactionId': 'a'*64,
            'configurationHash': self.gate.config_hash, 'state': 'STAGED',
            'sharedStructureHash': None, 'containerGeneration': None}
        self.state = {'id': 'fixture', 'bundle': '/sealed/bundle', 'status': 'creating', 'pid': 42}

    def enable_fixture_start(self):
        self.profile['applicationStartAuthorized'] = True
        self.gate = Preexec(self.profile, self.backend, self.coord, self.journal)
        self.record['configurationHash'] = self.gate.config_hash

    def test_owned_install_readback_verify_and_rollback(self):
        self.assertFalse(self.gate.operate('plan')['hostRulesChanged']); self.assertEqual(self.events, [])
        self.assertEqual(self.gate.operate('apply')['state'], 'PROTECTED')
        self.assertEqual(self.events, ['INSTALLING', 'create', 'INSTALLING', 'PROTECTED'])
        self.assertFalse(self.gate.operate('verify')['hostRulesChanged'])
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.assertEqual(self.gate.operate('rollback')['state'], 'ROLLED_BACK'); self.assertIsNone(self.current)
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')

    def test_failed_atomic_create_requires_explicit_tagged_reconcile(self):
        self.fail_create_after_commit = True
        with self.assertRaises(RuntimeError): self.gate.operate('apply')
        self.assertEqual(self.record['state'], 'INSTALLING'); self.assertIsNone(self.record['sharedStructureHash'])
        with self.assertRaises(PreexecDenied): self.gate.operate('rollback')
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.fail_create_after_commit = False
        self.assertEqual(self.gate.operate('reconcile')['state'], 'PROTECTED')
        self.assertEqual(self.events.count('create'), 1)

    def test_missing_template_or_foreign_hash_never_adopted_or_removed(self):
        self.fail_create_after_commit = True
        with self.assertRaises(RuntimeError): self.gate.operate('apply')
        self.current['footprint'] = 'e'*64
        with self.assertRaises(PreexecDenied): self.gate.operate('reconcile')
        self.assertIsNone(self.record['sharedStructureHash']); self.assertNotIn('remove', self.events)
        self.current = None; self.fail_create_after_commit = False; self.gate.operate('reconcile')
        self.current['hash'] = 'f'*64
        for mode in ('verify', 'reconcile', 'rollback'):
            with self.assertRaises(PreexecDenied): self.gate.operate(mode)
        self.assertNotIn('remove', self.events)

    def test_preexisting_table_and_failed_readback_fail_closed(self):
        self.current = {'footprint': 'c'*64, 'hash': 'd'*64}
        for mode in ('plan', 'apply'):
            with self.assertRaises(PreexecDenied): self.gate.operate(mode)
        self.assertEqual(self.events, [])
        self.current = None
        def bad_create(raw): self.current = {'footprint': 'f'*64, 'hash': 'd'*64}
        self.backend.create = bad_create
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.assertEqual(self.record['state'], 'INSTALLING')

    def test_recovery_of_interrupted_publication_and_removal(self):
        self.fail_publish = 'PROTECTED'
        with self.assertRaises(RuntimeError): self.gate.operate('apply')
        self.assertEqual(self.record['state'], 'INSTALLING'); self.assertEqual(self.record['sharedStructureHash'], 'd'*64)
        self.fail_publish = None; self.gate.operate('reconcile')
        self.fail_remove_after_commit = True
        with self.assertRaises(RuntimeError): self.gate.operate('rollback')
        self.assertEqual(self.record['state'], 'REMOVING'); self.assertIsNone(self.current)
        self.assertEqual(self.gate.operate('rollback')['state'], 'ROLLED_BACK')

    def test_start_flags_oci_identity_and_incomplete_install_deny(self):
        with self.assertRaises(PreexecDenied): self.gate.before_process(self.state)
        self.assertEqual(self.events, [])
        self.enable_fixture_start()
        with self.assertRaises(PreexecDenied): self.gate.before_process(self.state)
        self.gate.operate('apply')
        for key, value in [('id', 'other'), ('bundle', '/other'), ('pid', True), ('pid', 1), ('status', 'running')]:
            with self.assertRaises(PreexecDenied): self.gate.before_process({**self.state, key: value})
        self.assertIsNone(self.record['containerGeneration'])
        self.assertTrue(self.gate.before_process(self.state)['protectedBeforeProcess'])

    def test_quiescence_binding_authority_and_contention_prevent_changes(self):
        for phase in ('LEASE_READY', 'LEASE_UPDATING', 'QUIESCING', 'BLOCKED'):
            self.phase = phase
            with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.phase = 'QUIESCED'; self.authorized = True
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.authorized = False; self.leases = [{'10.78.0.2': 3}]
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.leases = []; self.binding_ok = False
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.binding_ok = True
        with self.coord.hold_lock():
            with self.assertRaises(BlockingIOError): self.gate.operate('apply')
        self.assertEqual(self.events, [])
        self.profile['infrastructureAuthorityComplete'] = False
        self.gate = Preexec(self.profile, self.backend, self.coord, self.journal)
        self.record['configurationHash'] = self.gate.config_hash
        with self.assertRaises(PreexecDenied): self.gate.operate('apply')
        self.assertEqual(self.events, [])

    def test_live_or_changed_generation_blocks_recovery_and_hook(self):
        self.enable_fixture_start(); self.gate.operate('apply'); self.gate.before_process(self.state)
        self.live = True
        for mode in ('rollback', 'reconcile'):
            with self.assertRaises(PreexecDenied): self.gate.operate(mode)
        # Unknown liveness is not proof of a dead generation.
        for unknown in (None, 0, ''):
            self.live = unknown
            for mode in ('rollback', 'reconcile'):
                with self.assertRaises(PreexecDenied): self.gate.operate(mode)
        self.generations = [{'pid': 43, 'startTicks': 567, 'namespaceInode': 123}]
        with self.assertRaises(PreexecDenied): self.gate.before_process(self.state)
        self.live = False; self.gate.operate('reconcile'); self.assertIsNone(self.record['containerGeneration'])
        self.generations = [{'pid': 42, 'startTicks': 567, 'namespaceInode': 123},
                            {'pid': 42, 'startTicks': 568, 'namespaceInode': 123}]
        with self.assertRaises(PreexecDenied): self.gate.before_process(self.state)

    def test_profile_journal_and_rules_drift_deny(self):
        for field, bad in [('state', 'RUNNING'), ('sharedStructureHash', True),
                           ('containerGeneration', {'pid': True}), ('configurationHash', 'e'*64)]:
            original = copy.deepcopy(self.record); self.record[field] = bad
            with self.assertRaises(PreexecDenied): self.gate.operate('plan')
            self.record = original
        self.gate.profile['applicationStartAuthorized'] = True
        with self.assertRaises(PreexecDenied): self.gate.operate('plan')
        self.gate.profile['applicationStartAuthorized'] = False; self.gate.rules += '\nflush ruleset\n'
        with self.assertRaises(PreexecDenied): self.gate.operate('plan')
        self.assertEqual(self.events, [])

    def test_transaction_tag_and_namespace_links_are_bound(self):
        self.assertEqual(rules(self.profile).count('comment "ouf-preexec:'+'a'*64+'"'), 2)
        for field, bad in [('namespaceInode', True), ('bundlePath', '/a/../b'), ('transactionId', 'bad')]:
            value = copy.deepcopy(self.profile); value[field] = bad
            with self.assertRaises(ValueError): Preexec(value, self.backend, self.coord, self.journal)
        value = copy.deepcopy(self.profile); value['namespaceLinks'][0]['hostIfindex'] = True
        with self.assertRaises(ValueError): Preexec(value, self.backend, self.coord, self.journal)


if __name__ == '__main__': unittest.main()
