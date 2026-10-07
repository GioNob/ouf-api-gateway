"""Real missing-table restoration and active lease revocation, isolated only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tests import test_semantic_shared_coordination_native as fixture
from scripts import restore_semantic_runtime_boot_guard as boot
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_boot_coordination import prepare_docker_boot
from tools.semantic_provider_lease_coordination import Coordinator, PrivateJournal, hold_common_lock
from tools.semantic_provider_lease_nft import NftBackend, structure_hash
from tools.semantic_provider_lease_owner import LeaseOwner


@unittest.skipUnless(os.environ.get('OUF_SHARED_COORDINATION_NATIVE_TEST') == '1', 'isolated namespace only')
class BootNativeTest(unittest.TestCase):
    setUp = fixture.NativeTest.setUp
    command = fixture.NativeTest.command
    cleanup = fixture.NativeTest.cleanup
    kernel = fixture.NativeTest.kernel

    def exercise(self, missing):
        cfg = self.kernel()
        self.command('nft', '-f', '-', raw=materialize(cfg, empty_provider_sets=True)['nftRules'])
        self.tables += [(f, 'lease_owned') for f in ('inet', 'bridge')]
        self.command('nft', 'add', 'table', 'inet', 'unrelated')
        self.tables.append(('inet', 'unrelated'))
        shared_before = self.command('nft', '-j', 'list', 'table', 'inet', 'unrelated')
        original = {f: json.loads(self.command('nft', '-j', 'list', 'table', f, 'lease_owned'))
                    for f in ('inet', 'bridge')}
        expected = structure_hash(original)
        with tempfile.TemporaryDirectory(dir='/etc', prefix='ouf-boot-coordination-') as tmp:
            root = Path(tmp); root.chmod(0o700)
            def private(name, value):
                raw = value if isinstance(value, bytes) else json.dumps(value).encode()
                path = root/name; path.write_bytes(raw); path.chmod(0o600); return path
            compiler = private('compiler.py', (Path(__file__).resolve().parents[1]/'tools/materialize_southbound_kernel.py').read_bytes())
            lock = private('common.lock', b'')
            old_journal = private('old.json', {'schema': 'ouf.semantic-runtime-transition.v1',
                'state': 'RUNTIME_EMPTY', 'transactionId': 'a'*64, 'configurationHash': 'b'*64,
                'startAuthorized': False, 'leaseStructureHash': expected})
            config = {'schema': 'ouf.semantic-runtime-boot-guard.v1', 'nftPath': shutil.which('nft'),
                'kernel': cfg, 'compilerFile': str(compiler), 'compilerHash': hashlib.sha256(compiler.read_bytes()).hexdigest(),
                'expectedFootprint': boot.footprint(original), 'journalFile': str(old_journal),
                'transactionId': 'a'*64, 'lockFile': str(lock)}
            binding = {'transactionId': 'c'*64, 'configurationHash': 'd'*64, 'leaseStructureHash': expected}
            journal_path = private('coord.json', {'schema': 'ouf.semantic-lease-coordination.v1', **binding,
                'state': 'LEASE_READY', 'leaseAuthorized': True, 'startAuthorized': False,
                'leaseAddresses': [['10.78.0.2']]})
            journal = PrivateJournal(journal_path)
            owner = LeaseOwner(cfg, {'resolvers': ['127.0.0.1'], 'resolverPort': 53, 'timeoutSeconds': 2,
                'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, NftBackend([shutil.which('nft')], cfg, expected, 2))
            coord = Coordinator(owner, binding, lambda: hold_common_lock(lock), journal.read, journal.write)
            if missing:
                self.command('nft', '-f', '-', raw='delete table inet lease_owned\ndelete table bridge lease_owned\n')
            else:
                for family in ('inet', 'bridge'):
                    self.command('nft', '-f', '-', raw=f'add element {family} lease_owned provider_0 {{ 10.78.0.2 timeout 30s }}\n')
            # Calls the genuine sealed boot restorer, not a simulated callback.
            result = prepare_docker_boot(coord, lambda: boot.membership(config), lambda: boot.restore(config, 'b'*64))
            self.assertTrue(result['dockerPrestartStructuralGate'])
            self.assertFalse(result['providerRestartAuthorized'])
            self.assertFalse(journal.read()['leaseAuthorized'])
            self.assertTrue(boot.sets_empty(boot.tables(config)))
            self.assertEqual(journal.read()['state'], 'BLOCKED' if missing else 'QUIESCED')
            self.assertEqual(result['leaseStructureReconciliationRequired'], missing)
            self.assertEqual(old_journal.read_bytes(), json.dumps({'schema': 'ouf.semantic-runtime-transition.v1',
                'state': 'RUNTIME_EMPTY', 'transactionId': 'a'*64, 'configurationHash': 'b'*64,
                'startAuthorized': False, 'leaseStructureHash': expected}).encode())
            with self.assertRaises(Exception): coord.fresh_start()
        self.assertEqual(shared_before, self.command('nft', '-j', 'list', 'table', 'inet', 'unrelated'))

    def test_missing_generation_restored_empty_without_rearm(self): self.exercise(True)
    def test_active_lease_revoked_before_boot_without_shared_changes(self): self.exercise(False)


if __name__ == '__main__': unittest.main()
