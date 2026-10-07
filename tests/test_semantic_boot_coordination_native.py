"""Real missing-table restoration and active lease revocation, isolated only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
            # Exercise the installed-style command through isolated Python and
            # a complete root-private source/configuration closure.
            from scripts.run_semantic_coordinated_lease_owner import FILES
            repo = Path(__file__).resolve().parents[1]
            source = root/'source'; source.mkdir(mode=0o700)
            additions = ('scripts/run_semantic_coordinated_boot_guard.py',
                         'tools/semantic_provider_boot_coordination.py')
            hashes = {}
            for name in (*FILES, *additions):
                target = source/name; target.parent.mkdir(mode=0o700, exist_ok=True)
                raw = (repo/name).read_bytes(); target.write_bytes(raw); target.chmod(0o600)
                hashes[name] = hashlib.sha256(raw).hexdigest()
            boot_config_path = private('boot-config.json', config)
            boot_hash = hashlib.sha256(boot_config_path.read_bytes()).hexdigest()
            old_value = json.loads(old_journal.read_bytes()); old_value['configurationHash'] = boot_hash
            old_journal.write_text(json.dumps(old_value)); original_journal_raw = old_journal.read_bytes()
            guard_file = private('boot-guard.py', (repo/'scripts/restore_semantic_runtime_boot_guard.py').read_bytes())
            owner_config_path = private('owner-config.json', {
                'schema': 'ouf.semantic-coordinated-owner-runtime.v1', 'kernel': cfg, 'dns': owner.profile,
                'expectedStructureHash': expected, 'nftPath': shutil.which('nft'),
                'nftSha256': hashlib.sha256(Path(shutil.which('nft')).read_bytes()).hexdigest(),
                'readBudgetSeconds': 2, 'pollSeconds': 5, 'commonLockFile': str(lock),
                'journalFile': str(journal_path), 'binding': binding,
                'sourceHashes': {name: hashes[name] for name in FILES}})
            profile_path = private('profile.json', {
                'schema': 'ouf.semantic-coordinated-boot-profile.v1',
                'sourceHashes': {name: hashes[name] for name in additions},
                'coordinatedConfiguration': str(owner_config_path),
                'coordinatedConfigurationHash': hashlib.sha256(owner_config_path.read_bytes()).hexdigest(),
                'bootConfiguration': str(boot_config_path), 'bootConfigurationHash': boot_hash,
                'bootGuardFile': str(guard_file), 'bootGuardHash': hashlib.sha256(guard_file.read_bytes()).hexdigest()})
            cli = [sys.executable, '-I', '-B', str(source/additions[0]), '--configuration', str(profile_path),
                   '--configuration-sha256', hashlib.sha256(profile_path.read_bytes()).hexdigest()]
            executed = subprocess.run(cli, capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            result = json.loads(executed.stdout.split('SEMANTIC_COORDINATED_BOOT_GUARD=')[1])
            self.assertTrue(result['dockerPrestartStructuralGate'])
            self.assertFalse(result['providerRestartAuthorized'])
            self.assertFalse(journal.read()['leaseAuthorized'])
            self.assertTrue(boot.sets_empty(boot.tables(config)))
            self.assertEqual(journal.read()['state'], 'BLOCKED' if missing else 'QUIESCED')
            self.assertEqual(result['leaseStructureReconciliationRequired'], missing)
            self.assertEqual(old_journal.read_bytes(), original_journal_raw)
            # Tampering is denied before another journal or firewall mutation.
            before = journal_path.read_bytes()
            (source/additions[1]).write_text('raise RuntimeError("unsealed")')
            denied = subprocess.run(cli, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(journal_path.read_bytes(), before)
            with self.assertRaises(Exception): coord.fresh_start()
        self.assertEqual(shared_before, self.command('nft', '-j', 'list', 'table', 'inet', 'unrelated'))

    def test_missing_generation_restored_empty_without_rearm(self): self.exercise(True)
    def test_active_lease_revoked_before_boot_without_shared_changes(self): self.exercise(False)


if __name__ == '__main__': unittest.main()
