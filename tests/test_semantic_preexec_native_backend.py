import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts.semantic_provider_preexec_hook import MODULES, SELF, parse, private_bytes
from tests.test_semantic_preexec import profile
from tools.semantic_provider_preexec import PreexecDenied
from tools.semantic_provider_preexec_native import NativeBackend, footprint


class NativeContractTest(unittest.TestCase):
    def test_footprint_retains_transaction_but_excludes_native_handles_counters(self):
        original = {'inet': {'nftables': [{'metainfo': {'version': '1'}},
            {'table': {'family': 'inet', 'name': 'owned', 'handle': 1, 'comment': 'ouf-preexec:fixture'}},
            {'rule': {'expr': [{'counter': {'packets': 0, 'bytes': 0}}], 'handle': 2}}]}}
        changed = copy.deepcopy(original); changed['inet']['nftables'][1]['table']['handle'] = 99
        changed['inet']['nftables'][2]['rule']['expr'][0]['counter']['packets'] = 3
        self.assertEqual(footprint(original), footprint(changed))
        changed['inet']['nftables'][1]['table']['comment'] = 'foreign'
        self.assertNotEqual(footprint(original), footprint(changed))

    def test_duplicate_json_and_exact_source_package_are_bounded(self):
        with self.assertRaises(RuntimeError): parse(b'{"profile":1,"profile":2}')
        self.assertEqual(len(MODULES), 9); self.assertEqual(SELF, 'scripts/semantic_provider_preexec_hook.py')

    @unittest.skipUnless(os.geteuid() == 0, 'trusted executable metadata fixture')
    def test_native_tables_partial_pairs_exclusive_rules_and_deadline(self):
        backend = NativeBackend(profile(), {k: '/usr/bin/true' for k in ('ip', 'nft', 'nsenter')}, 5)
        listing = []
        def run(name, arguments, raw=None):
            return json.dumps({'nftables': listing})
        backend.run = run
        self.assertIsNone(backend.tables())
        listing.append({'table': {'family': 'inet', 'name': 'shared_owned'}})
        with self.assertRaises(PreexecDenied): backend.tables()
        listing.append({'table': {'family': 'bridge', 'name': 'shared_owned'}})
        self.assertEqual(set(backend.tables()), {'inet', 'bridge'})
        with self.assertRaises(PreexecDenied): backend.create('flush ruleset')
        with patch.object(backend, 'generation', side_effect=PermissionError):
            with self.assertRaises(PermissionError): backend.generation_alive({'pid': 42})
        with patch.object(backend, 'generation', side_effect=FileNotFoundError):
            self.assertIs(backend.generation_alive({'pid': 42}), False)
        backend = NativeBackend(profile(), {k: '/usr/bin/true' for k in ('ip', 'nft', 'nsenter')}, 5)
        backend.deadline = 0
        with self.assertRaises(PreexecDenied): backend.run('nft', ['-j', 'list', 'tables'])
        backend.commands['nft'] = '/other'
        with self.assertRaises(PreexecDenied): backend.run('nft', [])

    @unittest.skipUnless(os.geteuid() == 0, 'root-private bootstrap fixture')
    def test_private_loader_refuses_duplicates_symlinks_modes_and_large_files(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT', str(Path.cwd()))) as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700)
            path = root/'private'; path.write_bytes(b'{}'); path.chmod(0o600)
            self.assertEqual(private_bytes(path), b'{}')
            path.chmod(0o644)
            with self.assertRaises(RuntimeError): private_bytes(path)
            path.chmod(0o600); link = root/'link'; link.symlink_to(path)
            with self.assertRaises(OSError): private_bytes(link)
            path.write_bytes(b'x'*131073)
            with self.assertRaises(RuntimeError): private_bytes(path)

    @unittest.skipUnless(os.geteuid() == 0, 'private source package fixture')
    def test_private_source_package_plan_apply_verify_replay_and_drift(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT', str(Path.cwd()))) as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700); source = root/'source'; source.mkdir(mode=0o700)
            repository = Path(__file__).resolve().parents[1]
            names = ['scripts/stage_semantic_preexec_package.py', 'scripts/semantic_provider_docker_runtime.py', SELF, *('tools/'+name+'.py' for name in MODULES)]
            for name in names:
                path = source/name; path.parent.mkdir(mode=0o700, exist_ok=True)
                path.write_bytes((repository/name).read_bytes()); path.chmod(0o600)
            hook_hash = hashlib.sha256((source/SELF).read_bytes()).hexdigest()
            def call(mode):
                return subprocess.run([sys.executable, '-I', '-B', str(source/names[0]), '--mode', mode,
                    '--package-root', str(root), '--source-commit', 'a'*40, '--hook-source-sha256', hook_hash],
                    capture_output=True, text=True, timeout=10)
            self.assertEqual(call('plan').returncode, 0); self.assertFalse((root/'source-package-receipt.json').exists())
            self.assertEqual(call('apply').returncode, 0)
            receipt = json.loads((root/'source-package-receipt.json').read_bytes())
            self.assertEqual(len(receipt['sourceHashes']), 12); self.assertFalse(receipt['startAuthorized'])
            self.assertFalse(receipt['runtimeAdapterInstalled']); self.assertFalse(receipt['admissionPreparerInstalled'])
            self.assertFalse(receipt['runtimeRegistered']); self.assertFalse(receipt['rulesChanged'])
            self.assertEqual(call('verify').returncode, 0); self.assertNotEqual(call('apply').returncode, 0)
            path = source/'tools/semantic_provider_preexec.py'; path.write_bytes(path.read_bytes()+b'\n# changed\n')
            self.assertNotEqual(call('verify').returncode, 0)


if __name__ == '__main__': unittest.main()
