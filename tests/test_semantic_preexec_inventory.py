import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from scripts.inventory_semantic_preexec_runtime import InventoryDenied, inventory, version


class InventoryTest(unittest.TestCase):
    def query(self, template):
        if template == '{{.ServerVersion}}': return '28.5.1\n'
        if template == '{{.DefaultRuntime}}': return 'runc\n'
        return 'runc\nio.containerd.runc.v2\n\n'

    def test_only_allowlisted_fields_and_no_start_or_integration_claim(self):
        result = inventory(self.query, '1.3.1')
        self.assertEqual(result['runtimeNames'], ['io.containerd.runc.v2', 'runc'])
        self.assertTrue(result['readOnly']); self.assertTrue(result['stableAcrossReads'])
        self.assertFalse(result['startAuthorized']); self.assertFalse(result['ociHookIntegrationProven'])
        self.assertFalse(result['atomicSnapshotProven'])

    def test_invalid_or_changed_runtime_inventory_fails_closed(self):
        for bad in ('runc\nrunc\n', 'runc\nsecret bad\n', '', 'runc\n'+'x'*129):
            def query(template):
                if 'range' in template: return bad
                return self.query(template)
            with self.assertRaises(InventoryDenied): inventory(query, '1.3.1')
        count = 0
        def changed(template):
            nonlocal count
            count += 1
            return 'other\n' if count == 5 else self.query(template)
        with self.assertRaises(InventoryDenied): inventory(changed, '1.3.1')

    def test_version_output_never_prints_unvalidated_text(self):
        self.assertEqual(version('1.3.1+build.2'), '1.3.1+build.2')
        self.assertEqual(version('1.3.1-0ubuntu1~24.04.1'), '1.3.1-0ubuntu1~24.04.1')
        for bad in ('secret\nvalue', '1.2.3\nsecret', '1.2.3;curl', 'x'*100, ''):
            with self.assertRaises(InventoryDenied): version(bad)


@unittest.skipUnless(os.environ.get('OUF_PREEXEC_INVENTORY_NATIVE_TEST') == '1', 'local Docker read-only inventory opt-in')
class LocalDockerInventoryTest(unittest.TestCase):
    def test_private_helper_reads_local_runtime_without_registration(self):
        self.assertEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory(prefix='ouf-runtime-inventory-', dir='/root') as tmp:
            source = Path(tmp); source.chmod(0o700)
            script = source/'inventory.py'
            script.write_bytes((Path(__file__).resolve().parents[1]/'scripts/inventory_semantic_preexec_runtime.py').read_bytes())
            script.chmod(0o600)
            docker, runc = shutil.which('docker'), shutil.which('runc')
            self.assertIsNotNone(docker); self.assertIsNotNone(runc)
            result = subprocess.run([sys.executable, '-I', '-B', str(script), '--docker-path', docker, '--runc-path', runc],
                                    capture_output=True, text=True, timeout=55)
            self.assertEqual(result.returncode, 0, result.stdout)
            lines = result.stdout.splitlines(); self.assertEqual(len(lines), 2)
            value = json.loads(lines[0].split('=', 1)[1]); self.assertTrue(value['readOnly'])
            self.assertFalse(value['ociHookIntegrationProven']); self.assertFalse(value['startAuthorized'])
            self.assertIn('=PASS ', lines[1]); self.assertEqual(result.stderr, '')


if __name__ == '__main__': unittest.main()
