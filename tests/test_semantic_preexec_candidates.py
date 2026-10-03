import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
from scripts import inventory_semantic_preexec_candidates as helper


class CandidateInventoryTest(unittest.TestCase):
    def setUp(self):
        self.net = 'e'*64; self.ids = {'one': 'a'*64, 'two': 'b'*64}
        self.manifest = {'installation': 'fixture', 'containers': [
            {'name': name, 'image': 'sha256:'+'c'*64,
             'networks': [{'name': 'fixture', 'id': self.net, 'ipv4': '192.0.2.'+str(i+2)}]}
            for i, name in enumerate(self.ids)]}
        self.journal = {'candidateIds': self.ids, 'transaction': 'd'*32, 'manifestHash': 'f'*64}
        self.cold = {'networkIds': {'internal': self.net}, 'binding': {'internal_bridge': 'br-fixture'}}
        self.rows = {identity: {'id': identity, 'name': '/'+name, 'image': 'sha256:'+'c'*64,
            'status': 'created', 'running': False, 'restarting': False, 'pid': 0, 'started': '0001-01-01T00:00:00Z',
            'runtime': 'runc', 'restart': 'no', 'mode': self.net, 'transaction': 'd'*32, 'manifest': 'f'*64,
            'sandbox': '', 'networks': {'fixture': {'NetworkID': '', 'IPAMConfig': {'IPv4Address': '192.0.2.'+str(i+2)},
                'Aliases': [name], 'GlobalIPv6Address': ''}}} for i, (name, identity) in enumerate(self.ids.items())}
        self.fact = {'id': self.net, 'name': 'fixture', 'driver': 'bridge', 'ipv6': False,
                     'internal': True, 'bridge': 'br-fixture', 'owner': 'fixture', 'members': {}}

    def query(self, kind, identity): return copy.deepcopy(self.rows[identity] if kind == 'container' else self.fact)

    def test_configured_created_endpoints_are_not_live_admission(self):
        value = helper.inventory(self.manifest, self.journal, self.cold, self.query)
        self.assertEqual(value['candidateRuntimes'], ['runc']); self.assertEqual(value['sandboxKeyPresentCount'], 0)
        for key in ('liveNamespaceBindingProven', 'atomicSnapshotProven', 'fullCreationAcceptanceProven',
                    'ociHookIntegrationProven', 'runtimeRegistrationAuthorized', 'startAuthorized'):
            self.assertFalse(value[key])
        self.assertNotIn('192.0.2.', json.dumps(value)); self.assertNotIn('transaction', value)

    def test_started_rebound_or_wrong_static_configuration_denied(self):
        identity = next(iter(self.rows)); original = copy.deepcopy(self.rows[identity])
        for key, bad in [('running', True), ('pid', 42), ('runtime', 'runc\nsecret'), ('restart', 'always'),
                         ('transaction', 'z'*32), ('image', 'changed'), ('started', '2026-10-03T00:00:00Z')]:
            self.rows[identity] = {**original, key: bad}
            with self.assertRaises(helper.Blocked): helper.inventory(self.manifest, self.journal, self.cold, self.query)
        self.rows[identity] = original
        self.rows[identity]['networks']['fixture']['IPAMConfig']['IPv4Address'] = '192.0.2.99'
        with self.assertRaises(helper.Blocked): helper.inventory(self.manifest, self.journal, self.cold, self.query)

    def test_foreign_owned_network_members_and_read_drift_denied(self):
        self.fact['members'] = {'9'*64: {'Name': 'foreign'}}
        with self.assertRaises(helper.Blocked): helper.inventory(self.manifest, self.journal, self.cold, self.query)
        self.fact['members'] = {}; calls = 0
        def changed(kind, identity):
            nonlocal calls
            calls += 1; row = self.query(kind, identity)
            if calls > 3 and kind == 'container': row['sandbox'] = '/var/run/docker/netns/changed'
            return row
        with self.assertRaises(helper.Blocked): helper.inventory(self.manifest, self.journal, self.cold, changed)

    def test_duplicate_keys_bounded_stdout_and_deadline(self):
        with self.assertRaises(helper.Blocked): helper.decode('{"a":1,"a":2}')
        env = {'PATH': '/usr/bin:/bin'}
        with self.assertRaises(helper.Blocked):
            helper.bounded([sys.executable, '-c', 'print("x"*140000)'], time.monotonic()+5, env)
        with self.assertRaises(helper.Blocked):
            helper.bounded([sys.executable, '-c', 'import time; time.sleep(10)'], time.monotonic()+0.1, env)


@unittest.skipUnless(os.environ.get('OUF_PREEXEC_INVENTORY_NATIVE_TEST') == '1', 'real Docker candidate inventory opt-in')
class DockerCandidateInventoryTest(unittest.TestCase):
    def test_cli_on_two_never_started_candidates_and_private_manifest(self):
        self.assertEqual(os.geteuid(), 0); docker = shutil.which('docker'); self.assertIsNotNone(docker)
        token = uuid.uuid4().hex[:10]; network = 'ouf-ci-'+token; bridge = 'ouf'+token
        names = ['ouf-ci-'+token+'-one', 'ouf-ci-'+token+'-two']; transaction = uuid.uuid4().hex
        def run(*args, payload=None):
            result = subprocess.run([docker, *args], input=payload, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, 'Docker fixture command failed')
            return result.stdout.decode().strip()
        image = None; created = []; net_id = None
        try:
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar:
                item = tarfile.TarInfo('fixture'); item.size = 7; tar.addfile(item, io.BytesIO(b'fixture'))
            image = run('image', 'import', '-', payload=archive.getvalue())
            net_id = run('network', 'create', '--internal', '--subnet', '192.0.2.0/24',
                         '--label', 'ouf.cold-network.owner=fixture', '--opt', 'com.docker.network.bridge.name='+bridge, network)
            specs = [{'name': name, 'image': image, 'networks': [{'name': network, 'id': net_id, 'ipv4': '192.0.2.'+str(i+2)}]}
                     for i, name in enumerate(names)]
            cold = {'networkIds': {'internal': net_id}, 'binding': {'internal_bridge': bridge}}
            cold_raw = json.dumps(cold).encode()
            manifest = {'schema': 'ouf.semantic-provider-stopped-manifest.v1', 'startAuthorized': False,
                        'installation': 'fixture', 'containers': specs, 'networkReceiptHash': helper.digest(cold_raw)}
            manifest_raw = json.dumps(manifest).encode(); mh = helper.digest(manifest_raw); ids = {}
            for spec in specs:
                cid = run('create', '--name', spec['name'], '--restart', 'no', '--network', net_id,
                          '--network-alias', spec['name'], '--ip', spec['networks'][0]['ipv4'],
                          '--label', 'ouf.semantic.candidate.transaction='+transaction,
                          '--label', 'ouf.semantic.candidate.manifest='+mh, image, '/never-run')
                created.append(cid); ids[spec['name']] = cid
            journal = {'schema': 'ouf.semantic-provider-stopped-create.v1', 'state': 'CREATED_STOPPED',
                       'startAuthorized': False, 'sourceCommit': '1'*40, 'manifestHash': mh,
                       'candidateIds': ids, 'transaction': transaction}
            journal_raw = json.dumps(journal).encode()
            with tempfile.TemporaryDirectory(dir='/root', prefix='ouf-candidate-inventory-') as tmp:
                root = Path(tmp); root.chmod(0o700)
                for name, raw in [('stopped-manifest.json', manifest_raw), ('creation-journal.json', journal_raw),
                                  ('network-receipt.json', cold_raw), ('inventory.py', Path(helper.__file__).read_bytes())]:
                    target = root/name; target.write_bytes(raw); target.chmod(0o600)
                result = subprocess.run([sys.executable, '-I', '-B', str(root/'inventory.py'),
                    '--manifest-root', tmp, '--creation-root', tmp, '--network-root', tmp,
                    '--expected-manifest-hash', mh, '--expected-creation-journal-hash', helper.digest(journal_raw),
                    '--creation-source-commit', '1'*40, '--docker-path', docker], capture_output=True, text=True, timeout=40)
                self.assertEqual(result.returncode, 0, result.stdout)
                lines = result.stdout.splitlines(); self.assertEqual(len(lines), 2)
                value = json.loads(lines[0].split('=', 1)[1]); self.assertEqual(value['candidateCount'], 2)
                self.assertTrue(value['configuredBindingsMatchManifest']); self.assertFalse(value['startAuthorized'])
                self.assertEqual(result.stderr, ''); self.assertIn('=PASS ', lines[1])
        finally:
            for cid in created: run('rm', cid)
            if net_id: run('network', 'rm', net_id)
            if image: run('image', 'rm', image)


if __name__ == '__main__': unittest.main()
