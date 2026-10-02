import contextlib
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_semantic_provider_tls_runtime as module
from scripts import prepare_semantic_provider_trust as trust
from tests import test_prepare_semantic_provider_trust as trust_fixture
from tools.materialize_semantic_provider_runtime import compile_plan


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('OUF_TRUST_FULL_OWNER_TEST') == '1',
                     'mandatory root CI owns the existing UID-bound private fixture')
class TLSRuntimePrepareTest(unittest.TestCase):
    def setUp(self):
        self.fixture = trust_fixture.TrustPrepareTest('test_plan_is_read_only_and_excludes_secret_inspect_fields')
        self.fixture.setUp(); self.addCleanup(self.fixture.tearDown)
        self.fixture.apply(); root = self.fixture.root
        stage = root/'stage'; stage.mkdir(mode=0o700)
        source = Path(__file__).resolve().parents[1]
        binding = json.loads((source/'examples/semantic-provider-runtime.ouf-lab.json').read_bytes())
        for value in (binding['routes'], binding['adapter']['admission']):
            value['installation'] = 'fixture-install'
        binding['tlsIdentities'] = {'adapterHostname': self.fixture.args.adapter_hostname,
                                  'southboundHostname': self.fixture.args.southbound_hostname}
        binding['routes']['upstream'].update(upstream_host=self.fixture.args.adapter_hostname,
            nodes={self.fixture.args.adapter_hostname+':9443': 1})
        raw = json.dumps(binding).encode(); plan = json.dumps(compile_plan(binding)).encode()
        trust.write(stage/'binding.json', raw); trust.write(stage/'runtime-plan.json', plan)
        names = ('tools/materialize_semantic_provider_runtime.py', 'tools/materialize_semantic_provider.py',
                 'tools/semantic_provider_adapter.py', 'tools/semantic_provider_admission.py',
                 'tools/semantic_provider_relay.py', 'tools/semantic_provider_boundary.py',
                 'tools/southbound_security.py', 'tools/lua/admit_semantic_provider.lua')
        receipt = {'bindingHash': module.digest(raw), 'planHash': module.digest(plan),
            'trustReceiptReference': str(self.fixture.args.snapshot_root/'trust-receipt.json'),
            'notReleaseAcceptance': True, 'runtimeFilesMounted': False,
            'sourceHashes': {p: module.digest((source/p).read_bytes()) for p in names}}
        trust.write(stage/'stage-receipt.json', json.dumps(receipt).encode())
        self.args = SimpleNamespace(mode='plan', stage_root=stage, trust_root=self.fixture.args.snapshot_root,
            snapshot_root=root/'tls-runtime', gateway_container='gw', expected_gateway_id='a'*64,
            adapter_image_id='sha256:'+'b'*64, adapter_source_commit='c'*40,
            docker_path='docker', openssl_path='openssl', listen_address='0.0.0.0', listen_port=10443,
            ssl_resource_id='fixture-tls')

    def test_plan_current_role_leaf_validation_without_writes_or_offline_ca_key_reads(self):
        real = trust.read_file; reads = []
        def read(path, *args, **kwargs):
            reads.append(str(path)); return real(path, *args, **kwargs)
        before = len(self.fixture.commands)
        with patch.object(trust, 'read_file', side_effect=read):
            desired = module.operate(self.args)
        self.assertEqual(desired['gateway']['uid'], 10004)
        self.assertFalse(self.args.snapshot_root.exists())
        self.assertNotIn(str(self.args.trust_root/'ca.key'), reads)
        commands = self.fixture.commands[before:]
        self.assertFalse(any('-newkey' in c or '-keyout' in c for c in commands))
        self.assertTrue(all(c[0] == 'openssl' or (c[0] == 'docker' and c[1] in ('inspect', 'exec', 'image')) for c in commands))

    def test_private_runtime_ownership_existing_leaf_serialization_and_verify(self):
        self.args.mode = 'apply'; desired = module.operate(self.args)
        root = self.args.snapshot_root
        for name, uid in [('config.yaml', 10004), ('apisix.yaml', 10004), ('adapter.json', 10006),
                          ('tls-runtime-intent.json', 0), ('tls-runtime-receipt.json', 0)]:
            info = (root/name).stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (uid, uid, 0o600))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        resources = json.loads((root/'apisix.yaml').read_text().removesuffix('\n#END\n'))
        self.assertEqual(resources['ssls'][0]['snis'], [self.fixture.args.southbound_hostname])
        self.assertEqual(resources['ssls'][0]['key'], (self.args.trust_root/'southbound/server.key').read_text())
        runtime = json.loads((root/'config.yaml').read_text())
        self.assertEqual(runtime['apisix']['node_listen'], [])
        saved = json.loads((root/'tls-runtime-receipt.json').read_text())
        self.assertTrue(saved['trustArtifactsRevalidated']); self.assertTrue(saved['containsPrivateKey'])
        self.assertFalse(saved['mountsInstalled']); self.assertEqual(saved['containersCreated'], 0)
        self.args.mode = 'verify'; self.assertEqual(module.operate(self.args), desired)
        (root/'adapter.json').write_bytes(b'{}')
        with self.assertRaisesRegex(trust.Blocked, 'TLS_RUNTIME_FILE_DRIFT'): module.operate(self.args)

    def test_role_stage_source_and_trust_binding_drift_rejected(self):
        self.fixture.gateway['id'] = 'f'*64
        with self.assertRaises(trust.Blocked): module.operate(self.args)
        self.fixture.gateway['id'] = 'a'*64
        path = self.args.stage_root/'stage-receipt.json'
        saved = path.read_bytes(); value = json.loads(saved)
        value['sourceHashes']['tools/semantic_provider_adapter.py'] = 'f'*64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(trust.Blocked, 'STAGED_COMPILER_SOURCE_DRIFT'): module.operate(self.args)
        path.write_bytes(saved)
        key = self.args.trust_root/'adapter/provider-receipt.key'; key.write_bytes(b'f'*64)
        with self.assertRaisesRegex(trust.Blocked, 'EXISTING_RUNTIME_TRUST_ARTIFACT_DRIFT'): module.operate(self.args)
        self.assertFalse(self.args.snapshot_root.exists())

    def test_no_overwrite_partial_failure_and_redacted_cli(self):
        self.args.mode = 'apply'
        real = trust.write
        def fail(path, raw, *args, **kwargs):
            if path.name == 'apisix.yaml': raise trust.Blocked('SYNTHETIC_WRITE_FAILURE')
            return real(path, raw, *args, **kwargs)
        with patch.object(trust, 'write', side_effect=fail):
            with self.assertRaises(trust.Blocked): module.operate(self.args)
        self.assertTrue((self.args.snapshot_root/'tls-runtime-intent.json').exists())
        self.assertFalse((self.args.snapshot_root/'tls-runtime-receipt.json').exists())
        with self.assertRaisesRegex(trust.Blocked, 'TLS_RUNTIME_ROOT_EXISTS_RECONCILE'): module.operate(self.args)
        output = io.StringIO()
        with patch.object(module, 'operate', side_effect=RuntimeError('PRIVATE-KEY-MUST-NOT-PRINT')), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit): module.main(['--mode', 'plan', '--stage-root', str(self.args.stage_root),
                '--trust-root', str(self.args.trust_root), '--snapshot-root', str(self.args.snapshot_root),
                '--gateway-container', 'gw', '--expected-gateway-id', 'a'*64, '--adapter-image-id', 'sha256:'+'b'*64,
                '--adapter-source-commit', 'c'*40, '--listen-address', '0.0.0.0', '--listen-port', '10443',
                '--ssl-resource-id', 'fixture-tls'])
        self.assertNotIn('PRIVATE-KEY-MUST-NOT-PRINT', output.getvalue())
        self.assertIn('NO_SECRETS_PRINTED=true', output.getvalue())


if __name__ == '__main__': unittest.main()
