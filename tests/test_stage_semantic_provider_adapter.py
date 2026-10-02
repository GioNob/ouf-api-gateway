import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout
from scripts import stage_semantic_provider_adapter as stage
REAL_PRIVATE_ANCESTORS = stage.private_ancestors
REVIEWED_PAYLOAD_HASHES = dict(stage.PAYLOAD_HASHES)


class StageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_STAGE_ROOT_FIXTURE_PARENT')); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(mode='plan', docker_path='docker', gateway_container='gateway-fixture',
            expected_gateway_id='1'*64, expected_gateway_version='3.18.0', source_commit='2'*40,
            source_url_base='https://source.fixture/repository', base_image='python@sha256:'+'3'*64,
            image_tag='provider-fixture:stage', runtime_uid=10006, runtime_gid=10006, snapshot_root=self.root/'stage')
        self.payload = b'fixture-build-file'
        self.hashes = {'Dockerfile.semantic-provider': hashlib.sha256(self.payload).hexdigest()}
        self.gateway = {'Id': '1'*64, 'Image': 'sha256:'+'4'*64,
            'State': {'Running': True, 'Pid': 123, 'StartedAt': 'fixture'},
            'Config': {'Env': ['PRIVATE_SECRET=never-print-this']}, 'HostConfig': {'ReadonlyRootfs': False},
            'Mounts': [{'Source': '/private-secret-location'}], 'NetworkSettings': {'Networks': {'private-net': {}}}}
        self.commands = []; self.built = False; self.drift = False; self.base_changed = False
        self.addCleanup(patch.stopall)
        patch.object(stage.os, 'geteuid', return_value=0).start()
        patch.object(stage, 'private_ancestors').start()
        patch.object(stage, 'PAYLOAD_HASHES', self.hashes).start()
        patch.object(stage, 'run', side_effect=self.command).start()

    def command(self, args, timeout=30, optional=False):
        self.commands.append(args)
        if args[1] == 'inspect':
            gateway = copy.deepcopy(self.gateway)
            if self.drift: gateway['Config']['Env'].append('UNEXPECTED_DRIFT=yes')
            return subprocess.CompletedProcess(args, 0, json.dumps([gateway]), '')
        if args[1] == 'exec':
            return subprocess.CompletedProcess(args, 0, 'luajit ./apisix/cli/apisix.lua version\n3.18.0\n', '')
        if args[1:3] == ['image', 'inspect']:
            if args[3] == self.args.base_image:
                image = {'Id': 'sha256:'+('9' if self.base_changed else '5')*64}
            elif not self.built:
                return subprocess.CompletedProcess(args, 1, '', 'not-found')
            else:
                image = {'Id': 'sha256:'+'6'*64, 'Config': {'User': '10006:10006', 'Entrypoint': stage.ENTRYPOINT,
                    'Labels': {'org.opencontainers.image.revision': self.args.source_commit,
                        'ouf.payload.sha256': stage.digest(self.hashes), 'ouf.component': 'semantic-provider-transport'}}}
            return subprocess.CompletedProcess(args, 0, json.dumps([image]), '')
        if args[1] == 'build':
            self.built = True
            return subprocess.CompletedProcess(args, 0, '', '')
        self.fail('unexpected command: '+repr(args))

    def downloader(self, args, context):
        stage.write_exclusive(context/'Dockerfile.semantic-provider', self.payload)

    def test_plan_is_read_only_no_fetch_build_or_container_mutation(self):
        with patch.object(stage, 'acquire_payload') as fetch:
            result = stage.operate(self.args)
        fetch.assert_not_called(); self.assertTrue(result['readOnly']); self.assertFalse(self.args.snapshot_root.exists())
        self.assertTrue(all(command[1] in ('inspect', 'exec', 'image') for command in self.commands))
        self.assertNotIn('never-print-this', json.dumps(result)); self.assertNotIn('/private-secret-location', json.dumps(result))

    def test_non_digest_base_non_root_ids_source_and_url_rejected_before_build(self):
        for field, value in [('base_image', 'python:3.13-slim'), ('runtime_uid', 0), ('runtime_gid', 0),
            ('source_commit', 'mutable-branch'), ('source_url_base', 'http://source.fixture'),
            ('source_url_base', 'https://secret@source.fixture'), ('image_tag', '-bad-tag')]:
            args = copy.copy(self.args); setattr(args, field, value)
            with self.subTest(field=field), self.assertRaises(stage.Blocked): stage.operate(args)
        self.assertFalse(self.commands)

    def test_gateway_identity_running_and_version_are_required(self):
        for field, value in [('expected_gateway_id', 'a'*64), ('expected_gateway_version', '3.19.0')]:
            args = copy.copy(self.args); setattr(args, field, value)
            with self.assertRaises(stage.Blocked): stage.operate(args)
        self.gateway['State']['Running'] = False
        with self.assertRaises(stage.Blocked): stage.operate(self.args)
        self.assertFalse(self.built)

    def test_existing_root_or_image_tag_never_overwritten(self):
        self.args.snapshot_root.mkdir()
        with self.assertRaisesRegex(stage.Blocked, 'ROOT_EXISTS'): stage.operate(self.args)
        self.args.snapshot_root.rmdir(); self.built = True
        with self.assertRaisesRegex(stage.Blocked, 'TAG_EXISTS'): stage.operate(self.args)
        self.assertFalse(any(command[1] == 'build' for command in self.commands))

    def test_apply_builds_minimal_offline_context_with_pinned_provenance(self):
        self.args.mode = 'apply'
        with patch.object(stage, 'acquire_payload', side_effect=self.downloader): result = stage.operate(self.args)
        self.assertEqual(result['imageId'], 'sha256:'+'6'*64)
        command = next(command for command in self.commands if command[1] == 'build')
        self.assertIn('--network=none', command); self.assertIn('--pull=false', command)
        for value in ['PYTHON_BASE_IMAGE='+self.args.base_image, 'SOURCE_REVISION='+self.args.source_commit,
                      'RUNTIME_UID=10006', 'RUNTIME_GID=10006', 'PAYLOAD_SHA256='+stage.digest(self.hashes)]:
            self.assertIn(value, command)
        self.assertTrue(result['noRuntimeContainersCreated']); self.assertEqual(result['providerCalls'], 0)
        self.assertEqual((self.args.snapshot_root/'stage-receipt.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.args.snapshot_root.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(command[1] in ('inspect', 'exec', 'image', 'build') for command in self.commands))

    def test_live_or_base_drift_before_build_retains_intent_and_blocks_build(self):
        self.args.mode = 'apply'
        for kind in ('gateway', 'base'):
            with tempfile.TemporaryDirectory() as root:
                self.args.snapshot_root = Path(root)/'stage'
                def acquire(args, context):
                    self.downloader(args, context)
                    if kind == 'gateway': self.drift = True
                    else: self.base_changed = True
                with patch.object(stage, 'acquire_payload', side_effect=acquire), self.assertRaises(stage.Blocked): stage.operate(self.args)
                self.assertTrue((self.args.snapshot_root/'build-intent.json').is_file()); self.assertFalse(self.built)
                self.drift = self.base_changed = False

    def test_interrupted_build_retains_intent_no_success_receipt_no_blind_rerun(self):
        self.args.mode = 'apply'
        original = self.command
        def fail(args, **kwargs):
            if args[1] == 'build': raise stage.Blocked('COMMAND_FAILED')
            return original(args, **kwargs)
        with patch.object(stage, 'run', side_effect=fail), patch.object(stage, 'acquire_payload', side_effect=self.downloader):
            with self.assertRaises(stage.Blocked): stage.operate(self.args)
        self.assertTrue((self.args.snapshot_root/'build-intent.json').is_file())
        self.assertFalse((self.args.snapshot_root/'stage-receipt.json').exists())
        with self.assertRaisesRegex(stage.Blocked, 'ROOT_EXISTS'): stage.operate(self.args)

    def test_source_hash_mismatch_and_redirect_are_rejected(self):
        context = self.root/'context'; context.mkdir()
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return self.url
            def read(self, size): return b'changed-source'
        response = Response(); response.url = self.args.source_url_base+'/'+self.args.source_commit+'/Dockerfile.semantic-provider'
        opener = Mock(); opener.open.return_value = response
        with patch.object(stage.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(stage.Blocked, 'HASH_MISMATCH'): stage.acquire_payload(self.args, context)
            response.url = 'https://foreign.fixture/file'
            with self.assertRaisesRegex(stage.Blocked, 'REDIRECT'): stage.acquire_payload(self.args, context)
        self.assertEqual(list(context.iterdir()), [])

    def test_image_contract_rejects_root_wrong_entrypoint_or_provenance(self):
        desired = stage.intent(self.args); self.built = True
        original = self.command
        for field, value in [('User', '0:0'), ('Entrypoint', ['sh'])]:
            def changed(args, **kwargs):
                result = original(args, **kwargs)
                if args[1:3] == ['image', 'inspect']:
                    image = json.loads(result.stdout)[0]; image['Config'][field] = value
                    result.stdout = json.dumps([image])
                return result
            with patch.object(stage, 'run', side_effect=changed), self.assertRaises(stage.Blocked): stage.check_staged_image(self.args, desired)

    def test_public_cli_result_never_exposes_inspect_secrets_or_mount_sources(self):
        output = io.StringIO()
        argv = ['stage', '--mode', 'plan', '--gateway-container', self.args.gateway_container,
            '--expected-gateway-id', self.args.expected_gateway_id, '--expected-gateway-version', '3.18.0',
            '--source-url-base', self.args.source_url_base, '--source-commit', self.args.source_commit,
            '--base-image', self.args.base_image, '--image-tag', self.args.image_tag,
            '--runtime-uid', '10006', '--runtime-gid', '10006', '--snapshot-root', str(self.args.snapshot_root)]
        with patch('sys.argv', argv), redirect_stdout(output): stage.main()
        self.assertIn('STAGE=PASS', output.getvalue())
        for value in ('never-print-this', '/private-secret-location', 'PRIVATE_SECRET'): self.assertNotIn(value, output.getvalue())


    @unittest.skipUnless(os.geteuid() == 0, 'real root receipt checks run in mandatory privileged staging CI')
    def test_verify_replays_no_mutation_and_rejects_changed_receipt_context(self):
        self.args.mode = 'apply'
        with patch.object(stage, 'acquire_payload', side_effect=self.downloader): stage.operate(self.args)
        self.commands.clear(); self.args.mode = 'verify'; result = stage.operate(self.args)
        self.assertEqual(result['imageId'], 'sha256:'+'6'*64)
        self.assertTrue(all(command[1] in ('inspect', 'exec', 'image') for command in self.commands))
        self.args.runtime_uid = 10007
        with self.assertRaisesRegex(stage.Blocked, 'RECEIPT_OR_LIVE_DRIFT'): stage.operate(self.args)

    @unittest.skipUnless(os.geteuid() == 0, 'real root ancestor checks run in mandatory privileged staging CI')
    def test_real_private_ancestor_guard_rejects_symlink_and_writable_parent(self):
        REAL_PRIVATE_ANCESTORS(self.root)
        child = self.root/'child'; child.mkdir(mode=0o700)
        self.root.chmod(0o777)
        with self.assertRaises(stage.Blocked): REAL_PRIVATE_ANCESTORS(child)
        self.root.chmod(0o700)
        link = self.root/'link'; link.symlink_to(child, target_is_directory=True)
        with self.assertRaises(stage.Blocked): REAL_PRIVATE_ANCESTORS(link)

    def test_reviewed_context_hashes_match_only_the_explicit_packaged_sources(self):
        repository = Path(__file__).resolve().parents[1]
        self.assertEqual(set(REVIEWED_PAYLOAD_HASHES), {'Dockerfile.semantic-provider',
            'tools/semantic_provider_adapter.py', 'tools/semantic_provider_admission.py',
            'tools/semantic_provider_boundary.py', 'tools/semantic_provider_relay.py', 'tools/southbound_security.py'})
        for path, expected in REVIEWED_PAYLOAD_HASHES.items():
            self.assertEqual(hashlib.sha256((repository/path).read_bytes()).hexdigest(), expected)


if __name__ == '__main__': unittest.main()
