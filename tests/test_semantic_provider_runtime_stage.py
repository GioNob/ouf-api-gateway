"""Root-private metadata staging with fixture-only curl; no network/provider I/O."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.geteuid() == 0, 'root metadata stage gate runs separately in CI')
class RuntimeStageTest(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get('OUF_RUNTIME_STAGE_TEST_PARENT', str(Path.cwd()))
        self.tmp = tempfile.TemporaryDirectory(prefix='runtime-stage-fixture-', dir=parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.bin = self.root/'bin'; self.bin.mkdir()
        self.source = self.root/'source'; self.source.mkdir()
        self.repo = Path(__file__).resolve().parents[1]
        paths = ['tools/materialize_semantic_provider_runtime.py', 'tools/materialize_semantic_provider.py',
            'tools/semantic_provider_adapter.py', 'tools/semantic_provider_admission.py',
            'tools/semantic_provider_relay.py', 'tools/semantic_provider_boundary.py',
            'tools/southbound_security.py', 'tools/lua/admit_semantic_provider.lua',
            'examples/semantic-provider-runtime.ouf-lab.json']
        for name in paths:
            destination = self.source/name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repo/name, destination)
        self.executable('curl', '''import os, pathlib, sys
args=sys.argv[1:]
assert args[args.index('--proto')+1]=='=https' and '--tlsv1.2' in args
assert '--location' not in args and '-L' not in args
prefix='https://raw.githubusercontent.com/fixture/repository/'+('a'*40)+'/'
assert args[-1].startswith(prefix)
raw=(pathlib.Path(os.environ['STAGE_FIXTURE_SOURCE'])/args[-1][len(prefix):]).read_bytes()
pathlib.Path(args[args.index('--output')+1]).write_bytes(raw)
print(os.environ.get('STAGE_FIXTURE_STATUS','200'),end='')
''')
        self.executable('sudo', '''import os, sys
# Downloaded Python may only run without sudo; the root stage is fixed stdlib.
assert sys.argv[1:4]==['python3','-B','-']
os.execvp(sys.argv[1],sys.argv[1:])
''')
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        STAGE_FIXTURE_SOURCE=str(self.source), OUF_RUNTIME_STAGE_TEMP_PARENT=str(self.root))

    def executable(self, name, code):
        path = self.bin/name; path.write_text('#!'+sys.executable+'\n'+code); path.chmod(0o700)

    def run_stage(self, name='snapshot', status='200'):
        return subprocess.run(['bash', str(self.repo/'scripts/stage_semantic_provider_runtime_plan.sh'),
            'fixture/repository', 'a'*40, 'examples/semantic-provider-runtime.ouf-lab.json',
            str(self.root/name), str(self.root/'trust-receipt.json')],
            env=dict(self.env, STAGE_FIXTURE_STATUS=status), capture_output=True, text=True, timeout=30)

    def test_private_concrete_lab_plan_and_hash_readback_without_secret_or_root_source_execution(self):
        result = self.run_stage(); self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        target = self.root/'snapshot'
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        for name in ('binding.json', 'runtime-plan.json', 'stage-receipt.json'):
            self.assertEqual(stat.S_IMODE((target/name).stat().st_mode), 0o600)
            self.assertEqual((target/name).stat().st_uid, 0)
        binding = json.loads((target/'binding.json').read_bytes())
        self.assertEqual(binding['adapter']['admission']['tenants'], ['ouf-lab'])
        plan = json.loads((target/'runtime-plan.json').read_bytes())
        self.assertFalse(plan['installed']); self.assertEqual(plan['providerCalls'], 0)
        self.assertEqual(plan['dnsBinding']['selectedResolvers'], ['46.38.252.230', '46.38.225.230'])
        receipt = json.loads((target/'stage-receipt.json').read_bytes())
        self.assertFalse(receipt['trustArtifactsRevalidated']); self.assertFalse(receipt['liveConfigurationRevalidated'])
        self.assertFalse(receipt['runtimeFilesMounted']); self.assertTrue(receipt['notReleaseAcceptance'])
        for name, key in [('binding.json', 'bindingHash'), ('runtime-plan.json', 'planHash')]:
            self.assertEqual(hashlib.sha256((target/name).read_bytes()).hexdigest(), receipt[key])
        self.assertFalse((self.root/'trust-receipt.json').exists(), 'trust reference must not be opened/created')
        self.assertIn('NO_CONTAINER_CREATED=true', result.stdout)
        self.assertNotIn('OUF_GATEWAY_OIDC_CLIENT_SECRET', result.stdout+result.stderr)

    def test_existing_snapshot_never_overwritten(self):
        self.assertEqual(self.run_stage().returncode, 0)
        target = self.root/'snapshot'
        before = {p.name: p.read_bytes() for p in target.iterdir()}
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DO_NOT_RERUN_BLINDLY=true', result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in target.iterdir()})

    def test_redirect_invalid_binding_symlink_and_unsafe_parent_rejected(self):
        result = self.run_stage('redirect', '302')
        self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root/'redirect').exists())
        profile = self.source/'examples/semantic-provider-runtime.ouf-lab.json'
        raw = profile.read_bytes(); binding = json.loads(raw)
        binding['adapter']['admission']['tenants'] = ['incorrect']
        profile.write_text(json.dumps(binding))
        result = self.run_stage('bad-binding')
        self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root/'bad-binding').exists())
        profile.write_bytes(raw)
        (self.root/'link').symlink_to(self.root/'absent', target_is_directory=True)
        result = self.run_stage('link')
        self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root/'absent').exists())
        (self.root/'unsafe').mkdir(mode=0o777); (self.root/'unsafe').chmod(0o777)
        result = self.run_stage('unsafe/snapshot')
        self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root/'unsafe/snapshot').exists())


if __name__ == '__main__': unittest.main()
