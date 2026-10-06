import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.test_semantic_authenticated_deployment_package import NAMES as V5_NAMES

NAMES=['scripts/stage_semantic_authenticated_runtime_package.py',*V5_NAMES,
       'tools/semantic_provider_deployment_reauthorization.py']

@unittest.skipUnless(os.geteuid()==0,'private source-only package')
class AuthenticatedRuntimePackageTest(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))))).resolve()
        self.root.chmod(0o700);repository=Path(__file__).resolve().parents[1]
        for name in NAMES:
            p=self.root/'source'/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            p.write_bytes((repository/name).read_bytes());p.chmod(0o600)
        self.hook_hash=hashlib.sha256((self.root/'source/scripts/semantic_provider_preexec_hook.py').read_bytes()).hexdigest()
    def call(self,mode):
        return subprocess.run([sys.executable,'-I','-B',str(self.root/'source'/NAMES[0]),'--mode',mode,
            '--package-root',str(self.root),'--source-commit','a'*40,'--hook-source-sha256',self.hook_hash],capture_output=True,text=True,timeout=10)
    def test_twenty_two_sources_no_policy_key_or_runtime_action_and_no_replay(self):
        self.assertEqual(len(set(NAMES)),22)
        self.assertEqual(self.call('plan').returncode,0);self.assertFalse((self.root/'source-package-receipt.json').exists())
        result=self.call('apply');self.assertEqual(result.returncode,0,result.stdout)
        value=json.loads((self.root/'source-package-receipt.json').read_bytes())
        self.assertEqual(value['schema'],'ouf.semantic-authenticated-runtime-source-package.v6')
        self.assertEqual(len(value['sourceHashes']),22)
        for key in ('signatureVerifierInstalled','trustPolicyProvisioned','externalProducerInstalled',
                    'runtimeRegistered','rulesChanged','unitsChanged','containersChanged','startAuthorized'):
            self.assertIs(value[key],False)
        for key in ('keysGenerated','signaturesIssued','providerCalls'):self.assertEqual(value[key],0)
        self.assertEqual(self.call('verify').returncode,0);self.assertNotEqual(self.call('apply').returncode,0)
        p=self.root/'source/tools/semantic_provider_deployment_reauthorization.py';p.write_bytes(p.read_bytes()+b'\n# drift\n')
        self.assertNotEqual(self.call('verify').returncode,0)
    def test_authenticator_not_executed_and_missing_source_blocks(self):
        p=self.root/'source/tools/semantic_provider_deployment_reauthorization.py';original=p.read_bytes()
        p.write_bytes(original+b'\nraise RuntimeError("NOT_EXECUTED_IN_STAGING")\n')
        self.assertEqual(self.call('plan').returncode,0)
        p.unlink();self.assertNotEqual(self.call('apply').returncode,0)
        self.assertFalse((self.root/'source-package-receipt.json').exists())
