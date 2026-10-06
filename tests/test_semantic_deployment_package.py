import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.semantic_provider_preexec_hook import MODULES, SELF

NAMES=['scripts/stage_semantic_deployment_package.py','scripts/stage_semantic_admission_package.py',
       'scripts/stage_semantic_preexec_package.py','scripts/semantic_provider_docker_runtime.py',SELF,
       'scripts/semantic_provider_admission_preparer.py',*('tools/'+m+'.py' for m in MODULES),
       'tools/semantic_provider_deployment_admission.py','tools/semantic_provider_deployment_protocol.py',
       'tools/semantic_provider_deployment_consumption.py']


@unittest.skipUnless(os.geteuid()==0,'root-private source package')
class DeploymentPackageTest(unittest.TestCase):
    def setUp(self):
        temp=self.enterContext(tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))))
        self.root=Path(temp).resolve(); self.root.chmod(0o700); self.source=self.root/'source'; self.source.mkdir(mode=0o700)
        repository=Path(__file__).resolve().parents[1]
        for name in NAMES:
            p=self.source/name; p.parent.mkdir(mode=0o700,exist_ok=True)
            p.write_bytes((repository/name).read_bytes()); p.chmod(0o600)
        self.hook_hash=hashlib.sha256((self.source/SELF).read_bytes()).hexdigest()

    def call(self,mode):
        return subprocess.run([sys.executable,'-I','-B',str(self.source/NAMES[0]),'--mode',mode,
            '--package-root',str(self.root),'--source-commit','a'*40,'--hook-source-sha256',self.hook_hash],
            capture_output=True,text=True,timeout=10)

    def test_eighteen_sources_sealed_without_runtime_actions_and_replay_denied(self):
        self.assertEqual(len(NAMES),18)
        self.assertEqual(self.call('plan').returncode,0); self.assertFalse((self.root/'source-package-receipt.json').exists())
        result=self.call('apply'); self.assertEqual(result.returncode,0,result.stdout)
        value=json.loads((self.root/'source-package-receipt.json').read_bytes())
        self.assertEqual(value['schema'],'ouf.semantic-deployment-source-package.v4')
        self.assertEqual(len(value['sourceHashes']),18)
        for key in ('runtimeRegistered','rulesChanged','unitsChanged','containersChanged','startAuthorized',
                    'runtimeAdapterInstalled','admissionPreparerInstalled','externalProducerInstalled'):
            self.assertIs(value[key],False)
        self.assertEqual(self.call('verify').returncode,0); self.assertNotEqual(self.call('apply').returncode,0)
        p=self.source/'tools/semantic_provider_deployment_consumption.py'; p.write_bytes(p.read_bytes()+b'\n# drift\n')
        self.assertNotEqual(self.call('verify').returncode,0)

    def test_missing_source_or_invalid_python_blocks_before_receipt(self):
        p=self.source/'tools/semantic_provider_deployment_consumption.py'; original=p.read_bytes(); p.unlink()
        self.assertNotEqual(self.call('plan').returncode,0)
        p.write_bytes(b'invalid python syntax !'); p.chmod(0o600)
        self.assertNotEqual(self.call('apply').returncode,0)
        self.assertFalse((self.root/'source-package-receipt.json').exists())
        p.write_bytes(original); self.assertEqual(self.call('plan').returncode,0)

    def test_source_compilation_does_not_execute_unrelated_module_body(self):
        p=self.source/'tools/semantic_provider_deployment_consumption.py'
        p.write_bytes(p.read_bytes()+b'\nraise RuntimeError("MUST_NOT_EXECUTE_DURING_STAGING")\n')
        self.assertEqual(self.call('plan').returncode,0)
        self.assertFalse((self.root/'source-package-receipt.json').exists())


if __name__=='__main__': unittest.main()
