"""Closed pinned manifest and immutable private receipt, without source execution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from scripts.stage_semantic_local_broker_package import NAMES

@unittest.skipUnless(os.geteuid()==0,'root-private source-only package')
class LocalBrokerPackageTest(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))))).resolve()
        self.root.chmod(0o700);(self.root/'source').mkdir(mode=0o700);repository=Path(__file__).resolve().parents[1]
        for name in NAMES:
            path=self.root/'source'/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            path.write_bytes((repository/name).read_bytes());path.chmod(0o600)
        self.manifest=self.root/'sources.sha256';self.seal()
    def seal(self):
        self.manifest.write_text(''.join(hashlib.sha256((self.root/'source'/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in NAMES))
        self.manifest.chmod(0o600);self.manifest_hash=hashlib.sha256(self.manifest.read_bytes()).hexdigest()
    def call(self,mode):
        return subprocess.run([sys.executable,'-I','-B',str(self.root/'source'/NAMES[0]),'--mode',mode,
            '--package-root',str(self.root),'--source-commit','a'*40,'--source-manifest-sha256',self.manifest_hash],
            capture_output=True,text=True,timeout=10)
    def test_twenty_sources_no_body_execution_no_installs_and_no_replay(self):
        self.assertEqual(len(NAMES),20)
        self.assertEqual(self.call('plan').returncode,0);self.assertFalse((self.root/'source-package-receipt.json').exists())
        result=self.call('apply');self.assertEqual(result.returncode,0,result.stdout)
        value=json.loads((self.root/'source-package-receipt.json').read_bytes())
        self.assertEqual(value['schema'],'ouf.semantic-local-broker-source-package.v7');self.assertEqual(value['sourceCount'],20)
        self.assertEqual(value['sourceManifestHash'],self.manifest_hash)
        for key in ('brokerInstalled','runtimeAdapterInstalled','admissionPreparerInstalled','signatureVerifierInstalled',
            'externalProducerInstalled','trustPolicyProvisioned','runtimeRegistered','rulesChanged','unitsChanged','containersChanged','startAuthorized'):
            self.assertIs(value[key],False)
        for key in ('sourceBodiesExecuted','keysGenerated','privateKeysRead','signaturesIssued','providerCalls'):self.assertEqual(value[key],0)
        self.assertEqual(self.call('verify').returncode,0);before=(self.root/'source-package-receipt.json').read_bytes()
        self.assertNotEqual(self.call('apply').returncode,0);self.assertEqual((self.root/'source-package-receipt.json').read_bytes(),before)
    def test_hook_broker_and_producer_bodies_are_never_executed(self):
        for name in ('scripts/semantic_provider_preexec_hook.py','scripts/semantic_provider_deployment_broker.py',
                     'tools/semantic_provider_deployment_producer.py'):
            path=self.root/'source'/name;path.write_bytes(path.read_bytes()+b'\nraise RuntimeError("MUST_NOT_EXECUTE")\n')
        self.seal();self.assertEqual(self.call('plan').returncode,0);self.assertEqual(self.call('apply').returncode,0)
    def test_source_drift_blocked_by_manifest_before_apply(self):
        path=self.root/'source/tools/semantic_provider_deployment_producer.py';path.write_bytes(path.read_bytes()+b'\n')
        result=self.call('apply');self.assertNotEqual(result.returncode,0);self.assertIn('PINNED_SOURCE_HASH_DRIFT',result.stdout)
        self.assertFalse((self.root/'source-package-receipt.json').exists())
    def test_manifest_edit_cannot_repin_sources_implicitly(self):
        path=self.root/'source/tools/semantic_provider_deployment_producer.py';path.write_bytes(path.read_bytes()+b'\n')
        old=self.manifest_hash;self.seal();self.manifest_hash=old
        self.assertNotEqual(self.call('apply').returncode,0);self.assertFalse((self.root/'source-package-receipt.json').exists())
    def test_missing_duplicate_or_foreign_manifest_source_is_denied(self):
        original=self.manifest.read_bytes()
        for value in (b'\n'.join(original.splitlines()[:-1])+b'\n',original+original.splitlines()[0]+b'\n',
                      original+b'0'*64+b'  tests/fixture.py\n'):
            with self.subTest():
                self.manifest.write_bytes(value);self.manifest_hash=hashlib.sha256(value).hexdigest()
                self.assertNotEqual(self.call('apply').returncode,0)
                self.assertFalse((self.root/'source-package-receipt.json').exists())
    def test_symlink_hardlink_or_public_source_is_denied(self):
        path=self.root/'source/tools/semantic_provider_deployment_producer.py';original=path.read_bytes()
        foreign=self.root/'foreign.py';foreign.write_bytes(original);foreign.chmod(0o600)
        for kind in ('symlink','hardlink','public'):
            with self.subTest(kind=kind):
                path.unlink()
                if kind=='symlink':path.symlink_to(foreign)
                elif kind=='hardlink':os.link(foreign,path)
                else:path.write_bytes(original);path.chmod(0o644)
                self.assertNotEqual(self.call('apply').returncode,0)
                self.assertFalse((self.root/'source-package-receipt.json').exists())
    def test_receipt_boolean_and_integer_alias_cannot_pass_verify(self):
        self.assertEqual(self.call('apply').returncode,0)
        path=self.root/'source-package-receipt.json';value=json.loads(path.read_bytes());value['brokerInstalled']=0
        path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
        self.assertNotEqual(self.call('verify').returncode,0)

    def test_verified_receipt_drift_is_denied_without_repair(self):
        self.assertEqual(self.call('apply').returncode,0)
        path=self.root/'source-package-receipt.json';value=json.loads(path.read_bytes());value['brokerInstalled']=True
        path.write_text(json.dumps(value));before=path.read_bytes()
        self.assertNotEqual(self.call('verify').returncode,0);self.assertEqual(path.read_bytes(),before)

if __name__=='__main__':unittest.main()
