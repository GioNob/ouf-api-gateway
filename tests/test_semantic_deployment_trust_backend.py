import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from scripts import inventory_semantic_deployment_trust_backend as probe
from tests.test_semantic_deployment_package import NAMES

@unittest.skipUnless(os.geteuid()==0,'root-private custody')
class TrustBackendTest(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))))).resolve()
        self.root.chmod(0o700)
        receipt=dict(schema='ouf.semantic-deployment-source-package.v4',sourceCommit='a'*40,sourceHashes={},providerCalls=0,notReleaseAcceptance=True,noSecretsPrinted=True)
        receipt.update({k:False for k in probe.FLAGS})
        for i,name in enumerate(NAMES):
            p=self.root/'source'/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            raw=('source '+str(i)).encode();p.write_bytes(raw);p.chmod(0o600)
            receipt['sourceHashes'][name]=hashlib.sha256(raw).hexdigest()
        self.receipt=self.root/'source-package-receipt.json';self.receipt.write_text(json.dumps(receipt));self.receipt.chmod(0o600)
        self.expected=self.root/'operator.json';self.expected.write_text(json.dumps(dict(schema='ouf.semantic-deployment-package.operator-attestation.v1',packageRoot=str(self.root),receipt=receipt)));self.expected.chmod(0o600)
        self.openssl=Path('/usr/bin/openssl')
    def inventory(self):return probe.inventory(self.root,self.expected,self.openssl)
    def test_real_signature_and_negatives_via_isolated_cli(self):
        files={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        r=subprocess.run([sys.executable,'-I','-B',str(Path(probe.__file__).resolve()),'--package-root',str(self.root),'--operator-attestation',str(self.expected),'--openssl-path',str(self.openssl)],capture_output=True,text=True,timeout=25)
        self.assertEqual(r.returncode,0,r.stdout)
        v=json.loads(r.stdout.splitlines()[0].split('=',1)[1])
        for k in ('ed25519VerificationProven','alteredMessageRejected','alteredSignatureRejected','sourceCustodyVerified','stableAcrossReads'):self.assertIs(v[k],True)
        for k in ('atomicSnapshotProven','deploymentAuthorityProven','startAuthorized','runtimeRegistrationAuthorized'):self.assertIs(v[k],False)
        for k in ('keysGenerated','privateKeysRead','signaturesIssued','providerCalls','dnsCalls','iamCalls'):self.assertEqual(v[k],0)
        self.assertEqual(files,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
    def test_source_drift_blocks_before_execution(self):
        (self.root/'source'/NAMES[0]).write_bytes(b'drift')
        with patch.object(probe,'backend_snapshot',side_effect=AssertionError('must not execute')):
            with self.assertRaisesRegex(RuntimeError,'OPERATOR_SOURCE_PACKAGE_DRIFT'):self.inventory()
    def test_permission_and_symlink_denied(self):
        self.expected.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_TRUST_INPUT_REQUIRED'):self.inventory()
        self.expected.chmod(0o600);p=self.root/'source'/NAMES[0];p.unlink();p.symlink_to(self.receipt)
        with self.assertRaises(OSError):self.inventory()
    def test_duplicate_json_key_denied(self):
        self.expected.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaisesRegex(RuntimeError,'DUPLICATE_TRUST_INPUT_KEY'):self.inventory()
    def test_missing_backend_does_not_grant_authority(self):
        with patch.object(probe,'run',side_effect=AssertionError('must not execute')):
            v=probe.inventory(self.root,self.expected,self.root/'absent-openssl')
        self.assertIs(v['opensslAvailable'],False);self.assertIs(v['ed25519VerificationProven'],False);self.assertIs(v['sourceCustodyVerified'],True);self.assertIs(v['startAuthorized'],False)
    def test_drift_between_reads_denied(self):
        with patch.object(probe,'backend_snapshot',side_effect=[{'opensslHash':'a'},{'opensslHash':'b'}]):
            with self.assertRaisesRegex(RuntimeError,'TRUST_INVENTORY_CHANGED_ACROSS_READS'):self.inventory()
    def test_wrong_operator_root_denied_before_execution(self):
        v=json.loads(self.expected.read_bytes());v['packageRoot']='/different';self.expected.write_text(json.dumps(v))
        with patch.object(probe,'backend_snapshot',side_effect=AssertionError('must not execute')):
            with self.assertRaisesRegex(RuntimeError,'OPERATOR_PACKAGE_ROOT_DRIFT'):self.inventory()
