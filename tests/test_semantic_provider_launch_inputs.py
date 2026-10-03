"""Native private-filesystem/SSL evidence with synthetic credentials and no IAM/provider calls."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts import prepare_semantic_provider_launch_inputs as launch

@unittest.skipUnless(os.geteuid()==0 and shutil.which('openssl'), 'requires root and openssl')
class LaunchInputsTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_LAUNCH_TEST_PARENT',str(Path.cwd())))
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        # Containerized mapped root cannot own the real APISIX role; native CI must.
        probe=self.root/'probe';probe.write_bytes(b'fixture')
        try:os.chown(probe,636,636)
        except OSError:
            if os.environ.get('OUF_LAUNCH_FULL_OWNER_TEST')=='1':raise
            self.skipTest('role UID unavailable here; mandatory native CI')
        self.args=argparse.Namespace(mode='plan',source_commit='b'*40,validator_source_commit='a'*40,
            snapshot_root=self.root/'prepared',credential_root=self.root/'credential',trust_root=self.root/'trust',
            tls_root=self.root/'tls',runtime_root=self.root/'runtime')
        for name in ('credential','trust','tls','runtime'):(self.root/name).mkdir(mode=0o700)
        self.trust={'intent':{'gateway':{'uid':636,'gid':636},'adapterUid':636,'adapterGid':636},'artifactHashes':{}}
        self.tls={'intent':{'runtimeTrustHashes':{}},'outputHashes':{}}
        for role in ('adapter','southbound'):
            folder=self.args.trust_root/role;folder.mkdir(mode=0o700)
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                '-nodes','-days','1','-subj','/CN=fixture','-keyout',str(folder/'server.key'),'-out',str(folder/'server.crt')],
                check=True,capture_output=True)
            (folder/'provider-receipt.key').write_bytes(b'a'*64)
            for name in ('server.key','server.crt','provider-receipt.key'):
                path=folder/name;path.chmod(0o600);os.chown(path,636,636)
                self.trust['artifactHashes'][role+'/'+name]=launch.validator.digest(path.read_bytes())
        self.tls['intent']['runtimeTrustHashes']=dict(self.trust['artifactHashes'])
        for name in ('config.yaml','apisix.yaml'):
            launch.validator.write(self.args.tls_root/name,b'synthetic-private-configuration',636,636)
            self.tls['outputHashes'][name]=launch.validator.digest((self.args.tls_root/name).read_bytes())
        self.binding={'routes':{'oidcSecretRef':'$ENV://CUSTOM_VALIDATOR_SECRET','receiptKeyEnvironment':'CUSTOM_RECEIPT_KEY','audience':'validator'}}
        self.save()
        launch.validator.write(self.args.credential_root/'client-secret',b'synthetic-validator-secret',636,636)
        launch.validator.write(self.args.credential_root/'credential-receipt.json',b'{}')
        self.addCleanup(patch.stopall)
        patch.object(launch.validator,'operate',return_value={'clientProfile':{'clientId':'validator'}}).start()
    def save(self):
        for root,name,value in [(self.args.trust_root,'trust-receipt.json',self.trust),
            (self.args.tls_root,'tls-runtime-receipt.json',self.tls),(self.args.runtime_root,'binding.json',self.binding)]:
            path=root/name
            if path.exists():path.unlink()
            launch.validator.write(path,launch.validator.encoded(value))
    def test_plan_apply_verify_minimal_private_env(self):
        intent=launch.operate(self.args)
        self.assertFalse(self.args.snapshot_root.exists())
        self.assertFalse(intent['offlineCaKeyRead'])
        self.args.mode='apply';launch.operate(self.args)
        env=self.args.snapshot_root/'southbound.env'
        self.assertEqual(env.stat().st_mode & 0o777,0o600)
        self.assertEqual((env.stat().st_uid,env.stat().st_gid),(0,0))
        self.assertEqual(env.read_bytes(),b'CUSTOM_VALIDATOR_SECRET=synthetic-validator-secret\nCUSTOM_RECEIPT_KEY='+b'a'*64+b'\n')
        self.args.mode='verify';launch.operate(self.args)
        env.write_bytes(b'tampered')
        with self.assertRaisesRegex(launch.inputs.Blocked,'LAUNCH_INPUT_CONTENT_DRIFT_NO_OVERWRITE'):launch.operate(self.args)
    def test_leaf_content_tamper_denied(self):
        (self.args.trust_root/'adapter/server.key').write_bytes(b'changed-synthetic-key')
        with self.assertRaisesRegex(launch.inputs.Blocked,'PRIVATE_TRUST_CONTENT_DRIFT'):launch.operate(self.args)
    def test_mismatched_key_pair_denied_even_with_matching_hashes(self):
        key=self.args.trust_root/'adapter/server.key'
        key.write_bytes((self.args.trust_root/'southbound/server.key').read_bytes())
        digest=launch.validator.digest(key.read_bytes())
        self.trust['artifactHashes']['adapter/server.key']=digest
        self.tls['intent']['runtimeTrustHashes']['adapter/server.key']=digest
        self.save()
        with self.assertRaisesRegex(launch.inputs.Blocked,'LEAF_PRIVATE_KEY_PAIR_INVALID'):launch.operate(self.args)
    def test_private_tls_content_and_environment_collision_denied(self):
        path=self.args.tls_root/'apisix.yaml';original=path.read_bytes();path.write_bytes(b'changed')
        with self.assertRaisesRegex(launch.inputs.Blocked,'PRIVATE_TLS_RUNTIME_CONTENT_DRIFT'):launch.operate(self.args)
        path.write_bytes(original)
        self.binding['routes']['receiptKeyEnvironment']='CUSTOM_VALIDATOR_SECRET';self.save()
        with self.assertRaisesRegex(launch.inputs.Blocked,'SECRET_ENVIRONMENT_BINDING_INVALID'):launch.operate(self.args)
    def test_no_overwrite_existing_target(self):
        self.args.snapshot_root.mkdir(mode=0o700)
        self.args.mode='apply'
        with self.assertRaisesRegex(launch.inputs.Blocked,'LAUNCH_INPUT_ROOT_EXISTS_RECONCILE'):launch.operate(self.args)

if __name__=='__main__':unittest.main()
