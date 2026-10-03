"""Real private filesystem, simulated IAM; no actual credentials or provider calls."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import prepare_semantic_southbound_validator_credentials as helper

@unittest.skipUnless(os.geteuid()==0, 'requires real root-owned filesystem')
class ValidatorCredentialTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_VALIDATOR_TEST_PARENT', str(Path.cwd())))
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.args=argparse.Namespace(mode='plan', source_commit='a'*40, credential_root=self.root/'prepared',
            trust_root=self.root/'trust', tls_root=self.root/'tls', runtime_root=self.root/'runtime',
            docker_path='/usr/bin/docker', iam_container='keycloak', kcadm_path='/opt/keycloak/bin/kcadm.sh', realm='test')
        for folder,name,value in [('trust','trust-receipt.json',{'intent':{'gateway':{'uid':636,'gid':636}}}),
            ('tls','tls-runtime-receipt.json',{}),('runtime','stage-receipt.json',{})]:
            directory=self.root/folder;directory.mkdir(mode=0o700)
            helper.write(directory/name,helper.encoded(value))
        self.row={'id':'test-id','clientId':'validator','enabled':True,'publicClient':False,
            'serviceAccountsEnabled':False,'clientAuthenticatorType':'client-secret'}
        self.secret='synthetic-test-secret-123456'
        self.calls=[]
        def iam(args,resource,fields,query=None):
            self.calls.append(resource)
            return [dict(self.row)] if resource=='clients' else {'value':self.secret}
        self.addCleanup(patch.stopall)
        patch.object(helper.inputs,'inventory',return_value={'oidcClient':{'clientId':'validator'}}).start()
        patch.object(helper,'read_iam',side_effect=iam).start()
    def test_plan_only_reads_metadata_and_creates_nothing(self):
        result=helper.operate(self.args)
        self.assertFalse(result['clientProfile']['serviceAccountsEnabled'])
        self.assertEqual(self.calls,['clients'])
        self.assertFalse(self.args.credential_root.exists())
    def test_apply_verify_private_copy_and_role_ownership(self):
        self.require_role_ownership()
        self.args.mode='apply';helper.operate(self.args)
        target=self.args.credential_root/'client-secret'
        self.assertEqual((target.stat().st_uid,target.stat().st_gid,target.stat().st_mode & 0o777),(636,636,0o600))
        self.assertEqual(target.read_text(),self.secret)
        self.assertEqual(self.args.credential_root.stat().st_mode & 0o777,0o700)
        self.args.mode='verify';helper.operate(self.args)
        self.assertTrue(all(x in ('clients','clients/test-id/client-secret') for x in self.calls))
    def test_changed_iam_secret_refuses_overwrite(self):
        self.require_role_ownership()
        self.args.mode='apply';helper.operate(self.args)
        original=(self.args.credential_root/'client-secret').read_bytes()
        self.secret='changed-synthetic-secret-123456'
        self.args.mode='verify'
        with self.assertRaisesRegex(helper.Blocked,'PRIVATE_CREDENTIAL_DRIFT_NO_OVERWRITE'):helper.operate(self.args)
        self.assertEqual((self.args.credential_root/'client-secret').read_bytes(),original)
    def test_existing_root_and_tampered_intent_denied(self):
        self.require_role_ownership()
        self.args.mode='apply';helper.operate(self.args)
        with self.assertRaisesRegex(helper.Blocked,'CREDENTIAL_ROOT_EXISTS_RECONCILE'):helper.operate(self.args)
        (self.args.credential_root/'credential-intent.json').write_text('{}')
        self.args.mode='verify'
        with self.assertRaisesRegex(helper.Blocked,'PRIVATE_RECEIPT_DRIFT'):helper.operate(self.args)
    def test_bad_secret_and_public_client_denied_without_secret_in_error(self):
        self.args.mode='apply';self.secret='sensitive\nvalue'
        with self.assertRaisesRegex(helper.Blocked,'^VALIDATOR_CREDENTIAL_INVALID$'):helper.operate(self.args)
        self.assertFalse(self.args.credential_root.exists())
        self.row['publicClient']=True
        with self.assertRaisesRegex(helper.Blocked,'VALIDATOR_CLIENT_PROFILE_DRIFT'):helper.operate(self.args)
    def require_role_ownership(self):
        probe=self.root/'ownership-probe';probe.write_bytes(b'fixture')
        try:os.chown(probe,636,636)
        except OSError:
            if os.environ.get('OUF_VALIDATOR_FULL_OWNER_TEST')=='1':raise
            self.skipTest('runtime cannot map role UID/GID; native CI requires this test')

if __name__=='__main__':unittest.main()
