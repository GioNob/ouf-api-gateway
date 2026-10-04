"""Real detached verification; signing keys are ephemeral CI fixtures only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import semantic_provider_deployment_authentication as auth
from tools.semantic_provider_deployment_protocol import validate_final
from tools.semantic_provider_preexec import PreexecDenied
from tests import test_semantic_deployment_protocol as fixtures


@unittest.skipUnless(os.geteuid() == 0, 'root-private verification fixture')
class AuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(
            dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT', str(Path.cwd()))))).resolve()
        self.root.chmod(0o700); self.signature_directory = self.root/'signatures'
        self.signature_directory.mkdir(mode=0o700)
        self.openssl = Path('/usr/bin/openssl'); self.key = self.root/'ci-private.pem'
        subprocess.run([str(self.openssl),'genpkey','-algorithm','ED25519','-out',str(self.key)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        self.key.chmod(0o600)
        public = subprocess.run([str(self.openssl),'pkey','-in',str(self.key),'-pubout','-outform','DER'],
            check=True,capture_output=True,timeout=3).stdout
        self.assertEqual(public[:12],auth.DER_PREFIX)
        self.ctx = {'installationRef':'installation-a','entityRef':'entity-a',
                    'intentIssuerRef':'installer-a','attestorRef':'verifier-a','approvalIssuerRef':'installer-a'}
        self.policy_path = self.root/'trust.json'
        self.policy = {'schema':'ouf.semantic-deployment-trust-policy.v1',
            'installationRef':'installation-a','entityRef':'entity-a','keys':[
                {'keyRef':'installer-key','issuerRef':'installer-a','roles':['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'],
                 'publicKey':public[12:].hex(),'notBefore':50,'expiresAt':300,'state':'ACTIVE'},
                {'keyRef':'verifier-key','issuerRef':'verifier-a','roles':['CREATION_ATTESTATION'],
                 'publicKey':public[12:].hex(),'notBefore':50,'expiresAt':300,'state':'ACTIVE'}]}
        self.write_policy()
        self.policy_binding = {'path':str(self.policy_path),'sha256':hashlib.sha256(self.policy_path.read_bytes()).hexdigest()}
        self.openssl_binding = {'path':str(self.openssl),'sha256':hashlib.sha256(self.openssl.read_bytes()).hexdigest()}
        self.verifier = auth.DetachedAuthenticator(self.policy_binding,self.signature_directory,self.openssl_binding,lambda:150)
        self.raw = b'{"payload":"exact synthetic CI evidence"}'
        self.sign(self.raw,'DEPLOYMENT_INTENT','installer-a','installer-key')

    def write_policy(self):
        self.policy_path.write_text(json.dumps(self.policy)); self.policy_path.chmod(0o600)

    def filename(self,raw,role):
        return self.signature_directory/(hashlib.sha256(raw).hexdigest()+'.'+role+'.json')

    def sign(self,raw,role,issuer,key_ref):
        header = {'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
            'keyRef':key_ref,'role':role,'issuerRef':issuer,'installationRef':'installation-a',
            'entityRef':'entity-a','payloadHash':hashlib.sha256(raw).hexdigest()}
        # Independent fixture producer implements the documented framing.
        canonical=json.dumps(header,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        frame=b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'+len(canonical).to_bytes(4,'big')+canonical+len(raw).to_bytes(4,'big')+raw
        source=self.root/'ci-frame.bin';source.write_bytes(frame);source.chmod(0o600)
        signature=subprocess.run([str(self.openssl),'pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(source)],
            check=True,capture_output=True,timeout=3).stdout
        self.assertEqual(len(signature),64)
        record={**header,'signature':signature.hex()};path=self.filename(raw,role)
        path.write_text(json.dumps(record));path.chmod(0o600);return record

    def verify(self,raw=None,role='DEPLOYMENT_INTENT',issuer='installer-a',installation='installation-a',entity='entity-a'):
        return self.verifier(self.raw if raw is None else raw,role,issuer,installation,entity)

    def test_real_three_role_protocol_integration_without_default_authority(self):
        fixture=fixtures.DeploymentProtocolTest();fixture.setUp()
        raws=[fixtures.encoded(v) for v in (fixture.intent,fixture.attestation,fixture.approval)]
        for raw,role,issuer,key in zip(raws,['DEPLOYMENT_INTENT','CREATION_ATTESTATION','FINAL_DEPLOYMENT_APPROVAL'],
                ['installer-a','verifier-a','installer-a'],['installer-key','verifier-key','installer-key']):
            self.sign(raw,role,issuer,key)
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        value=validate_final(*raws,self.ctx,self.verifier,lambda:150)
        self.assertEqual(value['generation'],fixture.attestation['generation'])
        self.assertNotIn('startAuthorized',value)
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_altered_signature_and_payload_rejected_by_real_crypto(self):
        path=self.filename(self.raw,'DEPLOYMENT_INTENT');record=json.loads(path.read_bytes())
        record['signature']=('00' if record['signature'][:2]!='00' else '01')+record['signature'][2:]
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(PreexecDenied,'DETACHED_SIGNATURE_INVALID'):self.verify()
        record=self.sign(self.raw,'DEPLOYMENT_INTENT','installer-a','installer-key')
        changed=self.raw+b' ';record['payloadHash']=hashlib.sha256(changed).hexdigest()
        path=self.filename(changed,'DEPLOYMENT_INTENT');path.write_text(json.dumps(record));path.chmod(0o600)
        with self.assertRaisesRegex(PreexecDenied,'DETACHED_SIGNATURE_INVALID'):self.verify(changed)

    def test_role_cannot_be_relabelled_using_same_issuer_key(self):
        record=json.loads(self.filename(self.raw,'DEPLOYMENT_INTENT').read_bytes());record['role']='FINAL_DEPLOYMENT_APPROVAL'
        path=self.filename(self.raw,'FINAL_DEPLOYMENT_APPROVAL');path.write_text(json.dumps(record));path.chmod(0o600)
        with self.assertRaisesRegex(PreexecDenied,'DETACHED_SIGNATURE_INVALID'):self.verify(role='FINAL_DEPLOYMENT_APPROVAL')

    def test_other_installation_entity_or_issuer_denied(self):
        for scope in ({'installation':'other'},{'entity':'other'},{'issuer':'other'}):
            with self.subTest(scope=scope),self.assertRaises(PreexecDenied):self.verify(**scope)

    def test_unprovisioned_or_revoked_key_denied(self):
        self.policy['keys'][0]['state']='REVOKED';self.write_policy()
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_TRUST_POLICY_REVOKED_OR_CHANGED'):self.verify()
        binding={**self.policy_binding,'sha256':hashlib.sha256(self.policy_path.read_bytes()).hexdigest()}
        self.verifier=auth.DetachedAuthenticator(binding,self.signature_directory,self.openssl_binding,lambda:150)
        with self.assertRaisesRegex(PreexecDenied,'ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED'):self.verify()

    def test_expiry_after_real_verification_denied(self):
        values=iter((150,300));self.verifier.clock=lambda:next(values)
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_MANDATE_EXPIRED_OR_CLOCK_REGRESSED'):self.verify()

    def test_revocation_during_verification_denied(self):
        original=self.verifier.verify
        def revoke(*args):
            original(*args);self.policy['keys'][0]['state']='REVOKED';self.write_policy()
        self.verifier.verify=revoke
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_TRUST_POLICY_REVOKED_OR_CHANGED'):self.verify()

    def test_changed_signature_after_verification_denied(self):
        original=self.verifier.verify;path=self.filename(self.raw,'DEPLOYMENT_INTENT')
        def change(*args):original(*args);path.write_bytes(path.read_bytes()+b' ')
        self.verifier.verify=change
        with self.assertRaisesRegex(PreexecDenied,'AUTHENTICATION_REVOKED_DURING_VERIFICATION'):self.verify()

    def test_bounded_inputs_and_private_permissions_before_native_execution(self):
        with patch.object(self.verifier,'verify',side_effect=AssertionError('must not execute')):
            with self.assertRaises(PreexecDenied):self.verify(b'a'*131073)
            path=self.filename(self.raw,'DEPLOYMENT_INTENT');path.chmod(0o644)
            with self.assertRaises(PreexecDenied):self.verify()
            path.chmod(0o600);path.write_bytes(b'a'*4097)
            with self.assertRaises(PreexecDenied):self.verify()

    def test_backend_drift_timeout_and_duplicate_policy_denied(self):
        self.verifier.openssl_binding['sha256']='0'*64
        with self.assertRaisesRegex(PreexecDenied,'AUTHENTICATION_EXECUTABLE_DRIFT'):self.verify()
        self.verifier.openssl_binding=self.openssl_binding
        with patch.object(auth.subprocess,'run',side_effect=subprocess.TimeoutExpired('public verifier',2)):
            with self.assertRaisesRegex(PreexecDenied,'DETACHED_VERIFICATION_UNPROVEN'):self.verify()
        with self.assertRaisesRegex(PreexecDenied,'DUPLICATE_AUTHENTICATION_KEY'):
            auth.policy(b'{"schema":1,"schema":2}','installation-a','entity-a',150)

    def test_no_default_policy_key_or_role_grant(self):
        self.policy['keys'][0]['roles']=['FINAL_DEPLOYMENT_APPROVAL'];self.write_policy()
        binding={**self.policy_binding,'sha256':hashlib.sha256(self.policy_path.read_bytes()).hexdigest()}
        self.verifier=auth.DetachedAuthenticator(binding,self.signature_directory,self.openssl_binding,lambda:150)
        with self.assertRaisesRegex(PreexecDenied,'ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED'):self.verify()
        self.policy['keys']=[];self.write_policy()
        self.verifier.policy_binding['sha256']=hashlib.sha256(self.policy_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_LOCAL_TRUST_POLICY_REQUIRED'):self.verify()

    def test_unknown_or_malformed_signature_frames_never_select_backend(self):
        for field,value in [('algorithm','none'),('keyRef','unprovisioned'),('payloadHash','0'*64)]:
            with self.subTest(field=field):
                record=self.sign(self.raw,'DEPLOYMENT_INTENT','installer-a','installer-key');record[field]=value
                self.filename(self.raw,'DEPLOYMENT_INTENT').write_text(json.dumps(record))
                with patch.object(self.verifier,'verify',side_effect=AssertionError('must not execute')):
                    with self.assertRaises(PreexecDenied):self.verify()

    def test_signature_symlink_and_directory_permissions_rejected(self):
        path=self.filename(self.raw,'DEPLOYMENT_INTENT');path.unlink();path.symlink_to(self.policy_path)
        with self.assertRaises(OSError):self.verify()
        self.signature_directory.chmod(0o755)
        with self.assertRaisesRegex(PreexecDenied,'PRIVATE_SIGNATURE_DIRECTORY_REQUIRED'):
            auth.DetachedAuthenticator(self.policy_binding,self.signature_directory,self.openssl_binding)


if __name__=='__main__':unittest.main()
