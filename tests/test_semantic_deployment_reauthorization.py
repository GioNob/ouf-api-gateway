"""Real signatures plus durable journals; no application is started."""
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from tests import test_semantic_deployment_authentication as crypto
from tests import test_semantic_deployment_protocol as protocol
from tools.semantic_provider_deployment_reauthorization import LateAuthenticatedEvidence
from tools.semantic_provider_deployment_consumption import Consumption
from tools.semantic_provider_lease_coordination import PrivateJournal, hold_common_lock
from tools.semantic_provider_preexec import PreexecDenied, digest

@unittest.skipUnless(os.geteuid()==0,'root-private fixture')
class LateEvidenceTest(unittest.TestCase):
    def setUp(self):
        f=self.fixture=crypto.AuthenticationTest();f.setUp();self.addCleanup(f.doCleanups)
        p=self.protocol=protocol.DeploymentProtocolTest();p.setUp()
        self.raws=p.records();records={}
        for key,raw,role,issuer,keyref in zip(('intent','attestation','approval'),self.raws,
                ('DEPLOYMENT_INTENT','CREATION_ATTESTATION','FINAL_DEPLOYMENT_APPROVAL'),
                ('installer-a','verifier-a','installer-a'),('installer-key','verifier-key','installer-key')):
            path=f.root/(key+'.json');path.write_bytes(raw);path.chmod(0o600)
            records[key]={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()};f.sign(raw,role,issuer,keyref)
        binding={'installationRef':'installation-a','entityRef':'entity-a','containerId':'a'*64,
            'transactionId':'b'*64,'intentHash':records['intent']['sha256'],'configurationHash':'c'*64}
        path=f.root/'consumption.json';path.write_text(json.dumps({'schema':'ouf.semantic-deployment-consumption.v1',
            **binding,'state':'STAGED',**dict.fromkeys(('bundleHash','generation','evidenceHash','approvalHash','driverHash'))}));path.chmod(0o600)
        lock=f.root/'guard.lock';lock.touch(mode=0o600)
        self.gate=Consumption(binding,PrivateJournal(path),lambda:hold_common_lock(lock))
        self.gate.authorize_create(self.raws[0],p.ctx,f.verifier,lambda:150)
        self.gate.created('1'*64,p.attestation['generation'])
        self.evidence=self.gate.ready(*self.raws,p.ctx,f.verifier,lambda:150);self.gate.seal_driver('d'*64)
        self.late=LateAuthenticatedEvidence(records,p.ctx,f.policy_binding,f.signature_directory,f.openssl_binding,
            digest(self.evidence),self.evidence['scope'],lambda:150);self.started=[]

    def consume(self):
        def starter():
            self.assertEqual(self.gate.record()['state'],'STARTING');self.started.append(1)
        with self.gate.hold_lock():
            self.gate.consume_locked(digest(self.evidence),'d'*64,self.protocol.attestation['generation'],self.late,starter)

    def test_real_signatures_allow_once_and_deny_replay(self):
        self.consume();self.assertEqual(self.started,[1]);self.assertEqual(self.gate.record()['state'],'STARTED')
        with self.assertRaises(PreexecDenied):self.consume()
        self.assertEqual(self.started,[1])

    def test_revocation_before_claim_preserves_ready(self):
        self.fixture.policy['keys'][0]['state']='REVOKED';self.fixture.write_policy()
        with self.assertRaises(PreexecDenied):self.consume()
        self.assertEqual(self.gate.record()['state'],'READY');self.assertEqual(self.started,[])

    def test_revocation_after_fsync_preserves_starting(self):
        original=self.gate.journal.write
        def revoke(old,new):
            original(old,new)
            if new['state']=='STARTING':
                self.fixture.policy['keys'][0]['state']='REVOKED';self.fixture.write_policy()
        self.gate.journal.write=revoke
        with self.assertRaises(PreexecDenied):self.consume()
        self.assertEqual(self.gate.record()['state'],'STARTING');self.assertEqual(self.started,[])
        with self.assertRaises(PreexecDenied):self.consume()

    def test_earlier_signature_changed_during_later_verification_denied(self):
        original=self.late.verifier.verify;calls=[]
        def change(*args):
            original(*args);calls.append(1)
            if len(calls)==3:
                path=self.fixture.filename(self.raws[0],'DEPLOYMENT_INTENT');path.write_bytes(path.read_bytes()+b' ')
        self.late.verifier.verify=change
        with self.assertRaisesRegex(PreexecDenied,'LATE_SIGNATURE_CHANGED'):self.consume()
        self.assertEqual(self.gate.record()['state'],'READY');self.assertEqual(self.started,[])

    def test_scope_and_evidence_hash_cannot_be_rebound(self):
        self.late.expected_scope['entityRef']='foreign'
        with self.assertRaisesRegex(PreexecDenied,'SEALED_AUTHENTICATED_EVIDENCE_DRIFT'):self.consume()
        self.late.expected_scope=self.evidence['scope'].copy();self.late.evidence_hash='0'*64
        with self.assertRaises(PreexecDenied):self.consume()
        self.assertEqual(self.started,[])

    def test_source_drift_denied_before_native_execution(self):
        path=self.fixture.root/'intent.json';path.write_bytes(path.read_bytes()+b' ')
        with patch.object(self.late.verifier,'verify',side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(PreexecDenied,'LATE_EVIDENCE_SOURCE_DRIFT'):self.consume()
        self.assertEqual(self.gate.record()['state'],'READY')

    def test_local_mandate_expiry_after_final_rereads_denied(self):
        for key in self.fixture.policy['keys']:key['expiresAt']=200
        self.fixture.write_policy()
        self.late.verifier.policy_binding['sha256']=hashlib.sha256(self.fixture.policy_path.read_bytes()).hexdigest()
        values=iter((150,150,150,200));self.late.clock=lambda:next(values)
        with self.assertRaisesRegex(PreexecDenied,'LATE_LOCAL_MANDATE_EXPIRED'):self.consume()
        self.assertEqual(self.started,[]);self.assertEqual(self.gate.record()['state'],'READY')

    def test_expiry_after_final_rereads_denied(self):
        values=iter((150,150,150,240));self.late.clock=lambda:next(values)
        with self.assertRaises(PreexecDenied):self.consume()
        self.assertEqual(self.started,[]);self.assertEqual(self.gate.record()['state'],'READY')

if __name__=='__main__':unittest.main()
