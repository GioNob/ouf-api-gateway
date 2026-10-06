"""Production installer CLI and real OpenSSL; keys/mandates are ephemeral tests."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch
from scripts import semantic_provider_installer_approval as cli
from tests import test_semantic_deployment_authentication as crypto
from tests import test_semantic_deployment_protocol as protocol
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_deployment_producer import LocalEvidenceProducer,encoded
from tools.semantic_provider_deployment_protocol import validate_final
from tools.semantic_provider_installer_approval import InstallerApproval
from tools.semantic_provider_preexec import PreexecDenied,digest

@unittest.skipUnless(os.geteuid()==0,'root-private real issuer fixture')
class InstallerApprovalTest(unittest.TestCase):
    def setUp(self):
        self.crypto=crypto.AuthenticationTest();self.crypto.setUp();self.addCleanup(self.crypto.doCleanups)
        self.p=protocol.DeploymentProtocolTest();self.p.setUp();self.root=self.crypto.root;now=int(time.time())
        self.p.intent.update(issuedAt=now-20,expiresAt=now+240)
        self.p.attestation.update(intentHash=digest(self.p.intent),observedAt=now-5)
        for key in self.crypto.policy['keys']:key.update(notBefore=now-100,expiresAt=now+300)
        self.crypto.write_policy();self.crypto.policy_binding['sha256']=self.sha(self.crypto.policy_path)
        self.crypto.verifier.policy_binding=self.crypto.policy_binding.copy();self.crypto.verifier.clock=time.time
        self.write(self.root/'intent.json',self.p.intent);self.write(self.root/'attestation.json',self.p.attestation)
        self.crypto.sign(encoded(self.p.intent),'DEPLOYMENT_INTENT','installer-a','installer-key')
        self.crypto.sign(encoded(self.p.attestation),'CREATION_ATTESTATION','verifier-a','verifier-key')
        self.mandate={'schema':'ouf.semantic-final-approval-mandate.v1','issuerRef':'installer-a','installationRef':'installation-a',
            'entityRef':'entity-a','intentHash':digest(self.p.intent),**{k:self.p.intent[k] for k in
                ('containerId','transactionId','artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')},
            'approvalRef':'explicit-test-approval','issuedAt':now-10,'expiresAt':now+180,'state':'ACTIVE',
            'issuanceAuthorized':True,'applicationStartAuthorized':True}
        self.write(self.root/'mandate.json',self.mandate)
        self.crypto.sign(encoded(self.mandate),'FINAL_DEPLOYMENT_APPROVAL','installer-a','installer-key')
        source=self.root/'source';source.mkdir(mode=0o700);repository=Path(__file__).resolve().parents[1]
        names=[cli.SELF,*('tools/'+m+'.py' for m in cli.MODULES)]
        for name in names:
            target=source/name;target.parent.mkdir(mode=0o700,exist_ok=True);target.write_bytes((repository/name).read_bytes());target.chmod(0o600)
        python=Path('/usr/bin/python3').resolve()
        self.cfg={'schema':'ouf.semantic-installer-approval-producer.v1','sourceRoot':str(source),'sourceHashes':{n:self.sha(source/n) for n in names},
            'pythonBinding':self.bind(python),'authorities':self.p.ctx,'intentBinding':self.bind(self.root/'intent.json'),
            'attestationPath':str(self.root/'attestation.json'),'approvalMandateBinding':self.bind(self.root/'mandate.json'),
            'policyBinding':self.crypto.policy_binding,'signatureDirectory':str(self.crypto.signature_directory),
            'opensslBinding':self.crypto.openssl_binding,'signingKeyBinding':self.bind(self.crypto.key),'keyRef':'installer-key',
            'brokerEmissionJournal':str(self.root/'broker-emission.json'),'issuanceClaimPath':str(self.root/'signing-claim.json'),'budgetSeconds':12}
        self.path=self.root/'issuer.json';self.refresh()
    def sha(self,path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    def bind(self,path):return {'path':str(path),'sha256':self.sha(path)}
    def write(self,path,value):path.write_bytes(encoded(value));path.chmod(0o600)
    def refresh(self):
        self.write(self.path,self.cfg)
        self.budget=VerificationBudget(18);self.crypto.verifier.budget=self.budget
        self.binding={'python':self.cfg['pythonBinding'],'source':self.bind(Path(self.cfg['sourceRoot'])/cli.SELF),'configuration':self.bind(self.path)}
        self.producer=LocalEvidenceProducer(self.binding,self.p.ctx,self.crypto.verifier,self.budget)
        self.facts={k:self.p.attestation[k] for k in ('containerId','transactionId','intentHash','artifactHash','deploymentConstraintsHash',
            'applicationHash','transportHash','runtimeExecutableHash','generation')}
        self.facts.update(attestationHash=self.sha(self.root/'attestation.json'),creationAcceptanceHash=digest(self.p.attestation['creationAcceptance']))
        request,self.request_raw=self.producer.request('FINAL_DEPLOYMENT_APPROVAL',self.facts)
        self.write(self.root/'broker-emission.json',{'schema':'ouf.semantic-local-producer-emission.v1',**{k:request[k] for k in
            ('role','installationRef','entityRef','issuerRef','containerId','transactionId')},'requestHash':hashlib.sha256(self.request_raw).hexdigest(),
            'producerHash':hashlib.sha256(encoded(self.binding)).hexdigest(),'state':'ISSUING','resultHash':None})
    def core(self):return InstallerApproval(self.cfg,encoded(self.cfg),self.path,self.binding)
    def emit(self):return self.producer.emit('FINAL_DEPLOYMENT_APPROVAL',self.facts)
    def reissue_mandate(self):
        self.write(self.root/'mandate.json',self.mandate);self.crypto.sign(encoded(self.mandate),'FINAL_DEPLOYMENT_APPROVAL','installer-a','installer-key')
        self.cfg['approvalMandateBinding']=self.bind(self.root/'mandate.json');self.refresh()
    def test_real_cli_emits_two_signatures_accepted_by_existing_protocol(self):
        result=self.emit();approval=json.loads(result['record'])
        self.assertEqual(approval['approvalRef'],self.mandate['approvalRef']);self.assertEqual(approval['expiresAt'],self.mandate['expiresAt'])
        signature_path=self.crypto.filename(result['record'],'FINAL_DEPLOYMENT_APPROVAL');signature_path.write_bytes(result['recordSignature']);signature_path.chmod(0o600)
        value=validate_final(encoded(self.p.intent),encoded(self.p.attestation),result['record'],self.p.ctx,self.crypto.verifier)
        self.assertEqual(value['generation'],self.p.attestation['generation']);self.assertEqual(json.loads((self.root/'signing-claim.json').read_bytes())['state'],'ISSUING')
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_DENIED'):self.emit()
    def test_missing_explicit_mandate_never_reads_key_or_claims(self):
        self.mandate['issuanceAuthorized']=False;self.reissue_mandate()
        with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw',side_effect=AssertionError('must not read key')):
            with self.assertRaisesRegex(PreexecDenied,'EXPLICIT_FINAL_APPROVAL_AUTHORITY_REQUIRED'):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_creation_only_intent_cannot_substitute_final_mandate(self):
        self.write(self.root/'mandate.json',self.p.intent);self.cfg['approvalMandateBinding']=self.bind(self.root/'mandate.json');self.refresh()
        with self.assertRaisesRegex(PreexecDenied,'EXACT_FINAL_APPROVAL_MANDATE_REQUIRED'):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_cross_installation_mandate_is_denied(self):
        self.mandate['entityRef']='other-entity';self.reissue_mandate()
        with self.assertRaisesRegex(PreexecDenied,'INSTALLER_MANDATE_INTENT_SCOPE_DRIFT'):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_expired_mandate_is_denied_before_claim(self):
        self.mandate['issuedAt']=int(time.time())-30;self.mandate['expiresAt']=int(time.time())-1;self.reissue_mandate()
        with self.assertRaises(PreexecDenied):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_mandate_exceeding_intent_is_denied(self):
        self.mandate['expiresAt']=self.p.intent['expiresAt']+1;self.reissue_mandate()
        with self.assertRaisesRegex(PreexecDenied,'INSTALLER_MANDATE_EXCEEDS_INTENT'):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_invalid_complete_attestation_blocks_signing(self):
        self.p.attestation['creationAcceptance']['accepted']=False;self.write(self.root/'attestation.json',self.p.attestation)
        self.crypto.sign(encoded(self.p.attestation),'CREATION_ATTESTATION','verifier-a','verifier-key');self.refresh()
        with self.assertRaisesRegex(PreexecDenied,'COMPLETE_CREATION_ACCEPTANCE_REQUIRED'):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_generation_request_drift_blocks_signing(self):
        self.facts['generation']={**self.facts['generation'],'startTicks':99}
        request,raw=self.producer.request('FINAL_DEPLOYMENT_APPROVAL',self.facts)
        value=json.loads((self.root/'broker-emission.json').read_bytes());value['requestHash']=hashlib.sha256(raw).hexdigest();self.write(self.root/'broker-emission.json',value)
        with self.assertRaisesRegex(PreexecDenied,'INSTALLER_ATTESTATION_REQUEST_DRIFT'):self.core().emit(raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_missing_broker_claim_never_reaches_key(self):
        (self.root/'broker-emission.json').unlink()
        with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw',side_effect=AssertionError('must not read key')):
            with self.assertRaises(FileNotFoundError):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_existing_or_uncertain_signer_claim_is_preserved(self):
        self.write(self.root/'signing-claim.json',{'unknown':True});before=(self.root/'signing-claim.json').read_bytes()
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY_INSTALLER_ISSUANCE'):self.core().emit(self.request_raw)
        self.assertEqual((self.root/'signing-claim.json').read_bytes(),before)
    def test_wrong_private_key_fails_with_durable_claim(self):
        other=self.root/'other.pem';subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ED25519','-out',str(other)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);other.chmod(0o600)
        self.cfg['signingKeyBinding']=self.bind(other);self.refresh()
        with self.assertRaisesRegex(PreexecDenied,'SIGNING_KEY_PUBLIC_MANDATE_DRIFT'):self.core().emit(self.request_raw)
        self.assertTrue((self.root/'signing-claim.json').exists())
    def test_key_source_drift_is_denied_and_unknown_claim_not_retried(self):
        self.crypto.key.write_bytes(self.crypto.key.read_bytes()+b'\n')
        with self.assertRaisesRegex(PreexecDenied,'EXISTING_SIGNING_KEY_DRIFT'):self.core().emit(self.request_raw)
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY_INSTALLER_ISSUANCE'):self.core().emit(self.request_raw)
    def test_claim_fsync_failure_does_not_read_key(self):
        with patch('tools.semantic_provider_installer_approval.os.fsync',side_effect=OSError('fixture fsync failure')):
            with patch('tools.semantic_provider_deployment_signing.ExistingEd25519Signer.key_raw',side_effect=AssertionError('must not read')):
                with self.assertRaises(OSError):self.core().emit(self.request_raw)
        self.assertTrue((self.root/'signing-claim.json').exists())
    def test_source_change_and_noncanonical_request_block_before_claim(self):
        with self.assertRaises(PreexecDenied):self.core().emit(self.request_raw+b' ')
        source=Path(self.cfg['sourceRoot'])/'tools/semantic_provider_deployment_signing.py';source.write_bytes(source.read_bytes()+b'\n')
        with self.assertRaisesRegex(PreexecDenied,'INSTALLER_SOURCE_CHANGED'):self.core().emit(self.request_raw)
        self.assertFalse((self.root/'signing-claim.json').exists())
    def test_clock_regression_across_whole_issuance_is_denied(self):
        now=time.time();calls=[0]
        def clock():
            calls[0]+=1
            return now+1 if calls[0]==1 else now
        core=InstallerApproval(self.cfg,encoded(self.cfg),self.path,self.binding,clock)
        with self.assertRaisesRegex(PreexecDenied,'INSTALLER_CLOCK_REGRESSED'):core.emit(self.request_raw)
        self.assertTrue((self.root/'signing-claim.json').exists())
    def test_two_real_cli_processes_cannot_sign_one_claim_twice(self):
        argv=[self.cfg['pythonBinding']['path'],'-I','-B',str(Path(self.cfg['sourceRoot'])/cli.SELF),'--configuration',str(self.path)]
        children=[subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        for child in children:child.stdin.write(self.request_raw);child.stdin.close();child.stdin=None
        results=[child.communicate(timeout=15) for child in children]
        self.assertEqual(sorted(child.returncode for child in children),[0,1])
        successful=results[next(i for i,c in enumerate(children) if c.returncode==0)][0]
        self.assertEqual(json.loads(successful)['schema'],'ouf.semantic-local-producer-result.v1')
        self.assertTrue((self.root/'signing-claim.json').exists())

if __name__=='__main__':unittest.main()
