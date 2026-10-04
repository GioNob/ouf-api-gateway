"""Real subprocess transport and two signatures; ephemeral test keys only."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from tests import test_semantic_deployment_authentication as crypto
from tests import test_semantic_deployment_protocol as protocol
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_deployment_producer import LocalEvidenceProducer, encoded
from tools.semantic_provider_deployment_protocol import validate_final
from tools.semantic_provider_preexec import PreexecDenied, digest

@unittest.skipUnless(os.geteuid()==0,'root-private local producer fixture')
class ProducerTest(unittest.TestCase):
    def setUp(self):
        self.fixture=crypto.AuthenticationTest();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.protocol=protocol.DeploymentProtocolTest();self.protocol.setUp()
        self.budget=VerificationBudget(5);self.fixture.verifier.budget=self.budget
        self.role='CREATION_ATTESTATION';self.facts=self.facts_for(self.role)
        self.producer=self.configured(self.role,self.facts)

    def facts_for(self,role):
        p=self.protocol
        facts={k:p.attestation[k] for k in ('containerId','transactionId','intentHash','artifactHash','deploymentConstraintsHash',
            'applicationHash','transportHash','runtimeExecutableHash','generation')}
        if role=='FINAL_DEPLOYMENT_APPROVAL':
            facts.update(attestationHash=hashlib.sha256(encoded(p.attestation)).hexdigest(),creationAcceptanceHash=digest(p.creation))
        return copy.deepcopy(facts)

    def response(self,role,facts,record=None):
        issuer='verifier-a' if role=='CREATION_ATTESTATION' else 'installer-a'
        key='verifier-key' if role=='CREATION_ATTESTATION' else 'installer-key'
        record=record if record is not None else (self.protocol.attestation if role=='CREATION_ATTESTATION' else self.protocol.approval)
        raw=encoded(record);sig=self.fixture.sign(raw,role,issuer,key)
        request=encoded({'schema':'ouf.semantic-local-producer-request.v1','role':role,
            'installationRef':'installation-a','entityRef':'entity-a','issuerRef':issuer,**facts})
        manifest=encoded({'schema':'ouf.semantic-local-producer-binding.v1','requestHash':hashlib.sha256(request).hexdigest(),
            'recordHash':hashlib.sha256(raw).hexdigest(),'recordSignatureHash':hashlib.sha256(encoded(sig)).hexdigest()})
        return {'schema':'ouf.semantic-local-producer-result.v1','recordBase64':base64.b64encode(raw).decode(),
            'recordSignature':sig,'bindingSignature':self.fixture.sign(manifest,role,issuer,key)}

    def configured(self,role,facts,source=None,response=None):
        root=self.fixture.root;name=role.lower()
        self.source=root/(name+'.py');self.config=root/(name+'.json')
        self.source.write_text(source or "import sys\nfrom pathlib import Path\nsys.stdin.buffer.read(4097)\nsys.stdout.buffer.write(Path(sys.argv[2]).read_bytes())\n");self.source.chmod(0o600)
        self.config.write_bytes(encoded(response or self.response(role,facts)));self.config.chmod(0o600)
        python=Path('/usr/bin/python3').resolve()
        bindings={k:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
            for k,p in [('python',python),('source',self.source),('configuration',self.config)]}
        return LocalEvidenceProducer(bindings,self.fixture.ctx,self.fixture.verifier,self.budget)

    def emit(self):return self.producer.emit(self.role,self.facts)

    def test_real_two_producers_feed_existing_three_role_protocol(self):
        att=self.emit();self.assertEqual(att['record'],encoded(self.protocol.attestation))
        approval=self.configured('FINAL_DEPLOYMENT_APPROVAL',self.facts_for('FINAL_DEPLOYMENT_APPROVAL')).emit(
            'FINAL_DEPLOYMENT_APPROVAL',self.facts_for('FINAL_DEPLOYMENT_APPROVAL'))
        intent=encoded(self.protocol.intent);self.fixture.sign(intent,'DEPLOYMENT_INTENT','installer-a','installer-key')
        evidence=validate_final(intent,att['record'],approval['record'],self.fixture.ctx,self.fixture.verifier,lambda:150)
        self.assertEqual(evidence['generation'],self.protocol.attestation['generation']);self.assertNotIn('startAuthorized',evidence)

    def test_unsigned_request_hash_change_cannot_reuse_reply(self):
        self.facts['intentHash']='0'*64
        with self.assertRaises(PreexecDenied):self.emit()

    def test_binding_signature_altered_is_denied(self):
        reply=self.response(self.role,self.facts);reply['bindingSignature']['signature']='0'*128
        self.producer=self.configured(self.role,self.facts,response=reply)
        with self.assertRaises(PreexecDenied):self.emit()

    def test_wrong_signed_record_scope_denied_even_with_valid_request_binding(self):
        record=copy.deepcopy(self.protocol.attestation);record['containerId']='0'*64
        self.producer=self.configured(self.role,self.facts,response=self.response(self.role,self.facts,record))
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_RECORD_SCOPE_DRIFT'):self.emit()

    def test_missing_role_mandate_blocks_before_invocation(self):
        self.fixture.policy['keys'][1]['roles']=['FINAL_DEPLOYMENT_APPROVAL'];self.fixture.write_policy()
        self.fixture.verifier.policy_binding['sha256']=hashlib.sha256(self.fixture.policy_path.read_bytes()).hexdigest()
        with patch.object(self.producer,'invoke',side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(PreexecDenied,'EXPLICIT_ACTIVE_LOCAL_PRODUCER_MANDATE_REQUIRED'):self.emit()

    def test_unknown_role_and_extra_fields_never_invoke(self):
        with patch.object(self.producer,'invoke',side_effect=AssertionError('must not run')):
            with self.assertRaises(PreexecDenied):self.producer.emit('DEPLOYMENT_INTENT',self.facts)
            with self.assertRaises(PreexecDenied):self.producer.emit(self.role,{**self.facts,'command':'untrusted'})

    def test_source_drift_blocks_before_invocation(self):
        self.source.write_bytes(self.source.read_bytes()+b'\n')
        with patch.object(self.producer,'invoke',side_effect=AssertionError('must not run')):
            with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_SOURCE_OR_CONFIGURATION_DRIFT'):self.emit()

    def test_configuration_changed_during_execution_denied(self):
        source="import sys\nfrom pathlib import Path\np=Path(sys.argv[2]);raw=p.read_bytes();p.write_bytes(raw+b' ');sys.stdout.buffer.write(raw)\n"
        self.producer=self.configured(self.role,self.facts,source=source)
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_SOURCE_OR_CONFIGURATION_DRIFT'):self.emit()

    def test_nonzero_diagnostics_are_redacted(self):
        self.producer=self.configured(self.role,self.facts,source="import sys\nprint('SYNTHETIC_PRIVATE_DIAGNOSTIC',file=sys.stderr);sys.exit(9)\n")
        with self.assertRaises(PreexecDenied) as error:self.emit()
        self.assertEqual(str(error.exception),'LOCAL_PRODUCER_DENIED')

    def test_output_flood_is_bounded_and_process_stopped(self):
        self.producer=self.configured(self.role,self.facts,source="import sys\nfor _ in range(512):sys.stdout.buffer.write(b'x'*65536)\n")
        with self.assertRaisesRegex(PreexecDenied,'LOCAL_PRODUCER_OUTPUT_UNBOUNDED'):self.emit()

    def test_hanging_producer_has_one_deadline(self):
        self.budget=VerificationBudget(1);self.fixture.verifier.budget=self.budget
        self.producer=self.configured(self.role,self.facts,source="import time\ntime.sleep(20)\n")
        with self.assertRaises(PreexecDenied):self.emit()

    def test_different_verifier_budget_cannot_extend_operation(self):
        with self.assertRaisesRegex(PreexecDenied,'SHARED_PRODUCER_VERIFICATION_DEADLINE_REQUIRED'):
            LocalEvidenceProducer(self.producer.configured,self.fixture.ctx,self.fixture.verifier,VerificationBudget(5))

if __name__=='__main__':unittest.main()
