"""Contract tests with synthetic authenticated producers; no runtime actions."""
import copy
import hashlib
import hmac
import json
import unittest

from tools.semantic_provider_deployment_protocol import validate_intent, validate_final, decode
from tools.semantic_provider_preexec import PreexecDenied, digest


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class DeploymentProtocolTest(unittest.TestCase):
    def setUp(self):
        self.ctx = {'installationRef': 'installation-a', 'entityRef': 'entity-a',
                    'intentIssuerRef': 'installer-a', 'attestorRef': 'verifier-a',
                    'approvalIssuerRef': 'installer-a'}
        self.intent = {'schema': 'ouf.semantic-deployment-intent.v1', 'issuerRef': 'installer-a',
                       'installationRef': 'installation-a', 'entityRef': 'entity-a',
                       'containerId': 'a'*64, 'transactionId': 'b'*64, 'artifactHash': 'c'*64,
                       'deploymentConstraintsHash': 'd'*64, 'transportHash': 'e'*64,
                       'runtimeExecutableHash': 'f'*64, 'issuedAt': 100, 'expiresAt': 250,
                       'infrastructureAuthorized': True, 'creationAuthorized': True,
                       'applicationStartAuthorized': False}
        self.creation = {'schema': 'ouf.semantic-container-creation-acceptance.v1',
                         'containerId': 'a'*64, 'applicationHash': '1'*64,
                         'transportHash': 'e'*64, 'accepted': True}
        self.attestation = {'schema': 'ouf.semantic-created-candidate-attestation.v1',
                            'attestorRef': 'verifier-a', 'installationRef': 'installation-a',
                            'entityRef': 'entity-a', 'intentHash': hashlib.sha256(encoded(self.intent)).hexdigest(),
                            **{k: self.intent[k] for k in ('containerId', 'transactionId', 'artifactHash',
                               'deploymentConstraintsHash', 'transportHash', 'runtimeExecutableHash')},
                            'applicationHash': '1'*64,
                            'generation': {'pid': 1234, 'startTicks': 42, 'namespaceInode': 99},
                            'observedAt': 120, 'creationAcceptance': copy.deepcopy(self.creation)}
        self.approval = {'schema': 'ouf.semantic-deployment-admission-approval.v1',
                         'issuerRef': 'installer-a', 'installationRef': 'installation-a',
                         'entityRef': 'entity-a', 'approvalRef': 'approval-a',
                         'containerId': 'a'*64, 'transactionId': 'b'*64,
                         'applicationHash': '1'*64, 'transportHash': 'e'*64,
                         'creationAcceptanceHash': digest(self.creation), 'issuedAt': 125,
                         'expiresAt': 240, 'state': 'ACTIVE',
                         'infrastructureAuthorized': True, 'applicationStartAuthorized': True}
        # Detached authentication fixture: distinct role credentials within this
        # independent installation. These are not deployed keys or issuer defaults.
        self.keys = {role: (role+'-synthetic-ci-key').encode() for role in
                     ('DEPLOYMENT_INTENT', 'CREATION_ATTESTATION', 'FINAL_DEPLOYMENT_APPROVAL')}
        self.signatures = {}
        self.calls = []

    def signed(self, value, role):
        raw = encoded(value)
        self.signatures[(raw, role)] = hmac.digest(self.keys[role], raw, 'sha256')
        return raw

    def authenticate(self, raw, role, issuer, installation, entity):
        self.calls.append(role)
        expected = {'DEPLOYMENT_INTENT': 'installer-a', 'CREATION_ATTESTATION': 'verifier-a',
                    'FINAL_DEPLOYMENT_APPROVAL': 'installer-a'}
        if (issuer, installation, entity) != (expected[role], 'installation-a', 'entity-a'):
            return False
        return hmac.compare_digest(self.signatures.get((raw, role), b''),
                                   hmac.digest(self.keys[role], raw, 'sha256'))

    def records(self):
        return (self.signed(self.intent, 'DEPLOYMENT_INTENT'),
                self.signed(self.attestation, 'CREATION_ATTESTATION'),
                self.signed(self.approval, 'FINAL_DEPLOYMENT_APPROVAL'))

    def final(self, **kw):
        return validate_final(*self.records(), kw.get('ctx', self.ctx),
                              kw.get('authenticate', self.authenticate), lambda: kw.get('now', 150))

    def test_valid_two_phase_evidence_retains_generation_and_compatible_receipt(self):
        value = self.final()
        self.assertEqual(self.calls, ['DEPLOYMENT_INTENT', 'CREATION_ATTESTATION', 'FINAL_DEPLOYMENT_APPROVAL'])
        self.assertEqual(value['generation'], self.attestation['generation'])
        self.assertEqual(value['scope']['creationAcceptanceHash'], hashlib.sha256(encoded(value['creationAcceptance'])).hexdigest())
        self.assertEqual(value['scope']['applicationHash'], '1'*64)
        self.assertNotIn('startAuthorized', value)
        self.assertNotIn('applicationHash', self.intent)

    def test_initial_intent_never_authorizes_application_execution(self):
        for field, value in [('applicationStartAuthorized', True), ('creationAuthorized', False),
                             ('infrastructureAuthorized', False), ('creationAuthorized', 1)]:
            with self.subTest(field=field, value=value):
                changed = {**self.intent, field: value}
                with self.assertRaises(PreexecDenied):
                    validate_intent(self.signed(changed, 'DEPLOYMENT_INTENT'), self.ctx, self.authenticate, lambda: 150)

    def framed(self):
        self.creation.update(schema='ouf.semantic-container-creation-acceptance.v2',
                             artifactHash=self.intent['artifactHash'],creationFrameHash='2'*64)
        self.attestation.update(schema='ouf.semantic-created-candidate-attestation.v2',
                                creationAcceptance=copy.deepcopy(self.creation))
        self.approval['creationAcceptanceHash']=digest(self.creation)

    def test_signed_frame_is_retained_in_final_evidence(self):
        self.framed()
        self.assertEqual(self.final()['creationAcceptance'],self.creation)

    def test_framed_evidence_cannot_mix_or_downgrade_schemas(self):
        for outer,inner in [('v1','v2'),('v2','v1')]:
            self.framed()
            self.attestation['schema']='ouf.semantic-created-candidate-attestation.'+outer
            self.attestation['creationAcceptance']['schema']='ouf.semantic-container-creation-acceptance.'+inner
            self.approval['creationAcceptanceHash']=digest(self.attestation['creationAcceptance'])
            with self.subTest(outer=outer,inner=inner),self.assertRaises(PreexecDenied):self.final()

    def test_framed_evidence_requires_exact_signed_artifact_and_frame_hash(self):
        for field,value in [('artifactHash','9'*64),('creationFrameHash',None),('creationFrameHash','invalid')]:
            self.framed()
            self.attestation['creationAcceptance'][field]=value
            self.approval['creationAcceptanceHash']=digest(self.attestation['creationAcceptance'])
            with self.subTest(field=field,value=value),self.assertRaises(PreexecDenied):self.final()

    def test_another_independent_installation_cannot_consume_evidence(self):
        for field in self.ctx:
            with self.subTest(field=field), self.assertRaises(PreexecDenied):
                self.final(ctx={**self.ctx, field: 'other'})

    def test_unconfigured_and_wrong_role_producers_are_denied(self):
        intent, attestation, approval = self.records()
        self.signatures[(attestation, 'CREATION_ATTESTATION')] = self.signatures[(intent, 'DEPLOYMENT_INTENT')]
        with self.assertRaisesRegex(PreexecDenied, 'AUTHENTICATION'):
            validate_final(intent, attestation, approval, self.ctx, self.authenticate, lambda: 150)
        for callback in (None, lambda *args: 1, lambda *args: 'true', lambda *args: False):
            with self.assertRaises(PreexecDenied): self.final(authenticate=callback)

    def test_tampered_authenticated_bytes_are_denied(self):
        intent, attestation, approval = self.records()
        changed = encoded({**self.attestation, 'generation': {'pid': 9999, 'startTicks': 42, 'namespaceInode': 99}})
        with self.assertRaisesRegex(PreexecDenied, 'AUTHENTICATION'):
            validate_final(intent, changed, approval, self.ctx, self.authenticate, lambda: 150)

    def test_attestor_cannot_change_approved_artifact_constraints_or_transport(self):
        original = copy.deepcopy(self.attestation)
        for key in ('containerId', 'transactionId', 'artifactHash', 'deploymentConstraintsHash',
                    'transportHash', 'runtimeExecutableHash', 'intentHash'):
            self.attestation = {**original, key: '9'*64}
            with self.subTest(key=key), self.assertRaises(PreexecDenied): self.final()

    def test_complete_oci_change_invalidates_final_approval(self):
        self.attestation['applicationHash'] = '9'*64
        self.attestation['creationAcceptance']['applicationHash'] = '9'*64
        with self.assertRaises(PreexecDenied): self.final()

    def test_forged_or_incomplete_creation_acceptance_is_denied(self):
        original = copy.deepcopy(self.creation)
        for key, value in [('accepted', False), ('accepted', 1), ('containerId', '9'*64),
                           ('transportHash', '9'*64), ('extra', True)]:
            self.attestation['creationAcceptance'] = {**original, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(PreexecDenied): self.final()

    def test_approval_requires_actual_creation_time_and_cannot_extend_intent(self):
        for issued, expires in ((119, 200), (160, 200), (125, 251), (125, 150)):
            self.approval.update(issuedAt=issued, expiresAt=expires)
            with self.subTest(issued=issued, expires=expires), self.assertRaises(PreexecDenied): self.final()

    def test_intent_expiry_future_or_unbounded_validity_is_denied(self):
        for issued, expires in ((151, 250), (100, 150), (100, 401)):
            self.intent.update(issuedAt=issued, expiresAt=expires)
            with self.subTest(issued=issued, expires=expires), self.assertRaises(PreexecDenied): self.final()

    def test_created_generation_requires_exact_positive_integer_fields(self):
        for generation in ({'pid': 1, 'startTicks': 42, 'namespaceInode': 99},
                           {'pid': True, 'startTicks': 42, 'namespaceInode': 99},
                           {'pid': 1234, 'startTicks': 0, 'namespaceInode': 99},
                           {'pid': 1234, 'startTicks': 42},
                           {'pid': 1234, 'startTicks': 42, 'namespaceInode': 99, 'extra': 1}):
            self.attestation['generation'] = generation
            with self.subTest(generation=generation), self.assertRaises(PreexecDenied): self.final()

    def test_observation_must_follow_intent_and_precede_current_time(self):
        for observed in (99, 151, True):
            self.attestation['observedAt'] = observed
            with self.subTest(observed=observed), self.assertRaises(PreexecDenied): self.final()

    def test_duplicate_unbounded_nonfinite_and_deep_records_are_denied(self):
        for raw in (b'{"x":1,"x":2}', b' '*131073, b'{"x":NaN}',
                    b'['*2000+b']'*2000, b'[]', b'\xff'):
            with self.subTest(length=len(raw)), self.assertRaises(PreexecDenied): decode(raw)

    def test_returned_evidence_is_detached_from_callers_objects(self):
        result = self.final()
        result['generation']['pid'] = 9999
        result['creationAcceptance']['accepted'] = False
        self.assertEqual(self.final()['generation']['pid'], 1234)
        self.assertIs(self.creation['accepted'], True)

    def test_revocation_of_final_approval_is_denied(self):
        self.approval['state'] = 'REVOKED'
        with self.assertRaises(PreexecDenied): self.final()

    def test_expiry_during_external_authentication_is_denied(self):
        for finished in (240, 250, 149):
            samples = iter((150, finished))
            with self.subTest(finished=finished), self.assertRaises(PreexecDenied):
                validate_final(*self.records(), self.ctx, self.authenticate, lambda: next(samples))

    def test_self_declared_issuer_and_extra_fields_cannot_extend_trust(self):
        self.intent['issuerRef'] = 'self-declared'
        with self.assertRaises(PreexecDenied): self.final()
        self.intent['issuerRef'] = 'installer-a'
        self.intent['applicationHash'] = '1'*64
        with self.assertRaises(PreexecDenied): self.final()

    def test_creation_intent_expiry_during_authentication_is_denied(self):
        for finished in (250, 149):
            samples = iter((150, finished))
            with self.subTest(finished=finished), self.assertRaises(PreexecDenied):
                validate_intent(self.signed(self.intent, 'DEPLOYMENT_INTENT'),
                                self.ctx, self.authenticate, lambda: next(samples))


if __name__ == '__main__': unittest.main()
