"""Reauthenticate sealed evidence immediately around durable consumption.

Caller holds the existing common guard/lease lock. This callback performs no
publication, signing, runtime operation, lock acquisition or authority grant.
The caller supplies the expected evidence and scope from its sealed driver.
"""
import copy
import hashlib
from pathlib import Path
import time

from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, binding, private_bytes, decode, policy as trust_policy
from tools.semantic_provider_deployment_protocol import validate_final, hashed
from tools.semantic_provider_preexec import PreexecDenied, digest


def require(value, reason):
    if not value:
        raise PreexecDenied(reason)


class LateAuthenticatedEvidence:
    def __init__(self, records, authorities, policy_binding, signature_directory,
                 openssl_binding, evidence_hash, expected_scope, clock=time.time, budget=None):
        require(type(records) is dict and set(records) == {'intent', 'attestation', 'approval'},
                'EXACT_LATE_EVIDENCE_RECORDS_REQUIRED')
        require(hashed(evidence_hash) and type(expected_scope) is dict,
                'SEALED_LATE_EVIDENCE_REQUIRED')
        self.records = {key: binding(value) for key, value in records.items()}
        self.authorities = copy.deepcopy(authorities)
        self.expected_scope = copy.deepcopy(expected_scope)
        self.evidence_hash = evidence_hash
        self.clock = clock
        self.verifier = DetachedAuthenticator(policy_binding, signature_directory, openssl_binding, clock, budget)

    def __call__(self):
        self.verifier.check_budget()
        started = self.clock()
        raws = []
        for key in ('intent', 'attestation', 'approval'):
            record = self.records[key]
            raw = private_bytes(Path(record['path']))
            require(hashlib.sha256(raw).hexdigest() == record['sha256'], 'LATE_EVIDENCE_SOURCE_DRIFT')
            raws.append(raw)
        signatures = []
        for raw, role in zip(raws, ('DEPLOYMENT_INTENT', 'CREATION_ATTESTATION', 'FINAL_DEPLOYMENT_APPROVAL')):
            path = self.verifier.signature_directory / (hashlib.sha256(raw).hexdigest()+'.'+role+'.json')
            signatures.append((path, private_bytes(path, 4096)))
        policy = self.verifier.read_policy()
        evidence = validate_final(*raws, self.authorities, self.verifier, self.clock)
        require(digest(evidence) == self.evidence_hash and evidence['scope'] == self.expected_scope,
                'SEALED_AUTHENTICATED_EVIDENCE_DRIFT')
        # Cross-role rereads catch revocation of an earlier role while a later
        # role is being verified. These are bounded reads, not an atomic snapshot.
        for key, raw in zip(('intent', 'attestation', 'approval'), raws):
            require(private_bytes(Path(self.records[key]['path'])) == raw, 'LATE_EVIDENCE_CHANGED')
        for path, raw in signatures:
            require(private_bytes(path, 4096) == raw, 'LATE_SIGNATURE_CHANGED')
        require(self.verifier.read_policy() == policy, 'LATE_POLICY_CHANGED')
        finished = self.clock()
        require(finished >= started, 'LATE_CLOCK_REGRESSED')
        configured = trust_policy(policy, self.authorities['installationRef'], self.authorities['entityRef'], finished)
        for _, signature in signatures:
            record = decode(signature, 4096)
            grants = [key for key in configured['keys'] if key['keyRef'] == record['keyRef']
                      and key['issuerRef'] == record['issuerRef'] and record['role'] in key['roles']
                      and key['state'] == 'ACTIVE' and key['notBefore'] <= finished < key['expiresAt']]
            require(len(grants) == 1, 'LATE_LOCAL_MANDATE_EXPIRED')
        # Recheck protocol freshness after the final rereads, without rerunning
        # native cryptography. Authentication above has already returned True.
        validate_final(*raws, self.authorities, lambda *_: True, lambda: finished)
        self.verifier.check_budget()
        return True


def sealed_authorizer(value, approval_binding, scope, evidence_hash, budget, clock=time.time):
    """Exact opt-in binding; never falls back to hash-only authority."""
    require(type(value) is dict and set(value) == {'records', 'authorities', 'policyBinding',
            'signatureDirectory', 'opensslBinding'}, 'EXACT_AUTHENTICATED_DRIVER_BINDING_REQUIRED')
    require(type(approval_binding) is dict and set(approval_binding) == {'path','sha256','issuedAt','expiresAt'}
            and type(value['records']) is dict
            and value['records'].get('approval') == {k: approval_binding[k] for k in ('path','sha256')},
            'AUTHENTICATED_APPROVAL_DRIVER_DRIFT')
    late = LateAuthenticatedEvidence(value['records'], value['authorities'], value['policyBinding'],
        value['signatureDirectory'], value['opensslBinding'], evidence_hash, scope, clock=clock, budget=budget)
    from tools.semantic_provider_deployment_admission import authority
    def authorize():
        budget.check()
        authority(approval_binding, scope, lambda p: private_bytes(Path(p)), clock)
        return late()
    return authorize
