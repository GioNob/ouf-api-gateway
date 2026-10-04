"""Pure two-phase admission contract for one independently managed installation.

The integration must supply an authenticator for locally configured authorities.
No default issuer, signing, image inspection, persistence or start operation exists
here. Successful validation is input evidence, never permission to bypass the
existing live namespace, guard/lease or pre-start revocation checks.
"""
import copy
import hashlib
import json
import re
import time

from tools.semantic_provider_preexec import PreexecDenied, digest
from tools.semantic_provider_deployment_admission import authority


def require(value, reason):
    if not value:
        raise PreexecDenied(reason)


def identity(value):
    return isinstance(value, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value)


def hashed(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 131072, 'BOUNDED_PROTOCOL_RECORD_REQUIRED')
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'DUPLICATE_PROTOCOL_KEY')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except PreexecDenied:
        raise
    except (ValueError, RecursionError, UnicodeError):
        raise PreexecDenied('INVALID_PROTOCOL_JSON') from None
    require(type(value) is dict, 'EXACT_PROTOCOL_OBJECT_REQUIRED')
    return value


def window(value, now):
    require(type(value['issuedAt']) is int and type(value['expiresAt']) is int
            and value['issuedAt'] <= now < value['expiresAt']
            and 0 < value['expiresAt'] - value['issuedAt'] <= 300,
            'PROTOCOL_AUTHORITY_EXPIRED_OR_NOT_YET_VALID')


def context(value):
    fields = {'installationRef', 'entityRef', 'intentIssuerRef', 'attestorRef', 'approvalIssuerRef'}
    require(type(value) is dict and set(value) == fields
            and all(identity(v) for v in value.values()), 'EXACT_INSTALLATION_AUTHORITIES_REQUIRED')
    return copy.deepcopy(value)


def authenticated(raw, role, issuer, ctx, authenticate):
    require(callable(authenticate), 'EXTERNAL_AUTHENTICATOR_REQUIRED')
    # Pass bytes and configured identities, never a mutable trusted payload.
    require(authenticate(raw, role, issuer, ctx['installationRef'], ctx['entityRef']) is True,
            'EXTERNAL_RECORD_AUTHENTICATION_REQUIRED')


def validate_intent(raw, configured_authorities, authenticate, clock=time.time):
    """Validate creation-only intent; it deliberately has no complete OCI hash."""
    ctx = context(configured_authorities)
    value = decode(raw)
    fields = {'schema', 'issuerRef', 'installationRef', 'entityRef', 'containerId',
              'transactionId', 'artifactHash', 'deploymentConstraintsHash', 'transportHash',
              'runtimeExecutableHash', 'issuedAt', 'expiresAt', 'infrastructureAuthorized',
              'creationAuthorized', 'applicationStartAuthorized'}
    require(set(value) == fields and value['schema'] == 'ouf.semantic-deployment-intent.v1',
            'EXACT_DEPLOYMENT_INTENT_REQUIRED')
    require(value['issuerRef'] == ctx['intentIssuerRef']
            and all(value[k] == ctx[k] for k in ('installationRef', 'entityRef')),
            'INSTALLATION_INTENT_SCOPE_DRIFT')
    require(all(hashed(value[k]) for k in ('containerId', 'transactionId', 'artifactHash',
            'deploymentConstraintsHash', 'transportHash', 'runtimeExecutableHash')),
            'EXACT_INTENT_HASHES_REQUIRED')
    require(value['infrastructureAuthorized'] is True and value['creationAuthorized'] is True
            and value['applicationStartAuthorized'] is False, 'CREATION_ONLY_INTENT_REQUIRED')
    now = clock()
    window(value, now)
    authenticated(raw, 'DEPLOYMENT_INTENT', ctx['intentIssuerRef'], ctx, authenticate)
    finished = clock()
    require(finished >= now, 'PROTOCOL_CLOCK_REGRESSED')
    window(value, finished)
    return copy.deepcopy(value)


def validate_final(intent_raw, attestation_raw, approval_raw, configured_authorities,
                   authenticate, clock=time.time):
    """Bind externally authenticated creation evidence and final approval.

    The attestor owns actual image/OCI/runtime inspection. This validator binds
    its claims and retains the created process generation for a subsequent live
    comparison; it performs neither inspection nor journal consumption itself.
    """
    ctx = context(configured_authorities)
    now = clock()
    intent = validate_intent(intent_raw, ctx, authenticate, lambda: now)
    attested = decode(attestation_raw)
    fields = {'schema', 'attestorRef', 'installationRef', 'entityRef', 'intentHash',
              'containerId', 'transactionId', 'artifactHash', 'deploymentConstraintsHash',
              'transportHash', 'runtimeExecutableHash', 'applicationHash', 'generation',
              'observedAt', 'creationAcceptance'}
    require(set(attested) == fields
            and attested['schema'] == 'ouf.semantic-created-candidate-attestation.v1',
            'EXACT_CREATED_ATTESTATION_REQUIRED')
    require(attested['attestorRef'] == ctx['attestorRef']
            and all(attested[k] == ctx[k] for k in ('installationRef', 'entityRef')),
            'INSTALLATION_ATTESTATION_SCOPE_DRIFT')
    require(attested['intentHash'] == hashlib.sha256(intent_raw).hexdigest()
            and all(attested[k] == intent[k] for k in ('containerId', 'transactionId', 'artifactHash',
                'deploymentConstraintsHash', 'transportHash', 'runtimeExecutableHash')),
            'CREATION_INTENT_BINDING_DRIFT')
    require(hashed(attested['applicationHash']), 'COMPLETE_OCI_HASH_REQUIRED')
    generation = attested['generation']
    require(type(generation) is dict and set(generation) == {'pid', 'startTicks', 'namespaceInode'}
            and all(type(v) is int and v > 0 for v in generation.values())
            and generation['pid'] > 1, 'CREATED_GENERATION_REQUIRED')
    require(type(attested['observedAt']) is int
            and intent['issuedAt'] <= attested['observedAt'] <= now,
            'CREATION_OBSERVATION_TIME_DRIFT')
    creation = attested['creationAcceptance']
    require(type(creation) is dict
            and set(creation) == {'schema', 'containerId', 'applicationHash', 'transportHash', 'accepted'}
            and creation['schema'] == 'ouf.semantic-container-creation-acceptance.v1'
            and creation['accepted'] is True
            and all(creation[k] == attested[k] for k in ('containerId', 'applicationHash', 'transportHash')),
            'COMPLETE_CREATION_ACCEPTANCE_REQUIRED')
    authenticated(attestation_raw, 'CREATION_ATTESTATION', ctx['attestorRef'], ctx, authenticate)
    approval = decode(approval_raw)
    # Canonical acceptance bytes must be used when publishing the legacy receipt.
    scope = {'issuerRef': ctx['approvalIssuerRef'], 'installationRef': ctx['installationRef'],
             'entityRef': ctx['entityRef'], 'approvalRef': approval.get('approvalRef'),
             'containerId': intent['containerId'], 'transactionId': intent['transactionId'],
             'applicationHash': attested['applicationHash'], 'transportHash': intent['transportHash'],
             'creationAcceptanceHash': digest(creation)}
    require(type(approval.get('issuedAt')) is int
            and approval['issuedAt'] >= attested['observedAt'], 'FINAL_APPROVAL_BEFORE_CREATION')
    binding = {'path': '/externally-authenticated/approval',
               'sha256': hashlib.sha256(approval_raw).hexdigest(),
               'issuedAt': approval.get('issuedAt'), 'expiresAt': approval.get('expiresAt')}
    authority(binding, scope, lambda _: approval_raw, lambda: now)
    require(approval['expiresAt'] <= intent['expiresAt'], 'FINAL_APPROVAL_EXCEEDS_INTENT')
    authenticated(approval_raw, 'FINAL_DEPLOYMENT_APPROVAL', ctx['approvalIssuerRef'], ctx, authenticate)
    # Authentication may involve an external verifier. Expiry must also hold
    # after that call, not only at the beginning of validation.
    finished = clock()
    require(finished >= now, 'PROTOCOL_CLOCK_REGRESSED')
    window(intent, finished)
    authority(binding, scope, lambda _: approval_raw, lambda: finished)
    return {'schema': 'ouf.semantic-validated-deployment-evidence.v1',
            'installationRef': ctx['installationRef'], 'entityRef': ctx['entityRef'],
            'intentHash': hashlib.sha256(intent_raw).hexdigest(),
            'attestationHash': hashlib.sha256(attestation_raw).hexdigest(),
            'approvalHash': binding['sha256'], 'scope': copy.deepcopy(scope),
            'creationAcceptance': copy.deepcopy(creation), 'generation': copy.deepcopy(generation)}
