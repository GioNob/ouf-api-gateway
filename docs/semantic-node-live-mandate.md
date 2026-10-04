# Live node mandate issuance

The optional node attestor v2 removes the requirement to pre-sign a created-process generation. It issues the existing v1 node acceptance mandate during the broker PREPARING invocation. It does not grant authority by observing a process.

## Explicit configuration and authorization

v1 configurations remain supported with a preexisting signed acceptanceMandatePath. A v2 configuration uses schema ouf.semantic-node-attestor.v2 and adds exactly one hash-pinned liveAcceptanceAuthorizationBinding. All other fields and source closure remain the same. No default upgrade or schema inference is performed.

The bound authorization has schema ouf.semantic-node-live-acceptance-authorization.v1 and exact fields: issuerRef, installationRef, entityRef, containerId, transactionId, intentHash, artifactHash, deploymentConstraintsHash, applicationHash, transportHash, runtimeExecutableHash, rootfsSeal, generationBinding, issuedAt, expiresAt, state, mandateIssuanceAuthorized, attestationAuthorized and completeCreationAccepted. All identity/hash bindings match the canonical producer request. generationBinding must be OBSERVED_CREATED; a generation field or wildcard is rejected. The three authority flags must explicitly be true and state ACTIVE.

The expected full OCI applicationHash and exact rootfsSeal must already have been accepted and signed by the selected attestor under CREATION_ATTESTATION. The artifact acceptance must cover external bind contents and generated OCI mounts: rootfs_seal traverses the host root filesystem, not a substitute for reviewing the whole mount view. Receipt/hash consistency is not sufficient authority. No authorization is emitted by this implementation or by staging code.

The authorization window follows the existing maximum300seconds and must be wholly within the exact intent window. Signed authorization, policy/key selection, original installation/entity/node issuer and source closure are revalidated. This introduces no new keypair, issuer, IAM grant or automatic consumer activation.

## Invocation sequence

Broker CREATED→PREPARING and producer ISSUING claim remain unchanged. Node v2 validates signed intent/authorization and real broker claim; observes created runtime, generation, full OCI, rootfs and live transport; requires the observed OCI/generation match the request and seal equals the previously accepted seal. It allocates the durable node issuance claim before any signing key read.

The existing signer emits a node mandate that copies all exact request facts, fills the real observed created generation, preserves the accepted seal, and caps expiry by intent/authorization. A second observation and stable-input checks precede private publication of detached signature and mandate with O_EXCL/fsync. The mandate is then verified by the existing acceptance verifier. Attestation and result-binding signatures follow, with a final observation and stable-input/window checks. Producer reply shape and downstream validation are unchanged.

No broker callback, extra subprocess or nested common lock is introduced. The broker common lock remains held during producer invocation; the issuer does not acquire it. There is no human pause inside the live window. The existing5second producer invocation,12second issuer and18second broker budgets remain unchanged. v2 adds one rootfs observation and one signature; actual selected image costs must be measured before deployment. Exhausted budgets deny, rather than extending deadlines implicitly.

## Recovery and authority boundary

Files must not already exist. Concurrent issuance has one durable-claim winner. Failure after a claim/signature leaves private evidence and ISSUING custody; there is no retry, cleanup, overwrite or inferred successful receipt. Target reconciliation must explicitly handle a partial signature/mandate. v1 callers preserve their existing no-replay contract.

Tests use ephemeral Ed25519 keys and explicitly mocked runtime observations. New tests cover exact scope, no-authority-before-key/claim, OCI/rootfs/generation drift, invalid/expired authorization, private publication interruption, concurrent issuance, v1 opt-in rejection and real source-sealed CLI/producer transport with an observation stub confined to an ephemeral package. No target/native v2 acceptance is claimed.

The lab remains at §41 historical lineage PASS. Its private packagev8 and policy remain unchanged. This software change is not deployed: v2 configuration, accepted OCI/rootfs/artifact, live issuance authorization, signing authority, runtime migration/registration and start require concrete separately approved target plans. Existing stopped candidates are never started or recreated by this change.

## Native v2 fixture boundary

A mandatory isolated CI fixture creates a real runc process and network namespace, then accepts its exact OCI/rootfs with ephemeral authority before pinning the v2 producer. The source-sealed CLI performs real runc/ip/nsenter observations and emits the signed live mandate and attestation without starting the application. It must fit the unchanged5second producer invocation. No observation, command or crypto mock is used. This proves the created-process issuance path for that small Busybox fixture, not selected VPS image costs or Docker pre-create immutable bindings.

The Docker adapter's immutable producer configuration is pinned before its shadow OCI is known. A v2 authorization includes that exact OCI and its hash is itself pinned by the producer configuration. Target integration must concretize the preparation point or explicit issuer bridge for this dependency; merely installing v2 cannot solve it. No wildcard, automatic acceptance or mutation of an already pinned broker configuration is permitted. Native v1 Docker/admission regressions remain independently exercised.

The native fixture also mutates actual rootfs bytes or the full OCI after signing authorization. Both independent cases must deny before creating a node claim or publishing a mandate; the runc process remains created and the application marker remains absent. These are new real-observation denials, distinct from the mocked unit drift tests.
