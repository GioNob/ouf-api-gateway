# Live node mandate issuance

Explicit node attestor live modes issue the existing v1 acceptance mandate with the real created-process generation during broker PREPARING. Observation never grants acceptance authority. v1 still verifies a preexisting signed mandate.

## Authority bytes and the creation timing dependency

| Configuration | Authority input | Preparation point |
| --- | --- | --- |
| ouf.semantic-node-attestor.v1 | acceptanceMandatePath, signed v1 mandate with exact generation | Existing precreated mandate path; no automatic upgrade |
| ouf.semantic-node-attestor.v2 | liveAcceptanceAuthorizationBinding with exact path/SHA256 | Accepted exact OCI/rootfs known before pinning producer |
| ouf.semantic-node-attestor.v3 | liveAcceptanceAuthorizationPath, fixed private path | Producer/broker pinned first; separately signed exact OCI/rootfs authorization supplied later |

v2 adds exactly the Binding field; v3 adds exactly the Path field. Mixed inputs, relative/traversal paths and inferred upgrades deny. v3 does not trust a mutable unsigned document: private root-owned0600/nlink1/nofollow/ancestor checks, bounded read, detached signature, configured issuer/install/entity/purpose and exact request facts are mandatory. The signed document is captured and must remain byte-identical throughout issuance. Its configuration path is immutable and hash-pinned in the source-sealed producer. The authority bytes can be signed after the full shadow OCI is known, without changing already pinned producer/broker configuration.

The authorization schema is ouf.semantic-node-live-acceptance-authorization.v1 with exact fields issuerRef, installationRef, entityRef, containerId, transactionId, intentHash, artifactHash, deploymentConstraintsHash, applicationHash, transportHash, runtimeExecutableHash, rootfsSeal, generationBinding, issuedAt, expiresAt, state, mandateIssuanceAuthorized, attestationAuthorized and completeCreationAccepted. All identity/hash bindings match the canonical producer request. generationBinding must be OBSERVED_CREATED; generation fields and wildcards deny. All three authority flags explicitly true, state ACTIVE, existing maximum300seconds wholly within intent. CREATION_ATTESTATION signature by the configured attestor is required before any node claim/signing key read.

The exact full OCI/rootfs/artifact must already be accepted by the external authority. v3 removes the configuration-byte dependency; it does not implement or authorize that external acceptance issuer. Target integration must provide it at the explicit shadow-OCI creation/preparation point, before invocation, under reviewed image/mount/generated-mount/constraint authority. No wildcard OCI, automatic acceptance from a hash, HUMAN pause inside invocation or broker configuration mutation is allowed. rootfs_seal is a host-filesystem seal, not whole external mount-view acceptance.

## Issuance and recovery

Broker CREATED→PREPARING and producer ISSUING remain unchanged. Validate intent/authorization/broker claim, independently observe runtime state, exact OCI/rootfs/live transport/real generation. Allocate durable node claim before reading signing key. Sign mandate with actual generation and accepted seal, cap expiry by intent/authority; second real observation/stable inputs precede O_EXCL/fsync publication of signature and mandate. Existing acceptance verifier validates it. Attestation/binding signatures follow a third observation and stable-input/window checks. Downstream protocol and reply shape are unchanged.

Existing5second producer invocation,12second node and18second broker deadlines remain unchanged. No callback, additional subprocess or nested common lock is introduced in the production broker. Exhausted budget denies. Concurrent issuance has one durable claim winner. Partial claim/signature/mandate is retained, no overwrite/retry/cleanup/inferred receipt.

## Evidence boundaries

Unit tests use ephemeral Ed25519 authority and explicit observation mocks. v2 tests15 cover scope/expiry/signatures, exact OCI/rootfs/generation drift, concurrent issuance and interrupted publication. v3 tests8 cover late signed bytes with unchanged producer pin, unsigned/missing/wrong OCI/private path/mixed schema denial, mutation during signing, and source-sealed CLI transport.

Mandatory isolated runc fixture: real created generation, ip/nsenter/rootfs observations and source-sealed producer CLI, no observation/command/crypto mocks. Positive mandate issuance does not start the application and fits the unchanged5second invocation on a small Busybox fixture. Two independent actual rootfs/OCI mutations deny before node claim/mandate, with process still created.

Mandatory Docker fixture adds v3 to the existing named adapter v4/preparer v3/driver v5 path. Producer and broker configuration are pinned before late authority exists; CI-only external acceptance signs the exact observed OCI/rootfs at the existing preparation point. Assertions require unchanged configuration bytes, real generation binding, rootfs-drift no mandate, lease/signature denial and guarded positive start only in owned ephemeral CI fixtures. v1 native regressions remain. Read CI logs on each source commit before claiming PASS.

These proofs are CI fixture authority, not publisher provenance, target image cost measurement, full target acceptance or deployment. Lab remains §41 historical lineage PASS; target packagev8/private policy remain unchanged. Live configuration, external acceptance issuer, operational signing authority, consumerlink, runtime migration/registration and target start remain separately scoped. No target signatures or start issued by these code changes.
