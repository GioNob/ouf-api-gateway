# Semantic deployment admission: independent installation and two phases

Architecture approved by the operator on 2026-10-04. Every Ente operates its own
independent OUF installation. A thousand Enti means a thousand independently
administered installations. Shared code, contracts and release tooling do not
create a shared tenant authority, a central runtime or trust between installations.
Within one installation, services may occupy different hosts/networks or share
one host and subnet. Installation and entity references scope evidence; they do
not imply a multitenant deployment.

The installer/orchestrator has an explicitly delegated infrastructure mandate.
It approves deployment intent and later the final deployment. A verifier on the
destination node attests actual creation. These are separate logical roles that
may be delivered in existing installation tooling; this decision introduces no
new mandatory microservice. Human identity and organizational authority remain
external under the PETs, M2M authority remains an explicit A/B/C binding, and
application capabilities remain owned by OUF Authorization. Neither an entity
identifier nor access to an internal network grants infrastructure authority.

## Sequence and contracts

1. Stage approved images and deployment inputs. The installer issues an
   authenticated `ouf.semantic-deployment-intent.v1` authorizing creation only.
2. Create the candidate without executing its application. No complete OCI hash
   is required in the initial intent, since the runtime-generated document does
   not yet exist. There is no inferred start permission.
3. A locally configured verifier independently inspects the destination node's
   image/root filesystem, complete OCI document, deployment constraints, approved
   network attachments and actual runtime/process generation. It issues
   authenticated `ouf.semantic-created-candidate-attestation.v1` evidence linked
   to the exact initial-intent bytes and hashes. It contains a compatible
   `ouf.semantic-container-creation-acceptance.v1` payload.
4. The explicitly configured installer approval issuer authenticates that
   evidence and issues the existing final
   `ouf.semantic-deployment-admission-approval.v1`. It binds installation, Ente,
   CID, transaction, complete OCI hash, transport and creation acceptance. Final
   approval cannot predate the creation observation or outlive the initial intent.
5. The existing preparer/guard/lease path must consume the sealed evidence and
   independently recheck live custody, current generation, revocation and expiry
   under the common lock. Actual start requires an explicitly authorized
   deployment action and all gates. Validation alone invokes no runtime.

Initial intents and final approvals are bounded to 300 seconds, without automatic
renewal or replay. Image staging occurs before issuance. A failed or expired
attempt must preserve its custody and use a reviewed new transaction/recovery
path rather than resetting a journal to reuse an old approval.

## Implemented contract validation

`tools/semantic_provider_deployment_protocol.py` validates bounded exact JSON,
creation-only intent, per-installation configured issuer/attestor identities,
exact hash lineage, created process generation, acceptance and final authority.
The caller must supply `authenticate(raw_bytes, role, issuer, installation, entity)`.
Only the literal `True` succeeds. The callback belongs to the trusted integration
and must validate producer identity, role, installation mandate and integrity
using the configured trust mechanism. There is no permissive default verifier,
self-declared authority, fixed IAM URL, shared issuer or mandatory signature
algorithm. Record hashes alone are not authentication.

The creation receipt must be published using canonical JSON: sorted keys,
separators `(',', ':')`, UTF-8. Its SHA256 equals the existing `digest(receipt)` and
the final approval's `creationAcceptanceHash`. The complete OCI digest follows
the existing `application_hash`; it does not independently prove image bytes.
Artifact and constraint hashes are accepted only as authenticated attestor claims;
the concrete node verifier must actually inspect and enforce those constraints.

Returned evidence contains no start flag. It retains the generation, intent,
attestation and approval hashes for later sealed journal consumption. Inputs are
bytes, context is detached, outputs are detached, and no mutable payload is passed
to the authenticator. Freshness is rechecked after authentication. The integration
must bound the authenticator's execution time and fail closed on its failures.

## Verification and remaining integration gates

Eighteen contract tests cover authenticated positive evidence, role separation,
independent-installation rejection, altered evidence, creation-only authority,
OCI drift, artifact/transport/runtime/constraint drift, invalid generation,
premature final approval, expiry during authentication, duplicate JSON, bounded
input, nonfinite values, excessive nesting and returned-object isolation. Test
credentials are synthetic and confined to test code. CI runs these tests in the
existing admission-preparer job alongside existing package/native regressions.

This is an implemented pure validation contract, not an installed signer, node
verifier or Docker orchestrator. The existing adapter v2 seals final approval and
admission configuration before `create`; it has not yet been migrated to this
two-phase sequence. A future integration must freeze creation intent, accept final
evidence exactly once after independent created-state inspection, preserve
generation custody and use the common guard/lease lock. No in-place rebind of an
existing v2 journal or automatic replay is authorized. Concurrent consumption and
revocation require durable journal/lock integration; this pure validator does not
claim to prevent a second caller from reusing the same evidence.

Target authority provisioning, actual image/rootfs inspection, authenticated
producer transport, durable exactly-once consumption, Docker adapter v2/v3
integration, atomic snapshots, IPv6/spoof resistance, application
OIDC/purpose/TLS/revocation, active lease and real reboot remain explicit gates.
The staged source-only v3 package at
`/etc/ouf/deploy-snapshots/semantic-admission-package-20261004-055825` remains
immutable and does not contain this new module. No VPS command, runtime
registration, application start, merge or replay accompanies this contract change.
