# Creation-only intent issuer

The first signed deployment intent previously had no production issuer. The new
source-sealed root CLI uses the existing installation installer key and the
existing detached Ed25519 verifier. It emits the exact creation-only contract
already consumed by the local broker. It never creates or starts a container.

The operator supplies a configuration path and its external SHA256 pin, and
explicitly invokes `--authorize-creation-only`. The root-private configuration
has schema `ouf.semantic-creation-intent-issuer.v1`; its closed source manifest
includes the CLI and every module listed in `MODULES`. It binds the current
interpreter, existing key hash/reference, policy hash, OpenSSL hash/version,
installation authorities, dedicated output directory and creation mandate.
All source modules are verified before execution and the isolated interpreter
is rechecked against its configured binding.

The root-provisioned mandate has schema `ouf.semantic-creation-intent-mandate.v1`,
issuer/installation/entity, container and transaction IDs, artifact/constraints/
transport/runtime hashes, issuedAt/expiresAt and four explicit booleans:
issuanceAuthorized, infrastructureAuthorized and creationAuthorized true;
applicationStartAuthorized false. Its lifetime is at most 300 seconds. Issuance
uses the current time and preserves its deadline. It does not renew authority.

The explicit root invocation is the local operator authorization boundary for
issuance. A prepared policy artifact alone does not authorize this action. The
consumer checks an active matching installer role, verifies its public key
against the existing private key, and signs only the bounded contract after a
durable exclusive issuance claim. It verifies the signature using the existing
protocol before publication. The claim is retained as ISSUING: successful stdout
does not prove the caller retained or consumed the evidence. Existing or partial
claims, payloads and signatures are preserved and cannot be retried in place.

No key generation, modification of historical receipts, Docker runtime
registration, image acceptance, provider call, database change or application
start accompanies issuance. The image and constraint hashes are explicit
installer commitments; this issuer does not inspect or accept image bytes.
The independently configured node attestor, final approval, live pre-execution
guard, lease lifecycle and actual governed deployment remain required.

Local tests use real ephemeral Ed25519 keys, OpenSSL and the production isolated
CLI. They cover successful protocol verification, start/cross-installation/
expired/excessive/unapproved mandate rejection, source/key drift, revoked policy,
two concurrent real CLI processes, retained failed fsync claims, configuration
pin mismatch, foreign evidence preservation and expiry during signing. These are
isolated fixtures, not installation acceptance or a provider start on the VPS.
