# Shared Authorization SDK 1.1.0

Normative authority: Reality Baseline 1.7, Authorization PET 1.5 §§109.2–3,
109.5–8, Matrix 1.7. Coordinates: `it.comune.trieste.ouf:authorization-sdk:1.2.0`.
Canonical source ownership stays here in the Authorization control-plane repository.
The source bundle is mirrored byte-for-byte in Java consumers under `vendor/` with
source commit and SHA-256 manifest. CI builds and installs the same Maven artifact;
there is no independently maintained evaluator or consumer PrincipalContext.

Run `bash scripts/install-authorization-sdk.sh` from the repository root before
building the consumer. The tests classifier contains explicit laboratory helpers;
it is test-scoped and must never enter the production boot JAR.

`TrustedPrincipal` is an authentication SPI: an upstream token/container adapter
must validate signature, issuer, audience and canonical claims before constructing
it. Neither request headers, container roles alone nor arbitrary capability
attributes create authorization. No local IAM or remote per-request PDP is added.
`ServletAuthorization` evaluates capabilities locally and pins one immutable
snapshot per request. A server-resolved `ResourceContext` may be provided as a
request attribute; default resource is tenant-bound with no organization. Domain
resource predicates/DataAccessLabel/assurance remain R1b; this version must reject
unknown mandatory bundle fields instead of ignoring unsupported policy.

The optional startup properties `ouf.authorization.bundle-file`, `bundle-id`,
`bundle-version`, `bundle-sha256` describe one exact local bundle (raw PolicyBundle
JSON schema v1). All reference properties are required when file is configured.
Bad hash/reference/schema prevents startup. Absent bundle makes protected resolver
calls deny; health is available through `LocalAuthorization.health()`.
`max-staleness-seconds` defaults to 300, bounded to 1..86400. `refresh` is an
explicit bounded configuration path, never invoked by `evaluate`. Deployment must
refresh against the governed ACTIVE pointer or restart with a new exact reference;
this SDK does not silently poll/re-trust an old local file. Version rollback,
lineage changes and mutation of an existing version are rejected; governed lineage
change requires restart. Revocation distribution and IAM bindings remain release
gates, not automatically satisfied by file-backed fixture tests.

Public same-major API changes must be additive. Payload JSON and historical
PolicyBundle/PrincipalContext fields are preserved; the Java package is now the
common `it.comune.trieste.ouf.authorization`, and in-repository consumers migrate
in this tranche. No previously published SDK artifact coordinates are replaced.

R1b: optional trusted role/assurance claims and grant constraints, explicit DENY precedence, resource/detail decision metadata, HTTPS background refresh with SHA-256 and bounded staleness. See owner docs/AUTHORIZATION_R1B.md. Unknown policy fields fail closed.
