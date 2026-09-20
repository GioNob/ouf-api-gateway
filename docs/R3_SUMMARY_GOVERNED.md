# R3 summary execution and evidence

This increment prepares `ouf.operations.summary` for a governed end-to-end
path. It does not certify a live installation or full R3 acceptance.

## Normative alignment

The attached Reality Baseline v1.7 was extracted without changes; all 323
SHA256SUMS entries matched. Consulted L0 Blueprint v0.3, Matrix v1.7 and
Terminology Notice v1.1, and the scope/invariants of all seven PETs. Targeted
requirements: MCP v1.4 §§33–34; Authorization v1.5 §34; Gateway v1.5 §§34–35;
Ingestion v1.3 §46. Onboarding v1.6 keeps configuration and THS ownership;
Semantic v1.3 retains TBox ownership; UDP v1.3 retains object/serving ownership.
No new central incident service, identity directory or human approval tool.

## Contract

The MCP private owner re-evaluates the current policy before reading state or
calling producers. Summary requests require TENANT_OPERATIONAL detail and the
same tenant/resource scope and decision reference; a public status grant is
not sufficient. Producer calls retain the request-only signed delegation and
original client identity. Proofs are neither arguments nor persisted fields.
The HTTP client uses closed Gateway paths for the three summary capabilities.

The owner validates JSON, byte/limit/source bounds, and an RFC3339 since value.
Default catch-up is 24 hours; maximum requested lookback is 30 days. These are
query bounds, not scheduler or retention changes. Producers compute current
health independently from the catch-up window.

The aggregator accepts only known status/completeness/module values, applies
an output allowlist and a deterministic global incident-item budget, and
preserves incompleteness including its own MCP producer. A denied producer
fails the aggregate with NOT_AUTHORIZED, without an incident payload. Failed,
malformed or unavailable producers yield partial DEGRADED; UNKNOWN never
becomes HEALTHY. Protected classes and arbitrary producer fields are omitted.
The incidents sibling now also requires owner authorization; its broader
pagination/lifecycle completion is outside this increment.

## Verification

Local Go test ./... passed; database and external pairwise cases retain their
explicit environment skips. Race tests passed for operational, orchestration
and HTTP client packages. Added owner-denial-before-read, malformed evidence,
redaction, producer denial and fixed Gateway path/delegation tests.
Gateway's companion PR supplies generated Lua tests and extends its real
APISIX/OIDC CI test; that is separate from a live OUF installation.

## Gateway evidence freshness

The Gateway candidate now contains a persistent collector adapter and a freshness contract. The collector writes normalized APISIX/etcd incidents plus independent APISIX/ETCD observation timestamps. The Java summary owner remains read-only and refuses to infer HEALTHY when either collector source is missing or older than the configured evidence-age bound. This closes the code-level false-healthy gap; it does **not** yet close the live-installation gate. Real fault/recovery/restart/reboot evidence is still required.

The APISIX adapter uses only fixed logical endpoint categories and never stores raw lines. The etcd adapter currently verifies endpoint health; storage-latency and proposal-backpressure evidence continues to be produced by the publication resilience gate and still needs a representative production binding. No authorization rule, grant or THS behavior is relaxed by the collector.


Deploy compatible owner implementations before enabling the new routes. The
Gateway operational owner now has a private Java host and producer receipt/SDK
adapter; Ingestion has the matching receipt-to-principal filter. See
R3_PRODUCER_IDENTITY.md for configuration and integration evidence. The summary
path refuses operation without verified identity, local policy and an explicitly
bound tenant. Reconstructed HTTP headers alone never constitute that binding.
These are explicit integration gates, not a reason to broaden grants.

Use the current Onboarding policy workflow for summary and producer grants,
reviewed and published by a human. Register compatible descriptors and scopes,
then retain allow/deny/partial and offline-catch-up evidence with image and
policy versions. No permission was granted or deployment performed here.

## Authorization checkpoint from the working session

The existing THS feedback record documents nominal policy 9 and a successful
HEALTHY/PUBLIC_OPERATIONAL read. Later, the user reported removing the IAM role
collaudo-funzionario-informatico; one giovanni-chatgpt status read returned
non-retryable authorization denied. The read catalogue had operational-viewer
assigned to that IAM role. This is expected negative evidence, not an incident
to repair. The exact later policy version and revocation latency are not
available in that tool response and are not invented. ouf-admin can read the
role catalogue but also received a denied status read; administration is not
an automatic operational grant. No role restoration is part of this increment.

## Preparing the Gateway candidate

`python3 -m tools.materialize_summary --runtime <resolved-runtime.json>
--oidc-client-secret-ref '$ENV://OIDC_SECRET' --delegation-key-env DELEGATION_KEY
--owner-key-env OWNER_KEY --output <candidate.json>` extends the existing
status/permission profile without replacing it. The three upstreams, paths,
scopes, operation types and timeout budgets are fixed and checked against the
compiled registry. No arbitrary target can be supplied in tool arguments.
The summary proof is forwarded only to the private MCP owner, which needs it
for two bounded producer calls; producer hops receive no human bearer/proof.
Do not activate this candidate until the owner-adapter gates above are met.
Keep the previous route snapshot for rollback. The installer, secrets, IAM and
current published policy were not changed by this PR.


## Collector packaging for the Netcup acceptance

The branch packages systemd templates under `ops/systemd/` for a persistent APISIX log
collector and a periodic etcd health probe. They share the Gateway-owned SQLite file under
a systemd `StateDirectory` and group 10001, so the Java owner can mount that file read-only.
The units are deployment candidates only: they have not been installed by this change.
Docker-log access is a laboratory adapter with host-level privilege and is not claimed as
the generic production observability architecture.
