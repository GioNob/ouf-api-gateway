# Persistent scoped pressure control — reference profile v1

Mandatory [OUF resilience policy v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md). Status: reference engine implemented; owner metric sampling, scheduler quota enforcement and target deployment OPEN. No new service/broker, no platform-wide incident authority.

## Current signals, not historical totals

`PersistentPressureController` uses only owner-produced current300second window attempts/failures, proved continuous dependency-unavailable duration, current capacity utilization and oldest backlog age. It does not accept historical issue totals, login timestamps or time since the operator last consulted. Scope references are explicit governed installation/dependency config, not one row per job/object. At most1,024 configured scopes. A dependency affecting5,000 jobs remains one pressure scope, with affected-job links retained separately in the owner.

The reference v1 finite profile is an OUF implementation decision, not an AWS numeric default: at least20attempts for a50%failure-rate signal,90seconds sustained high signal; immediate pause at90%current capacity,300seconds proved dependency unavailability (even low-volume) or backlog≥900seconds with capacity≥70%. Resume requires120seconds continuous fresh low evidence (capacity≤70%, backlog<300seconds, no dependency outage and failure rate≤10%). Observations must have correct types/ranges, a300second window and age≤30seconds/future≤5seconds. Missing/stale evidence returns UNKNOWN and zero business slots, never HEALTHY.

Two control slots remain reserved in every decision. Business quotas: NORMAL8, CAUTIOUS2, PAUSED0, PROBE1, RECOVERING2→4→8 after fresh healthy30second stages with observed attempts and zero failures. Current failure during probing pauses that scope. A sample gap resets recovery evidence, so two isolated healthy observations cannot certify continuous recovery. These quotas are limits, never permission to execute: IAM/revocation/admission/current-generation guards, persistent incident retry budgets and HUMAN recovery authority remain separately mandatory. No pressure probe renews an exhausted budget.

## Persistence and concurrency

SQLite owner-local rows preserve mode, version and evidence boundaries across restart. Transactions are short; no wait/RPC under a write lock. Every update uses expected-version CAS; duplicate exact observations are idempotent, conflicting/older evidence is rejected. Unregistered scopes cannot be synthesized by a new job ID. Scope admission pressure does not remove existing control state. The engine does not discard quarantined input or advance a data checkpoint.

## Validation and limits

13 focused reference groups pass locally: three-hour outage and gradual recovery, independent dependency, restart, concurrent/stale writer conflicts, exact duplicate, malformed/stale signals, low-volume long outage, capacity/backlog pressure, hysteresis, bounded scope admission and a31day operator absence with an old OPEN issue that does not cause a current crisis. Native Gateway/APISIX qualification remains required before merge.

No trusted production sampler or scheduler currently consumes these quotas; reserved slots are a tested decision contract, not proof of reserved production capacity. SQLite HA, live metrics quality, threshold calibration, distributed quota enforcement, cancellation/revocation and complete owner retry integration remain OPEN. Do not label the platform detector active until those paths are qualified. No email, provider call, VPS migration/restart or R9/R10 action occurs.

## AWS alignment

The architectural reasoning follows primary AWS guidance on limiting retries, idempotency, jitter and isolating concurrency:

- [Timeouts, retries, and backoff with jitter](https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/): retries at one layer, finite attempts, side-effect safety, measured dependency latency.
- [Making retries safe with idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/): stable request intent and reconciliation of ambiguous effects.
- [Using dependency isolation to contain concurrency overload](https://builder.aws.com/content/3EuxuD6bWtQ6gEp9FaKQfd3Z2AM/using-dependency-isolation-to-contain-concurrency-overload): concurrency containment is separate from merely tightening timeouts.
- [Using load shedding to avoid overload](https://builder.aws.com/content/3Eun1EEyX6p2e3VYNyRLSJzLuMV/using-load-shedding-to-avoid-overload): protect useful/control work under overload; retry amplification can worsen pressure.

Consulted2026-10-11. OUF finite values, durable quarantine/new HUMAN budgets and operator receipt semantics are project policy decisions and must be qualified in OUF, not attributed to AWS as prescribed values.
