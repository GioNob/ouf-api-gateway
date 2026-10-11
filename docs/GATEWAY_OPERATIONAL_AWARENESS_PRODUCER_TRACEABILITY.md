# Gateway-produced Operational Awareness traceability

Normative baseline: OUF Reality Baseline Package v1.7, Gateway PET v1.5 §34 and Cross-Module Alignment Matrix v1.7 §6-7.

## PET requirements

- OA-GW-01: significant upstream/control-plane fault becomes a semantic incident aggregate rather than raw telemetry.
- OA-GW-02: etcd degradation that blocks publication is reflected in Gateway operational state.
- OA-GW-04: unavailable evidence/module state must not be collapsed to HEALTHY.
- OA-GW-05: recovery updates/resolves the existing incident.
- Persistent catch-up is mandatory; live notification is optional.
- Raw APISIX/etcd telemetry, credentials, hostnames and stack traces are not part of the user-facing projection.

## Implementation evidence

- `tools/operational_incidents.py`: durable SQLite reference adapter with OPEN/RECOVERING/RESOLVED lifecycle, stable dedup key, occurrence aggregation and bounded projections.
- `tools/publication.py`: publication failures produce one governed `GATEWAY_PUBLICATION_BLOCKED` incident and successful activation resolves it.
- `tools/etcd_resilience.py`: quorum, slow-storage and proposal-backpressure failures update one `GATEWAY_ETCD_DEGRADED` incident; healthy safety state resolves it.
- `tools/gateway_operational_api.py`: private owner projection requiring verified Gateway and Authorization context.
- `ouf.gateway.operations.incidents` / `ouf.gateway.operations.summary`: internal, non-MCP-tool producer capabilities for MCP aggregation.

## Test evidence

- Persistence survives store reopen.
- Equivalent faults deduplicate into one incident timeline and increment occurrence count.
- Recovery resolves the same incident.
- etcd degradation and recovery are mapped without raw telemetry disclosure.
- Owner API fails closed without verified Gateway/Authorization context and enforces bounded queries.
- Producer route bindings remain private, Gateway-owned and non-tool-eligible.

## Evidence pending

- SQLite is the deterministic CI/reference durable adapter, not yet evidence of the production HA persistence backend. Production shared persistence/backup/retention and multi-replica behavior remain `EVIDENCE PENDING`.
- Real APISIX/etcd fault injection, CNI/NetworkPolicy enforcement and deployed Authorization decision propagation remain `EVIDENCE PENDING`.
- MCP cross-producer aggregation of Gateway + Ingestion + MCP state is a following increment.

## Governed reference owner pages, 2026-10-11

The mandatory [platform resilience policy](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md) and [cursor design](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_OPERATIONAL_CURSOR_DESIGN.md) govern this increment.

- Atomic SQLite UPSERT merges equivalent platform incidents without losing concurrent occurrence increments; recovery updates the same identity. Observation time never moves backwards during reopen/recovery. Logical control-plane dedup keys are platform scoped; this reference adapter rejects relabeling into tenant business incidents.
- `tools/operational_cursor.py` captures an immutable, priority-ordered owner membership and payload snapshot. SQLite serializes writers; its transition revisions are commit ordered. PostgreSQL sequences do not have that property and require the separate Ingestion publication protocol.
- Same-transaction triggers capture changes; rollback removes the change and history together. Existing rows receive an honest history baseline, and an earlier requested `since` reports `historyGap`. New payload projection uses an explicit allowlist.
- Opt-in incidents request `{ "snapshot": true, "limit": 50 }`; continuation accepts only `{ "cursor": "<opaque UUID>" }`. UUIDs bind verified principal, tenant, actor/authentication context, current local policy reference and stable snapshot metadata. Pages are refetched and authorized before disclosure. Changed authorization alters `itemsDigest`; consumers must invalidate any saved offset rather than reuse cached authority.
- Each request requires a current owner-local collection grant for `module=GATEWAY`, `incidentScope=PLATFORM`, `detailLevel=RESTRICTED_OPERATIONAL`, followed by current per-incident decisions. The host adapter must inject its local policy evaluator; none is synthesized from a caller decision header. Missing evaluator fails closed. The test grant exists only under `tests/`.
- Query parsing rejects duplicate keys, invalid UTF-8, arrays, nulls, unknown fields, boolean limits and changed cursor filters. Requests are at most64KiB; outputs at most512KiB. Redacted or truncated summaries do not claim HEALTHY or export unrestricted counters.
- Finite reference profile:30minute snapshot expiry, at most100items/page and200pages,20,000items/session,16sessions/principal,128sessions/tenant,4,096total sessions,64,000captured items/tenant and200,000total captured items. Admission cleans at most one expired session and rejects capacity pressure without stopping incident writes. SQLite busy timeout is2seconds per DB attempt; no nested retry loop or sleeps under a transaction. This short DB contention profile is not the external dependency outage budget.
- Paging does not record an operator receipt, acknowledge an alert, resolve an incident or authorize recovery. Platform control-plane pages cannot accept an Ingestion `sourceId` as though it were a matching Gateway tenant filter.

Validation:14 new reference tests exercise concurrent dedup, immutable/atomic history, restart-stable paging, fine-grained revocation, identity/tenant/policy binding, expiry/capacity, malformed inputs, priority before paging and secret-column exclusion. Native GitHub qualification is recorded separately after completion.

Remaining limits: production HA/backend deployment and actual owner-local Authorization SDK host wiring remain unproven; the reference constructor cannot enable this by default. Transition history currently has no retention pruning: bounded snapshot storage is not proof of bounded incident-history storage. Durable publication-revision resume bookmarks, persistent consultation receipts, cross-producer stable merge, notification outbox and pressure hysteresis are subsequent work. No VPS command, replay, restart or traffic lease is authorized by this paging contract.
