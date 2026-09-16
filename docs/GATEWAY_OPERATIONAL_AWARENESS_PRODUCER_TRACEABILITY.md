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
