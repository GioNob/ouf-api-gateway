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

## Live collection increment

- `tools/gateway_operational_collector.py` is the first deployment-target collector for the current Netcup/Docker topology. It tails the real APISIX access stream, maps only fixed governed paths to logical endpoint references, debounces repeated 502/503/504 responses into one `GATEWAY_UPSTREAM_UNREACHABLE` incident and resolves that same incident after a successful observation.
- The same collector has an etcd probe mode that runs the real `etcdctl endpoint health` inside the deployed etcd container. A failed probe opens/updates one `GATEWAY_ETCD_DEGRADED` incident and a later healthy probe resolves it.
- Collector liveness is persisted separately in `gateway_operational_collector_state` for APISIX and ETCD. The Java owner requires both observations to be fresh; missing or stale collector state yields `UNKNOWN` with `partial=true`, even if the incident table is empty.
- The collector never persists raw access lines, request bodies, JWTs, headers or etcd command output. Only normalized incident fields and collector timestamps enter the SQLite store.
- This increment does not make Docker-log access a product-wide architecture. It is an installation adapter for the current laboratory. A production packaging must give the collector least-privilege access to an approved log/event source and a durable store without introducing a central incident service.


- Persistence survives store reopen.
- Equivalent faults deduplicate into one incident timeline and increment occurrence count.
- Recovery resolves the same incident.
- etcd degradation and recovery are mapped without raw telemetry disclosure.
- Owner API fails closed without verified Gateway/Authorization context and enforces bounded queries.
- Producer route bindings remain private, Gateway-owned and non-tool-eligible.

## Evidence pending

- SQLite is the deterministic CI/reference durable adapter, not yet evidence of the production HA persistence backend. Production shared persistence/backup/retention and multi-replica behavior remain `EVIDENCE PENDING`.
- Real APISIX/etcd fault injection, collector restart/reboot behavior, CNI/NetworkPolicy enforcement and deployed Authorization decision propagation remain `EVIDENCE PENDING` until exercised on the installation.
- The etcd probe covers endpoint health. The existing publication gate still owns storage-slow and proposal-backpressure semantics; a production metrics binding for those signals remains evidence pending and must not be inferred from endpoint health alone.
- MCP cross-producer aggregation of Gateway + Ingestion + MCP state is a following increment.
