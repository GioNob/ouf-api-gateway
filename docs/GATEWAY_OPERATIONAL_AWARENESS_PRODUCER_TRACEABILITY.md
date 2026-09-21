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


## Live acceptance evidence — 21 September 2026

The first complete live R3 summary path was observed with:

- public MCP request HTTP 200;
- parent `ouf.operations.summary` HTTP 200;
- Gateway producer `ouf.gateway.operations.summary` HTTP 200;
- Ingestion producer `ouf.ingestion.operations.summary` HTTP 200;
- aggregate `HEALTHY`, `partial=false`.

The Gateway projection included a previously resolved upstream-unreachable
incident while current Gateway health remained HEALTHY. This is expected:
catch-up history and current health are different dimensions.

### Dynamic-route drift discovered during acceptance

APISIX route state must be treated as runtime state, not inferred from repository
or InstallationProjection contents alone.

During the same acceptance session, `mcp-permissions-read` still referenced
`ouf-source-onboarding:8080` although the deployed container exposed only
`ouf-onboarding`. APISIX returned 503 before the owner was reached. The
connector surfaced this as `INVALID_ARGUMENT`, which was misleading without
Gateway logs.

Reusable diagnostic rule:

1. correlate the client failure with APISIX error/access logs;
2. distinguish DNS/upstream failure from owner validation failure;
3. inspect the live etcd route;
4. snapshot the complete route before mutation;
5. construct a candidate and prove that only the expected node changes;
6. apply through APISIX Admin API rather than writing etcd directly;
7. read the live route back and retain the rollback snapshot.

The observed minimal correction was:

`ouf-source-onboarding:8080 -> ouf-onboarding:8080`.

Do not interpret a 503 from an execute route as proof that request arguments are
invalid until upstream reachability is established.

### Reading APISIX dynamic configuration in minimal containers

The lab etcd image did not provide a shell, but
`/usr/local/bin/etcdctl` was executable directly through `docker exec`.
This is preferable to installing tools or exposing etcd ports merely for
diagnostics.

The APISIX container Admin API listened only on loopback inside the container
network namespace. Host-side diagnostics used the existing namespace rather
than publishing a new admin port.

### Operational receipt comparison pattern

Gateway and Ingestion summary routes use the same receipt-materialization logic
with producer-specific keys. When one producer succeeds and another fails:

- compare receipt key fingerprints, never raw keys;
- compare raw and trimmed hashes if files can contain a trailing newline;
- verify exact producer path and capability;
- verify issuer/audience/tenant/workload;
- verify `AuthorizationDecisionRef`;
- remember that the owner performs a fresh local Authorization decision after
  receipt validation.

A working Gateway producer is therefore a valuable control case, but it does
not prove the Ingestion owner policy/resource checks are equivalent.

### Evidence boundary after the live positive

Live deployed Authorization decision propagation and MCP cross-producer summary
are now positively evidenced for the tested path. This does not close the
separate R3 acceptance gates for deny/revocation, staleness/partial behavior,
real fault injection/recovery, restart/reboot or final correlation/audit.


### Live route consolidation completed

The stale Onboarding upstream was subsequently reconciled from the verified R3
Gateway source at commit
`1629652163edce7b3bc4c8f80bf29a3ef1b1ab8a`.

Compilation plus InstallationProjection application and
`tools.materialize_permission_proposals` produced
`ouf-onboarding:8080` for:

- `mcp-permissions-read`;
- `mcp-permissions-propose`;
- `mcp-permissions-status`;
- `authorization-ths-page`;
- `authorization-ths-api`;
- `authorization-ths-login`.

The live pre-deploy comparison showed `mcp-permissions-read` already fixed and
the remaining five routes still pointing to `ouf-source-onboarding:8080`.
Those five live route documents were backed up and only those five IDs were
updated through the APISIX Admin API.

The post-deploy etcd read-back confirmed all six routes on
`ouf-onboarding:8080`. A read-only MCP smoke test,
`authorization.permissions.read` with `view=ROLES` under the governed
`ouf-admin` identity, succeeded and returned the expected role catalogue.

This is deployed evidence that the runtime route drift was removed without
requiring a schema relaxation, body-forwarding change, container rebuild or
Keycloak change.
