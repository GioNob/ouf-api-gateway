# Gateway Operational Awareness — PET v1.4 traceability

Normative baseline: Gateway PET v1.4 and Cross-Module Alignment Matrix v1.6.

## Implemented evidence

- Registers `ingestion-runtime-operations@1.0.0` as a governed logical backend.
- Adds MCP-eligible capabilities `ouf.ingestion.status`, `ouf.ingestion.history`, `ouf.operations.incidents`, and `ouf.operations.summary`.
- Each capability has a distinct Authorization scope and `TENANT_OPERATIONAL` classification.
- Adds internal POST routes from `ouf-mcp-server` to the bounded Ingestion operational API.
- Route inputs cannot substitute host/port; backend remains `service://ouf-ingestion-runtime`.
- Capability schema now recognizes operational visibility classifications introduced by PET v1.4.

## Evidence boundary

This is configuration/control-plane evidence. Real APISIX routing, identity propagation, Authorization decisions and packet-level NetworkPolicy remain deployment evidence pending. Gateway-owned incident production (etcd/upstream/trust recovery aggregation) is a separate producer-hardening tranche.
