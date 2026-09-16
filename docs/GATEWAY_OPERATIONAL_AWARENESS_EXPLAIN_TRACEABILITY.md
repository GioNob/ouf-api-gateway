# Gateway Operational Awareness — incident explain

Normative baseline: Gateway PET v1.4 Operational Awareness, MCP PET v1.3, Authorization PET v1.5, Cross-Module Alignment Matrix v1.6.

Adds the governed capability `ouf.operations.explain` with scope `operations.incident.explain` and a northbound internal route restricted to `ouf-mcp-server`. The backend is the registered Ingestion operational endpoint `/api/internal/v1/ingestion/operations/incidents/explain`.

CI evidence proves schema/config compilation and reference integrity. Real APISIX runtime, Authorization decisions and deployed packet-level enforcement remain EVIDENCE PENDING.
