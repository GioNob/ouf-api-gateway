# Operational Awareness aggregation routing traceability

Normative baseline: OUF Reality Baseline Package v1.7, MCP PET v1.4, Gateway PET v1.5 and Cross-Module Alignment Matrix v1.7.

- Global human-facing `ouf.operations.incidents` and `ouf.operations.summary` are MCP-owned aggregation capabilities, not Ingestion aliases.
- MCP and future UI/API bindings converge on the same private MCP owner endpoints; no binding targets `/mcp`.
- Ingestion and Gateway expose separate non-tool internal producer primitives. Producer truth remains owned by the producing module.
- Producer primitives are callable only through Gateway mediation by the MCP service identity.
- Authorization/IAM deployed enforcement remains `EVIDENCE PENDING`; repository tests prove configuration intent and compile-time coherence only.
