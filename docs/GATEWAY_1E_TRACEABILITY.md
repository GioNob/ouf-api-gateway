# Gateway 1E — MCP Evidence Ingress traceability

Normative baseline: Urban API Gateway PET v1.3 plus MCP Server Go Implementation Baseline v1.2 and cross-module identity/integration invariants from Reality Baseline Package v1.6.

| Obligation | Evidence in this increment | Status |
|---|---|---|
| Owner evidence enters MCP only through a governed boundary | `tools/mcp_evidence_ingress.py` | IMPLEMENTED |
| Backend owner is derived from authenticated trusted workload identity, never selected by payload | fixed service-principal → owner binding; payload owner is consistency-only | IMPLEMENTED |
| Dedicated owner evidence scope | `mcp.evidence.submit` required before network I/O | IMPLEMENTED |
| Canonical evidence contract and bounded payload | `schemas/mcp-evidence-ingress-v1.json`, 1 MiB ingress bound | IMPLEMENTED |
| OWNER_RESULT and OWNER_PROVES_NO_DISPATCH validation | mediator validation and tests | IMPLEMENTED |
| Object hash version fail-closed | only admitted `v1` forwarded | IMPLEMENTED |
| MCP replay/conflict semantics preserved | 200/201/409 returned without semantic rewriting | IMPLEMENTED |
| Correlation propagation without sensitive payload logging | correlation is required and forwarded; mediator emits no payload log | IMPLEMENTED |
| Direct owner access to MCP persistence prohibited | requires deployed IAM/DB/network-policy evidence | EVIDENCE PENDING |
| Real workload-token cryptography and role denial | requires deployed IAM evidence | EVIDENCE PENDING |
| Gateway↔MCP concurrency/replay pairwise | coordinated follow-up after this Gateway increment | PENDING PAIRWISE |

This increment does not promote MCP-A52 by itself. Promotion requires the coordinated Gateway↔MCP evidence pairwise and role-denial evidence required by the MCP PET.
