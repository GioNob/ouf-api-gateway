# Gateway 1C MCP capability binding traceability

Normative baseline: Urban API Gateway PET v1.3 §§20–23 and T29.1–T29.5, MCP Server PET v1.2 §§2.1, 38 and 68, plus Cross-Module Alignment Matrix v1.5.

| PET control | Gateway 1C evidence | State after CI |
|---|---|---|
| GWMCP-01 / GW-A15 | caller supplies only `capability://` binding; service and backend path come exclusively from compiled configuration | Candidate VERIFIED at adapter boundary |
| GW-A04 / GW-QGOV-02/03 | backend status, body, `Problem Details` and `Retry-After` pass through after exactly one upstream invocation | Candidate VERIFIED |
| GW-A07 | `humanRequired` capability rejects MCP/non-human actor before upstream | Candidate VERIFIED at policy boundary |
| GW-A10/GW-A11 | authenticated M2M identity, scope, decision reference, correlation, actor, tenant, attempt and idempotency context are checked and propagated | Candidate VERIFIED at adapter boundary |
| T29.5 | `toolEligible` is necessary for registry exposure but never grants scope; cognitive metadata does not affect authorization | Candidate VERIFIED |
| MCP→Gateway→UDP micro-pairwise | exact Go MCP 1C envelope fixture resolves to the published UDP related-search service/path and typed arguments | Candidate VERIFIED at contract boundary |
| Gateway→Onboarding regression | original managed-file micro-pairwise remains green with route selected by stable ID | VERIFIED regression |

Real APISIX/etcd convergence, IAM token cryptography, CNI/NetworkPolicy egress enforcement and deployed UDP end-to-end execution are deliberately not claimed by this increment.
