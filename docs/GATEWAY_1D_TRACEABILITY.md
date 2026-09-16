# Gateway 1D — MCP recovery mediation

Normative baseline: API Gateway PET v1.3 capability/binding, workload identity and default-deny controls, aligned with MCP Server PET v1.2 §§77, 80 and 111.

| Control | Executable evidence |
|---|---|
| Governed owner binding | `ownerOutcomePath` belongs to the versioned UDP source profile and compiles with capability owner/service; request schema has no URL, service or path field. |
| Workload authorization | only `ouf-mcp-server` with `mcp.attempt.recover` may enter the mediator. |
| Exact recovery identity | capability and owner must match the registry; correlation header must match the request; backend request IDs use a closed format. |
| No blind terminal inference | owner non-200/unavailable and malformed or mismatched evidence cannot become a terminal outcome. |
| Normalized outcomes | only `SUCCEEDED`, `FAILED`, `NOT_DISPATCHED` and `UNKNOWN` are returned, with bounded non-negative actual costs. |
| Owner proof | `OWNER_PROVES_NO_DISPATCH` is preserved with zero cost for MCP's deterministic release transition. |
| Pairwise owner adapter | a real loopback HTTP owner receives exactly one GET on the compiled UDP outcome path with correlation and recovery headers. |

The coordinated Go `RecoveryClient` → Gateway HTTP endpoint test will be pinned to the eventual Gateway 1D merge SHA in the MCP repository after this increment merges. Evidence Inbox, cryptographic evidence verification, `maxUnknownHold`, `UNRESOLVED` and late compensation remain MCP 1E scope.
