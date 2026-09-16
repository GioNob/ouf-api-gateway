# Gateway channel-neutral Operational Awareness traceability

Normative baselines: Gateway PET v1.5 and Cross-Module Alignment Matrix v1.7.

`ouf.system.status` is owned by MCP but exposed as a channel-neutral Gateway capability. The internal M2M route and public OIDC route both resolve to `service://ouf-mcp-server` at `/api/internal/v1/mcp/operations/status`. No `ouf.system.status` backend points to `/mcp`, preventing protocol recursion.

CI evidence verifies config compilation, capability/backend consistency and route-policy separation. Deployed APISIX, OIDC and packet-level NetworkPolicy enforcement remain EVIDENCE PENDING.
