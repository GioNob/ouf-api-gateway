# Semantic read mediation — candidate

Base source `2b1c84c9081898aa305c1eb06e90406994393acd`; live APISIX resource state
is preserved by add-only materialization, not inferred from this source branch.

`tools.materialize_semantic_read.materialize` consumes an existing materialized runtime,
resolved installation issuer/audience/workload, two distinct key environment names,
Semantic upstream binding and two installation-owned route IDs. No host, domain,
tenant, network, secret path or service identity default. Existing routes remain unchanged.
Route drift/collision fails for reconciliation; this function is not a live plan/apply installer.

Fixed execute paths `/internal/capabilities/v1/execute/semantic/search` and `/semantic/get`
map to read-only owner POST `/api/internal/v1/semantic/consultation/search` and `/get`.
Bounded closed input; OIDC workload and signed delegation checked before a short-lived
purpose/body/path/capability/tenant-bound receipt. Client-provided authority headers,
bearer/cookie/delegation are stripped. Signing key never enters MCP.

Owner bindings: `ouf.semantic.delegation.key-file`, `ouf.semantic.delegation.workload`,
`ouf.iam.issuer`, `ouf.iam.audience`. Receipt key is 64 hex characters as ASCII bytes,
matching existing OUF owner receipt convention. Use a dedicated key distinct from delegation.
No receipt can authorize Semantic approval, publication, adoption or direct database access.

Remote network/TLS/trust configuration remains an explicit deployment gate. Tests against
Lua mocks prove software signing/dispatch rules; they do not prove deployed APISIX/JWKS/TLS.
Before rollout: fresh policy/scopes/route readback, compatible owner and MCP candidates,
private snapshot/rollback and existing picker/Search regression. Do not re-enable Cinema runs.
