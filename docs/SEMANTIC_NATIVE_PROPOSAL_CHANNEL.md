# Native semantic proposal mediation

The four additive routes use the existing MCP workload/OIDC and signed human delegation. The Gateway produces a distinct `semantic-proposal-owner` receipt bound to capability, path, original envelope, principal, tenant and expiry. Read-only semantic receipts cannot authorize these endpoints. Owner policy is checked independently on every call; approval/publication and THS operations are excluded.

`materialize_semantic_proposal.materialize` requires explicit installation IDs, upstream and custody environment bindings. It preserves existing routes and rejects duplicates for reconciliation. Route schemas are closed and bounded to 65,536 bytes and 21 native commands. Upstream retries are zero: owner receipts and the stable proposalKey support reconciliation after a lost response; Gateway never retries an ambiguous mutation.

Gateway Lua/schema tests use synthetic identities and OpenSSL equivalents. Actual OIDC/APISIX enforcement, key custody, owner policy grants, target migration, route installation and THS rendering remain deployment gates. No grants, keys or installed routes are changed by creating this source change.
