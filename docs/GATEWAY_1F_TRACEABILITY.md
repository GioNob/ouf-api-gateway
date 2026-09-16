# Gateway 1F — Control-plane hardening

Normative baseline: Urban API Gateway PET v1.3 publication, last-known-good, default-deny and control-plane requirements already established for this repository.

| Obligation | Evidence | Status |
|---|---|---|
| real control-plane boundary separated from compiler/publisher | `APISIXControlPlane` implements the existing publication port | CI VERIFIED |
| immutable/hash-pinned staged revision | canonical content-addressed `sha256:` revision | CI VERIFIED |
| no success from write acknowledgement alone | stage requires read-after-write equality | CI VERIFIED |
| verification is fail-closed | health, route binding, authorization negative path, upstream reachability and convergence must all be true | CI VERIFIED |
| activation convergence | active revision is read back and must equal staged revision | CI VERIFIED |
| preserve last-known-good on failed verification/activation | existing Publisher advances ACTIVE manifest only after successful activation; rollback refuses deletion of an active revision | CI VERIFIED |
| APISIX/etcd adapter fault semantics | unit tests cover corrupt readback, failed governance probe and non-converging activation | CI VERIFIED at adapter boundary |
| real APISIX 3.18.x Admin API transport | requires environment/secret/TLS configuration and deployed integration | EVIDENCE PENDING |
| real etcd quorum/partition/restart fault injection | deployment evidence | EVIDENCE PENDING |
| HA/HPA/PDB/NetworkPolicy and representative performance | deployment evidence | EVIDENCE PENDING |

## CI evidence

Gateway PR #7 head `99a2406a49dde22fc705912068c04c2dbb5b254c` passed the complete repository `scripts/verify.sh` gate in Actions run #30 before merge. Stable Gateway 1F main merge is `b75816e9f102b936a8b35b02958029edd7623506`.

## Cross-module review after MCP/Gateway 1F

Stable MCP 1F is `7b472d545e0a1f7ecf1a08ebc6d9feef92928b3f`. MCP 1F changes maintenance, debt-cache reconciliation and governed retention; it does not alter the Gateway dispatch, recovery or evidence-ingress wire contracts already pairwise verified in 1E. Gateway 1F changes publication/control-plane semantics and does not alter those MCP wire contracts. No new MCP↔Gateway pairwise dependency is therefore introduced by either 1F increment.

## Scope boundary

Gateway 1F does not claim that a fake Admin port proves an APISIX/etcd deployment. It closes the fail-closed control-plane semantics in code so that a subsequent environment-backed adapter/integration cannot weaken publication invariants. No PET deviation is introduced.
