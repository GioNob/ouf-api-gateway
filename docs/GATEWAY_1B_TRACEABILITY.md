# Gateway 1B controlled publication traceability

Normative baseline: Urban API Gateway PET v1.3 and Cross-Module Alignment Matrix v1.5 in Reality Baseline Package v1.6.

| PET clause | Gateway 1B evidence | State after CI |
|---|---|---|
| T33.3 validate/compile/stage/verify/activate/record | `Publisher` state machine and success/failure tests | Candidate VERIFIED at adapter boundary |
| Git acceptance is not ACTIVE | only successful convergence plus every verification gate writes `active.json` | Candidate VERIFIED at adapter boundary |
| GW-ETCD-03 batching/coalescing/backpressure | latest change per object, bounded batch and exclusive publication lease | PARTIAL — real APISIX/etcd load pending |
| GW-ETCD-04 / GW-A19 last-known-good | degraded control plane blocks stage; verification failure rolls back and leaves active manifest unchanged | PARTIAL — adopted APISIX runtime fault test pending |
| PublicationManifest evidence | canonical v1 schema, immutable ID, source revision, input hashes, artifact hash, control-plane revision and outcome | Candidate VERIFIED |
| Ownership boundary | compiler consumes Onboarding projections and never changes them or writes directly to etcd | Candidate VERIFIED statically |

Not claimed: live APISIX Admin/Gateway API writes, etcd convergence, WAL fault injection, member loss/restore, IAM integration, NetworkPolicy enforcement or MCP dispatch. Those require environment-backed increments and corresponding PET evidence.
