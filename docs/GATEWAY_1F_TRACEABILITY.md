# Gateway 1F — Control-plane hardening

Normative baseline: Urban API Gateway PET v1.3 publication, last-known-good, default-deny and control-plane requirements already established for this repository.

| Obligation | Evidence | Status |
|---|---|---|
| real control-plane boundary separated from compiler/publisher | `APISIXControlPlane` implements the existing publication port | IMPLEMENTED |
| immutable/hash-pinned staged revision | canonical content-addressed `sha256:` revision | IMPLEMENTED |
| no success from write acknowledgement alone | stage requires read-after-write equality | IMPLEMENTED |
| verification is fail-closed | health, route binding, authorization negative path, upstream reachability and convergence must all be true | IMPLEMENTED |
| activation convergence | active revision is read back and must equal staged revision | IMPLEMENTED |
| preserve last-known-good on failed verification/activation | existing Publisher advances ACTIVE manifest only after successful activation; rollback refuses deletion of an active revision | IMPLEMENTED |
| APISIX/etcd fault semantics | adapter unit tests cover corrupt readback, failed governance probe and non-converging activation | CI CANDIDATE |
| real APISIX 3.18.x Admin API transport | requires environment/secret/TLS configuration and deployed integration | EVIDENCE PENDING |
| real etcd quorum/partition/restart fault injection | deployment evidence | EVIDENCE PENDING |
| HA/HPA/PDB/NetworkPolicy and representative performance | deployment evidence | EVIDENCE PENDING |

## Scope boundary

Gateway 1F does not claim that a fake Admin port proves an APISIX/etcd deployment. It closes the fail-closed control-plane semantics in code so that a subsequent environment-backed adapter/integration cannot weaken publication invariants. No PET deviation is introduced.
