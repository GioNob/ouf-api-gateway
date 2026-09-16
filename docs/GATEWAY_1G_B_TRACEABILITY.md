# Gateway 1G-B — Adopted APISIX runtime control-plane transport

Normative baseline: Urban API Gateway PET v1.3 T33 publication/control-plane requirements, GW-ETCD-03/GW-ETCD-04 and the adopted APISIX 3.18.x runtime boundary.

| Obligation | Evidence | Status |
|---|---|---|
| concrete APISIX Admin API transport | `tools/apisix_admin_http.py` uses the adopted Admin API over HTTPS | CI CANDIDATE at transport boundary |
| Admin API credentials not in URL | URL userinfo rejected; API key sent only in header | CI CANDIDATE |
| TLS server verification | Python default verified TLS context; optional CA bundle | CI CANDIDATE |
| bounded request timeout | every Admin API request has an explicit timeout | CI CANDIDATE |
| immutable staged revision readback | concrete transport stores/reads content-addressed publication metadata; `APISIXControlPlane` verifies equality | CI CANDIDATE |
| activation convergence | active revision metadata is read repeatedly until bounded deadline | CI CANDIDATE |
| last-known-good | Publisher advances ACTIVE only after every verification gate and activation; failed staged revision is discarded | existing CI VERIFIED + concrete transport candidate |
| runtime authorization negative-path | transport refuses to synthesize this result | EVIDENCE PENDING until adopted APISIX runtime test |
| runtime upstream reachability | transport refuses to synthesize this result | EVIDENCE PENDING until adopted APISIX runtime test |
| etcd quorum/partition/restart/member-loss | requires adopted multi-member etcd fault environment | EVIDENCE PENDING |
| direct etcd publication bypass denial | requires deployed IAM/NetworkPolicy/etcd ACL evidence | EVIDENCE PENDING |

## Important evidence boundary

This increment makes the Admin API transport concrete but does not label mocked HTTP tests as a real APISIX deployment. In particular `authorizationNegativePath` and `upstreamReachability` remain false in the generic transport probe, so the Publisher cannot activate merely because Admin API storage works. A deployed runtime probe must supply those gates before production activation can succeed.
