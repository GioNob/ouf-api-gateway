# Gateway 1G-C — Security and network boundary

Normative baseline: Urban API Gateway PET v1.3 GW-NET-01..05, T33.8 and acceptance controls GW-A13..GW-A16.

| PET control | Evidence | Status |
|---|---|---|
| GW-A13 southbound default-deny | `helm/networkpolicy/southbound-default-deny.yaml` selects southbound pods with ingress+egress default deny | CI CANDIDATE manifest contract; deployed packet evidence pending |
| GW-A14 SSRF adversarial | `southbound_security.validate_destination/validate_redirect` rejects host/port substitution, loopback, link-local/metadata, multicast/reserved, unregistered private IP, CIDR mismatch and host-changing redirects | CI CANDIDATE |
| GW-NET-04 DNS rebinding | every resolved address must remain inside the registered CIDR set when CIDR-bound; mixed answers fail closed | CI CANDIDATE; dynamic FQDN CNI evidence pending |
| GW-A15 registry-bound upstream | destination scheme/host/port must exactly match registered endpoint; caller URL cannot replace them | CI CANDIDATE |
| GW-A16 ingestion bypass prevention | baseline Ingestion egress policy allows only `apisix-southbound` in `ouf-gateway` | CI CANDIDATE manifest contract; deployed compromised-Pod test pending |
| GW-NET-03 dynamic FQDN | broad Internet CIDRs are explicitly not introduced; FQDN-aware CNI/equivalent remains required | EVIDENCE PENDING |
| independent network allowlist | application SSRF validation and NetworkPolicy are separate cumulative controls | IMPLEMENTED boundary |

## Evidence boundary

CI can verify policy manifests and deterministic anti-SSRF logic, but it cannot prove that the target Kubernetes CNI enforces them. GW-A13 and GW-A16 therefore remain deployment-evidence pending until packet-level tests run in the adopted cluster. No PET deviation is introduced.
