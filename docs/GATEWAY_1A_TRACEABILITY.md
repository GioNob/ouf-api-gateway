# Gateway 1A traceability

Normative baseline: Urban API Gateway PET v1.3 in Reality Baseline Package v1.6, MCP Server PET v1.2, Source Onboarding PET v1.5 and Cross-Module Alignment Matrix v1.5.

This increment establishes the Git-to-compiled-configuration boundary. It does not claim deployed APISIX, IAM, Kubernetes NetworkPolicy, etcd convergence, performance, DR or end-to-end evidence.

| Requirement | Gateway 1A evidence | State after CI |
|---|---|---|
| T9/T32.2 versioned runtime artifacts | Closed schemas plus versioned capability, source, extraction and route documents | Candidate VERIFIED |
| T9.2/T33.14 active/reference gate | ACTIVE-only schemas and exact `id@version` resolution | Candidate VERIFIED |
| T5 capability-bound route | Every compiled route resolves capability and logical source before output | Candidate VERIFIED |
| GW-NET-01/GW-A15 registry-bound upstream | Caller has no URL/host/port field; physical HTTP endpoint in consumed source profile fails closed | Candidate VERIFIED |
| GW-A10 internal identity | Internal route requires an explicit service-identity allowlist | PARTIAL — runtime mTLS/IAM remains environment-bound |
| Gateway–Onboarding micro pairwise | Exact GET path, `ref=object://...`, 10 MiB bound and Onboarding identity fixture | Candidate VERIFIED at mock boundary |
| Correlation generation/propagation | APISIX 3.18 `request-id` plugin preserves a supplied `X-Correlation-ID` or generates UUID and returns it | Candidate VERIFIED as compiled configuration; runtime pending |

The generated APISIX-shaped document is deterministic and includes a SHA-256 over canonical configuration. Git acceptance does not make a configuration ACTIVE; APISIX/etcd convergence and a PublicationManifest are later increments.
