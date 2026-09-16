# Gateway 1G — Runtime policy enforcement boundary

Normative baseline: Urban API Gateway PET v1.3 default-deny, identity, capability/scope, request-bound and registry-owned route policy requirements already established for this repository.

| Obligation | Evidence | Status |
|---|---|---|
| compiled policy is authoritative at runtime | `policy_enforcement.enforce` consumes only `x-ouf-policy` from compiled route | IMPLEMENTED |
| unauthenticated requests fail closed | explicit 401 before upstream I/O | IMPLEMENTED |
| identity mode cannot be selected by caller | trusted `RequestIdentity.identity_mode` must equal compiled policy | IMPLEMENTED |
| internal service allowlist | service principal must belong to compiled allowlist | IMPLEMENTED |
| actor-type restriction | actor must belong to compiled actor allowlist when present | IMPLEMENTED |
| capability scope enforcement | compiled `requiredScope` is mandatory and must be present in trusted scopes | IMPLEMENTED |
| request-size enforcement | compiled `maxRequestBytes` rejects known oversized requests | IMPLEMENTED |
| malformed/missing runtime policy | fail-closed 503/403 semantics | IMPLEMENTED |
| negative-path suite | unauthenticated, wrong mode/service/actor, missing scope, oversized and missing policy | CI CANDIDATE |
| real OIDC/M2M/mTLS token verification | Authorization/IAM and deployed APISIX integration | EVIDENCE PENDING |
| streaming body over-limit enforcement | requires adopted APISIX request-body/runtime integration | EVIDENCE PENDING |
| deployed NetworkPolicy and workload identity | environment evidence | EVIDENCE PENDING |

## Scope boundary

1G establishes the deterministic enforcement kernel for policy already compiled from governed registry projections. It does not invent an identity provider, accept identity claims from request payloads, or claim deployed APISIX/IAM evidence. No PET deviation is introduced.
