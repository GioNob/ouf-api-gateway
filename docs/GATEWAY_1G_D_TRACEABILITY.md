# Gateway 1G-D — IAM/runtime identity boundary

Normative baseline: Urban API Gateway PET v1.3 identity/authentication trust-boundary requirements. This increment intentionally stops at the verifier port because the OUF Authorization module and adopted IAM integration are not yet implemented.

| Obligation | Evidence | Status |
|---|---|---|
| identity derives from trusted authentication, never request payload | `IdentityBoundary` accepts only `VerifiedCredential` from verifier port | CI CANDIDATE |
| issuer+subject mapped by governed trust binding | exact tuple lookup; unknown subject fails closed | CI CANDIDATE |
| audience binding | required Gateway audience checked after cryptographic-verifier boundary | CI CANDIDATE |
| scopes are not caller-normalized | scopes copied only from verifier output | CI CANDIDATE |
| actor/service identity normalization | governed binding supplies `servicePrincipalId` and `actorType` | CI CANDIDATE |
| authentication evidence reference | credential ID and `authentication_context_ref` mandatory | CI CANDIDATE |
| workload trust catalog | `config/trust-bindings-v1.yaml` | CI CANDIDATE as configuration contract |
| real signature/JWKS/certificate validation | adopted IAM verifier | EVIDENCE PENDING |
| credential rotation/revocation lifecycle | adopted IAM/deployment | EVIDENCE PENDING |
| Authorization decision/policy evaluation | separate Authorization physical module | NOT IMPLEMENTED; must not be simulated here |
| IAM scenario A/B/C selection | architecture/deployment decision prescribed by PET | EVIDENCE PENDING; no scenario invented by Gateway |

## Boundary

1G-D establishes the contract into which the adopted IAM verifier must plug. A fake verifier proves fail-closed normalization semantics only; it is not accepted as evidence of cryptographic authentication or Authorization. No PET deviation is introduced.
