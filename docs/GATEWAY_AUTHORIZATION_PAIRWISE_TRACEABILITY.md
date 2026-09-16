# Gateway ↔ Authorization pairwise traceability

## Baseline

Reality Baseline Package v1.7; Authorization PET v1.5; Urban API Gateway PET v1.5; Cross-Module Alignment Matrix v1.7.

## Implemented evidence

- Gateway identity normalization preserves the Authorization principal fields needed downstream: principal/subject, tenant, actor type, authentication context reference, issuer, audience and scopes.
- Tenant context is fail-closed: it must come from the verified credential mapping or a governed trust binding.
- Gateway actor vocabulary is aligned to Authorization SDK values `HUMAN`, `SERVICE`, `AI_AGENT`; module-specific labels such as `MCP_SERVER` are not used as Authorization actor types.
- Capability coarse enforcement uses the governed capability `spec.scope` and only scopes from a cryptographically verified credential.
- Wrong audience, unbound identity, missing verification evidence, missing tenant and missing scope are fail-closed.
- The Gateway coarse gate does not evaluate fine-grained grants or resource predicates. Those remain owner-local through the shared Authorization policy bundle/evaluator.
- The pairwise is pinned to Source Onboarding / Authorization main `fb2dd51dfc204577a47c1e702f17531dd0709b3c` and its `authorization-sdk-v1.json` contract.

## CI evidence

- `tests/test_identity_boundary.py` verifies trusted normalization and negative identity cases.
- `tests/test_authorization_gateway_pairwise.py` verifies SDK principal vocabulary, scenario-neutrality, capability scope alignment, positive coarse authorization and missing-scope denial.
- Full Gateway `scripts/verify.sh` remains the regression gate.

## Evidence pending

Repository CI does not claim deployed IAM integration. The following remain external/deployment evidence pending until IAM scenario A/B/C is selected and deployed:

- real issuer/JWKS validation and key rotation;
- concrete claim-to-tenant mapping;
- real OIDC/M2M audience configuration;
- trusted header injection/stripping at APISIX/data-plane boundaries;
- workload identity and revocation behavior;
- multi-Pod policy/cache convergence for components that consume Authorization bundles;
- end-to-end direct API and MCP channel security equivalence under real identities.
