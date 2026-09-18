# R3a.1i APISIX Authorization bundle route materialization

Normative basis: Reality Baseline Package v1.7, Cross-Module Alignment Matrix v1.7, Gateway PET v1.5, Authorization PET v1.5 and MCP PET v1.4.

## Goal

Materialize the existing governed internal capability route used by MCP Server to refresh the active Authorization policy bundle.

The route is:

`GET /internal/capabilities/v1/authorization/policy-bundle/active`

and proxies to Source Onboarding:

`/api/internal/v1/authorization/policy-bundle/active`

## Security boundary

The APISIX route validates issuer, Gateway audience, required scope `authorization.bundle.read`, actor type `SERVICE` and the projection-resolved MCP service identity. Client-supplied trusted headers are stripped. The bearer token is preserved because Source Onboarding independently validates the signed token and constructs its server-local trusted principal.

No direct MCP-to-Source-Onboarding bypass is introduced. No secret value is embedded in generated artifacts.

## Deployment

`tools/materialize_apisix_authorization_runtime.py` creates the native APISIX route. `ops/apisix/deploy_authorization_bundle_route.sh` publishes it through the loopback-only Admin API, performs read-after-write and negative authentication acceptance, and rolls back on failure.

Positive acceptance is the MCP Server Authorization bundle bootstrap using its renewable workload identity.
