# R3a.1h — APISIX MCP route materialization

Normative basis:
- OUF Reality Baseline Package v1.7;
- Cross-Module Alignment Matrix v1.7;
- Gateway PET v1.5 deployment/configuration controls;
- MCP PET v1.4 Gateway-only admission boundary;
- R3a.1d InstallationProjection-mediated Gateway configuration.

## Goal

Materialize the already compiled and InstallationProjection-resolved public MCP endpoint into live APISIX without bypassing the Gateway security boundary.

Target path:

`POST /mcp`

Expected path:

`client -> Caddy -> APISIX -> ouf-mcp-server:8080/mcp`

## Runtime compilation contract

The compiler now preserves the MCP backend coordinates required for deployment:

- service name;
- port;
- backend path.

These coordinates remain governed configuration and are emitted as `x-ouf-backend-binding`.

## APISIX materialization

`tools/materialize_apisix_runtime.py` converts the resolved OUF runtime artifact into a native APISIX Route.

For the public MCP endpoint it produces:

- exact method/path: `POST /mcp`;
- upstream to the governed MCP service/port;
- request ID and rate limit;
- bounded request body size;
- bearer-only `openid-connect`;
- exact issuer discovery URL from the InstallationProjection;
- audience match against the resolved Gateway audience;
- required scope `mcp.connect`;
- JWKS token verification;
- fail-closed actor vocabulary;
- trusted-header stripping before authentication;
- trusted identity reconstruction only after successful OIDC verification;
- removal of the original Authorization header before proxying.

OIDC secret material is never embedded in the artifact. The materializer accepts only an APISIX secret reference such as:

`$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET`

## Trusted identity reconstruction

The APISIX access pipeline reconstructs only:

- `X-OUF-Gateway-Verified`;
- `X-OUF-Service-Principal`;
- `X-OUF-Principal-ID`;
- `X-OUF-Tenant-ID`;
- `X-OUF-Actor-Type`;
- `X-OUF-Authentication-Context-Ref`;
- `X-OUF-Token-Issuer`;
- `X-OUF-Token-Audience`;
- `X-OUF-Granted-Scopes`.

Client-supplied values for those headers are removed before the OIDC decision.

## Deployment

`ops/apisix/deploy_mcp_route.sh`:

1. requires a materialized route artifact;
2. requires an APISIX Admin key file;
3. requires the APISIX container name;
4. verifies the OIDC secret environment reference exists in the APISIX container;
5. snapshots any previous route;
6. publishes through the loopback-only APISIX Admin API using a sidecar sharing the APISIX network namespace;
7. performs read-after-write;
8. requires unauthenticated `POST /mcp` to return 401/403;
9. restores or deletes the new route if acceptance fails.

The script never prints the Admin key or OIDC client secret.

## Deployment boundary

This increment closes native route materialization and the negative authentication path.

Positive authenticated MCP acceptance still requires:
- a confidential Gateway OIDC client/secret bound to the APISIX secret reference;
- the MCP runtime container reachable as the projected service;
- a real access token with audience `ouf-api-gateway` and scope `mcp.connect`;
- representative MCP protocol request through the public HTTPS endpoint.
