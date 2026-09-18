# R3a.1j — ChatGPT OAuth discovery for the public MCP boundary

Normative basis:
- OUF Reality Baseline Package v1.7;
- Gateway PET v1.5 boundary enforcement and configuration-as-code controls;
- Authorization PET v1.5 HUMAN/AI/SERVICE separation and default-deny policy;
- MCP PET v1.4 Gateway-only northbound admission;
- MCP Authorization protected-resource metadata;
- OpenAI MCP OAuth authorization-code + PKCE integration requirements.

## Goal

Make the governed public MCP endpoint discoverable by OAuth-capable remote clients without weakening its existing bearer-token enforcement.

The protected endpoint remains:

`POST https://api.ouf-lab.it/mcp`

The public discovery endpoint is:

`GET https://api.ouf-lab.it/.well-known/oauth-protected-resource`

## Security boundary

The Gateway continues to validate issuer, signature, expiry, audience, `mcp.connect`, actor type and mandatory trusted claims before forwarding any MCP request. The MCP route remains `bearer_only`; APISIX does not create browser sessions and never receives or stores a HUMAN password.

An unauthenticated request returns `401` with a challenge that points to the protected-resource metadata:

```text
WWW-Authenticate: Bearer resource_metadata="https://api.ouf-lab.it/.well-known/oauth-protected-resource", scope="mcp.connect"
```

The metadata response is generated from the InstallationProjection and governed route policy. It publishes only:

- canonical MCP resource URL;
- governed authorization-server issuer;
- bearer header support;
- required transport scope.

No secret, client credential, token, role or tenant data is published.

## APISIX materialization

`tools/materialize_apisix_runtime.py` emits two native APISIX routes:

1. the existing OIDC-protected `POST /mcp` route, now with a conditional `response-rewrite` that replaces the generic APISIX challenge only for `401` responses;
2. a rate-limited, GET-only protected-resource metadata route with a deterministic JSON response and no upstream.

Both the issuer and public API base URL must be canonical HTTPS URLs. The public API base URL must be an origin without a path, query or fragment. Invalid projection values fail materialization.

The static metadata response uses only a standard APISIX plugin. No custom plugin or image is introduced.

## Atomic deployment and rollback

`ops/apisix/deploy_mcp_route.sh` treats the two routes as one publication unit:

1. validate cross-route consistency before contacting APISIX;
2. snapshot both prior routes;
3. publish metadata before the protected MCP route;
4. read back both routes;
5. require metadata HTTP `200` with exact governed fields;
6. require unauthenticated MCP HTTP `401` with the exact `resource_metadata` challenge;
7. restore both prior routes if any gate fails.

The Admin key and OIDC client secret remain file/environment references and are never printed.

## Deliberate separation from IAM client registration

This increment enables standards-based discovery only. A ChatGPT OAuth client is configured separately in the selected IAM using Authorization Code + PKCE and least privilege. It is not the workload client `ouf-mcp-server`; client credentials remain reserved for service/workload identity.

The redirect URI must be copied exactly from the ChatGPT MCP connection management page. IAM activation remains an environment-specific acceptance action and is not embedded in the repository.

## Acceptance gates

- repository verification and tests green;
- both routes accepted by APISIX 3.18;
- metadata is public and exact;
- unauthenticated `/mcp` returns `401` plus the discovery challenge;
- wrong audience and missing scope remain denied;
- the existing workload-token MCP handshake remains `200`;
- ChatGPT completes Authorization Code + PKCE against the governed HUMAN/AI client;
- discovered tools match the MCP server manifest;
- restart preserves both routes and rollback evidence is retained.
