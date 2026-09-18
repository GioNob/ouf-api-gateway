# R3a — Remote MCP exposure through the Urban API Gateway

Normative baseline: Reality Baseline Package v1.7, Cross-Module Alignment Matrix v1.7, Gateway PET v1.5, MCP Server PET v1.4 Go and Authorization PET v1.5.

This increment exposes the MCP protocol endpoint as a governed northbound transport. It does not turn the transport itself into a business capability and does not weaken per-tool Authorization/admission.

## Architectural rule

The external client never reaches `ouf-mcp-server` directly.

```text
Remote MCP client
      |
      | HTTPS + OIDC bearer
      v
Urban API Gateway
      |
      | verified identity context only
      v
ouf-mcp-server:8080/mcp
      |
      | local Authorization/admission per tool
      v
Gateway southbound -> owner modules
```

The route is represented by `McpEndpointBinding`, not `RouteBinding`, because a single MCP transport endpoint multiplexes multiple tool capabilities. A synthetic transport capability would conflate connection admission with tool authorization.

## Governed transport contract

Public endpoint:
- method: `POST`
- path: `/mcp`
- transport: MCP Streamable HTTP
- MCP protocol version: `2026-07-28`
- stateless: true
- backend: `ouf-mcp-server:8080/mcp`

Gateway admission:
- identity: OIDC
- required audience: `ouf-api-gateway`
- required transport scope: `mcp.connect`
- allowed canonical actor types: `HUMAN`, `AI_AGENT`, `SERVICE`
- request body cap: 1 MiB
- bounded timeout and rate limit

`mcp.connect` authorizes reaching the MCP protocol boundary only. It does not authorize any MCP tool. Tool calls still require their own Authorization capability/scope/grant and are evaluated locally from the active PolicyBundle.

## Trusted identity boundary

The Gateway must remove every client-supplied trusted OUF identity header before forwarding. The governed set is:

- `X-OUF-Gateway-Verified`
- `X-OUF-Service-Principal`
- `X-OUF-Principal-ID`
- `X-OUF-Tenant-ID`
- `X-OUF-Actor-Type`
- `X-OUF-Authentication-Context-Ref`
- `X-OUF-Token-Issuer`
- `X-OUF-Token-Audience`
- `X-OUF-Granted-Scopes`

After successful token verification, the Gateway reconstructs the trusted identity from validated claims and injects `X-OUF-Gateway-Verified: true`. Client headers are never an authority.

The compiler fails closed if any trusted header is omitted from the stripping set or if the claim projection is incomplete.

## Identity separation

The remote caller identity and the internal MCP workload identity are different concepts.

- The northbound `/mcp` request preserves the external principal/actor/tenant/authentication context.
- When MCP later calls Gateway southbound, the service principal remains `ouf-mcp-server` while the delegated principal context is propagated separately.
- No HUMAN password, MFA material or privileged HUMAN token is stored by MCP.

## Repository evidence in this increment

- `schemas/mcp-endpoint-binding-v1.json`: transport-specific governed schema.
- `ouf-config/protocol/mcp-endpoint.yaml`: desired public MCP endpoint.
- `tools/compile_config.py`: compiles the protocol route without a synthetic capability.
- `tests/test_config.py`: positive contract and forged-header fail-closed regression tests.

## Exit gates before deployed acceptance

Repository CI is not production acceptance. R3a is deployable only after all of the following are exercised against the real environment:

1. APISIX route materialization from the compiled protocol binding.
2. Real Keycloak issuer/JWKS/audience verification.
3. `mcp.connect` scope issuance to an explicitly governed demo identity.
4. Client-forged trusted OUF headers are stripped and cannot influence MCP identity.
5. No token -> 401.
6. Wrong audience -> 401.
7. Missing `mcp.connect` -> 403.
8. Valid token -> MCP protocol handshake succeeds through Gateway.
9. `tools/list` succeeds through Gateway.
10. A tool without its own scope/grant is denied after transport admission.
11. An authorized tool traverses MCP -> Gateway -> owner and returns governed output.
12. Correlation/audit evidence links northbound request, MCP attempt and southbound dispatch.
13. Restart preserves the endpoint and no direct MCP host port is exposed.
14. Rollback to the previous Gateway configuration remains available.

Until those gates are green, this increment must be described as repository/configuration evidence, not deployed remote-MCP acceptance.
