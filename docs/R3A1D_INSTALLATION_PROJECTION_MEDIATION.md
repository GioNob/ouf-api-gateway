# R3a.1d — Gateway mediation from InstallationProjection

Normative basis:
- OUF Reality Baseline Package v1.7;
- Cross-Module Alignment Matrix v1.7;
- Gateway PET deployment/configuration controls;
- MCP Server PET Gateway-only mediation controls;
- R3a.1c InstallationConfiguration runtime projections.

## Goal

Materialize the Gateway-side contracts required by the MCP projection without introducing organization-specific hostnames, audience values or workload identities into product configuration.

## Generic MCP mediation

Two Gateway-local protocol bindings are introduced:

- `POST /internal/capabilities/v1/execute` — generic governed execution mediation;
- `POST /internal/capabilities/v1/recovery` — generic recovery mediation.

They use `McpMediationBinding` because neither endpoint is a business capability. A synthetic capability is not created.

The mediation binding refers to the MCP workload by:

`installation://iam.workloadClients.mcpServer`

The InstallationProjection resolves that reference at deployment/runtime.

## Authorization PolicyBundle

Policy distribution is different: `authorization.bundle.read` is already a real Authorization capability.

Gateway therefore exposes:

`GET /internal/capabilities/v1/authorization/policy-bundle/active`

and proxies it to Source Onboarding:

`/api/internal/v1/authorization/policy-bundle/active`

The route requires:
- M2M identity;
- capability scope `authorization.bundle.read`;
- canonical actor `SERVICE`;
- MCP workload service identity resolved from InstallationProjection.

## Installation projection application

The product compiler emits logical installation references.

`tools/apply_installation_projection.py` turns compiled configuration plus an InstallationProjection into runtime configuration.

It resolves:
- Gateway audience;
- MCP service identity;
- installation metadata;
- Caddy network/hostname inputs.

No client secret, bearer token or key material is copied into Gateway runtime configuration.

## Caddy

`ops/caddy/deploy.sh` no longer has lab hostname/network defaults.

Deployment requires:

`OUF_INSTALLATION_PROJECTION=/path/to/installation-projection.json`

The script obtains from the projection:
- backend network;
- edge network;
- internal issuer hostname;
- internal API hostname;
- OIDC discovery URL.

It assigns both issuer and API hostnames as declarative aliases on the backend network, avoiding public-IP hairpinning while preserving TLS hostname/SNI semantics.

The Caddyfile remains an installation artifact and must contain both projected hostnames; deployment fails closed when either is absent.

## Actor vocabulary

RouteBinding accepts canonical `HUMAN`, `SERVICE`, `AI_AGENT` values while preserving legacy compatibility values already used by older route contracts. No automatic semantic conversion is introduced in this increment.

## Laboratory example

The test fixture records the current Netcup projection:
- issuer host: `auth.ouf-lab.it`;
- API host: `api.ouf-lab.it`;
- Gateway audience: `ouf-api-gateway`;
- MCP workload: `ouf-mcp-server`;
- backend network: `ouf-backend`;
- edge network: `ouf-edge`.

Those values are fixture/evidence only and are absent from product deployment defaults.

## Verification

Tests prove:
- generic execution/recovery routes compile without fake capabilities;
- PolicyBundle route is backed by real `authorization.bundle.read`;
- unresolved product configuration contains installation references;
- laboratory projection resolves audience and MCP service identity;
- dispatcher and recovery mediator work with a non-laboratory workload identity;
- Caddy deployment script contains no lab hostname defaults;
- missing projection fields fail closed.

## Explicit deployment boundary

This increment is repository/configuration evidence.

It does not yet claim:
- real APISIX materialization of these bindings;
- real OIDC verification on APISIX;
- deployed PolicyBundle path through Gateway;
- deployed recovery path through Gateway;
- remote MCP end-to-end acceptance.

Those are the live deployment gates immediately following merge.
