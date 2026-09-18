# Caddy internal issuer DNS production acceptance — 2026-09-18

Normative baseline: OUF Reality Baseline Package v1.7; Gateway PET v1.5; Authorization PET v1.5.

## Problem

The host resolved `auth.ouf-lab.it` to the VPS address, but containers on `ouf-backend` could not resolve the public issuer hostname. IAM-enabled Onboarding therefore failed startup during OIDC discovery with:

- `Unable to resolve the Configuration with the provided Issuer`;
- `UnknownHostException: auth.ouf-lab.it`.

Changing the issuer was not acceptable because JWT `iss` is `https://auth.ouf-lab.it/realms/ouf`.

## Declarative fix

PR #29 merged as `9af37cee292b8a5930b40ad0849078c26aaffc3e`.

It introduced:
- `ops/caddy/deploy.sh`;
- `ops/caddy/README.md`;
- declarative Docker alias `auth.ouf-lab.it` on `ouf-backend`;
- Caddy validation;
- OIDC discovery probe;
- rollback preservation.

CI:
- Gateway control-plane and MCP mediation — run `35316146906` — SUCCESS.

## Live validation defect and hotfix

First production execution of PR #29 failed safely before replacing Caddy:

```text
container cannot be connected to multiple networks with one of the networks in private (none) mode
```

The existing `ouf-caddy` remained running and unchanged.

Root cause:
- candidate was created in Docker network mode `none`;
- Docker does not permit later attachment from private `none` mode to normal networks.

PR #30 corrected the candidate topology and merged as `6cd593a926399d793a78b408952a4a997ef0d40c`.

Correct behavior:
- candidate starts directly on `ouf-backend`;
- `--network-alias auth.ouf-lab.it` is declared at creation;
- candidate then joins `ouf-edge`;
- no default bridge and no per-consumer host override;
- rollback and OIDC discovery gates remain.

CI:
- Gateway control-plane and MCP mediation — run `35317130999` — SUCCESS.

## Production application

Gateway server checkout was updated to `main@6cd593a`.

Successful deployment output included:
- `Caddy active as ouf-caddy`;
- `Internal issuer DNS alias: auth.ouf-lab.it on ouf-backend`;
- `OIDC discovery probe: OK`.

Runtime network evidence:
- `ouf-backend` DNS names include `auth.ouf-lab.it`;
- Caddy remained attached to `ouf-backend` and `ouf-edge`;
- internal discovery from an ephemeral container on `ouf-backend` returned HTTP 200.

Rollback:
- previous Caddy preserved as `ouf-caddy-rollback-de52015c14f1`;
- rollback container was not deleted.

## Result

- public issuer string unchanged;
- TLS/SNI path preserved through Caddy;
- Docker-internal issuer discovery works;
- no permanent `--add-host` workaround remains;
- deployment logic is repository-tracked and repeatable;
- failure path was exercised and proved non-destructive before the successful hotfix deployment.
