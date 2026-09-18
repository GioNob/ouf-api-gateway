# Declarative Caddy deployment and internal issuer DNS

Baseline: OUF Reality Baseline Package v1.7, Gateway PET v1.5, Authorization PET v1.5.

## Purpose

OUF workloads validate JWTs against the public issuer `https://<issuer-host>/realms/ouf`. The issuer string must remain identical inside and outside Docker because it is compared with the JWT `iss` claim.

The Docker network `ouf-backend` does not use the host resolver for public names. Therefore both `<issuer-host>` and the public Gateway hostname `<api-host>` must resolve inside that network to the Caddy reverse proxy, not directly to Keycloak/APISIX and not through per-consumer `--add-host` overrides.

The canonical deployment gives `ouf-caddy` the network aliases:

```text
<issuer-host>
<api-host>
```

on `ouf-backend`.

This keeps TLS host/SNI, OIDC discovery and the JWT issuer aligned while avoiding consumer-specific host-file workarounds.

## Deployment

Use:

```sh
sudo sh ops/caddy/deploy.sh
```

The script:

1. validates `/opt/ouf/Caddyfile` before switch;
2. creates a replacement from pinned image `caddy:2.11.4` directly on `ouf-backend`, with aliases `<issuer-host>` and `<api-host>`, avoiding any implicit default bridge;
3. attaches `ouf-edge`;
4. preserves the previous container as a stopped rollback container;
5. switches to the replacement;
6. validates the running Caddy configuration;
7. probes the real OIDC discovery URL from `ouf-backend`;
8. automatically restores the previous Caddy container if activation or discovery fails.

The script does not contain credentials or secrets.

## Acceptance

Successful deployment prints:

```text
OIDC discovery probe: OK
```

Independent verification from `ouf-backend`:

```sh
docker run --rm --network ouf-backend curlimages/curl:8.16.0 \
  -fsS -o /dev/null -w '%{http_code}\n' \
  https://<issuer-host>/realms/ouf/.well-known/openid-configuration
```

Expected result:

```text
200
```

Also verify:

```sh
docker inspect ouf-caddy --format '{{json .NetworkSettings.Networks}}'
```

The Caddy container must be attached only to the intended OUF networks, and the `ouf-backend` DNS names must include both `<issuer-host>` and `<api-host>`.

## Rollback

The immediately previous container is retained as `ouf-caddy-rollback-<container-id-prefix>`. Do not delete it until IAM acceptance is complete.

If manual rollback is required:

```sh
docker rm -f ouf-caddy
docker rename <rollback-container> ouf-caddy
docker start ouf-caddy
```

## Invariants

- Caddy remains the TLS/reverse-proxy boundary for `<issuer-host>` and `<api-host>`.
- Keycloak remains reachable internally as `ouf-keycloak:8080` only behind Caddy for the public issuer path.
- No consumer gets a permanent `--add-host` override.
- No issuer rewrite is allowed.
- Production JWT validation remains fail-closed.

## Production acceptance history

The 2026-09-18 live deployment, safe initial failure, hotfix, OIDC discovery acceptance and preserved rollback are recorded in [ACCEPTANCE_HISTORY_2026-09-18.md](ACCEPTANCE_HISTORY_2026-09-18.md).

## R3a internal API hostname acceptance

For MCP and other backend workloads, `https://<api-host>` must terminate on Caddy inside `ouf-backend` instead of hairpinning through the VPS public address. The deployment therefore assigns `<api-host>` as an additional Docker network alias on `ouf-caddy`. This preserves the public hostname, TLS SNI and certificate validation while keeping traffic on the backend network.

Expected probe from `ouf-backend` after deployment:

```sh
docker run --rm --network ouf-backend curlimages/curl:8.16.0 \
  -sS -o /dev/null -w '%{http_code}\n' https://<api-host>/
```

A `404` is acceptable before a root route is defined; it proves internal DNS, TLS termination and Caddy -> APISIX connectivity.

### Deployment-specific hostnames

The Caddy deployment does not define organization DNS names. Each installation must provide `OUF_INTERNAL_ISSUER_HOST` and `OUF_INTERNAL_API_HOST` explicitly. For the current OUF lab deployment those values are supplied by operations; another organization may use any DNS zone and hostnames it governs. `OUF_OIDC_DISCOVERY_URL` is optional and otherwise derives from the configured issuer host plus the governed realm path.
