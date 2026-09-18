# Declarative Caddy deployment and internal issuer DNS

Baseline: OUF Reality Baseline Package v1.7, Gateway PET v1.5, Authorization PET v1.5.

## Purpose

OUF workloads validate JWTs against the public issuer `https://auth.ouf-lab.it/realms/ouf`. The issuer string must remain identical inside and outside Docker because it is compared with the JWT `iss` claim.

The Docker network `ouf-backend` does not use the host resolver for public names. Therefore `auth.ouf-lab.it` must resolve inside that network to the Caddy reverse proxy, not directly to Keycloak and not through per-consumer `--add-host` overrides.

The canonical deployment gives `ouf-caddy` the network alias:

```text
auth.ouf-lab.it
```

on `ouf-backend`.

This keeps TLS host/SNI, OIDC discovery and the JWT issuer aligned while avoiding consumer-specific host-file workarounds.

## Deployment

Use:

```sh
sudo ops/caddy/deploy.sh
```

The script:

1. validates `/opt/ouf/Caddyfile` before switch;
2. creates a replacement from pinned image `caddy:2.11.4`;
3. attaches `ouf-edge`;
4. attaches `ouf-backend` with alias `auth.ouf-lab.it`;
5. preserves the previous container as a stopped rollback container;
6. switches to the replacement;
7. validates the running configuration;
8. restores the previous container automatically if activation fails.

The script does not contain credentials or secrets.

## Acceptance

After deployment, from `ouf-backend`:

```sh
docker run --rm --network ouf-backend curlimages/curl:8.16.0 \
  -sS -o /dev/null -w '%{http_code}\n' \
  https://auth.ouf-lab.it/realms/ouf/.well-known/openid-configuration
```

Expected result:

```text
200
```

Also verify:

```sh
docker inspect ouf-caddy --format '{{json .NetworkSettings.Networks}}'
```

The `ouf-backend` DNS names must include `auth.ouf-lab.it`.

## Rollback

The immediately previous container is retained as `ouf-caddy-rollback-<container-id-prefix>`. Do not delete it until IAM acceptance is complete.

If manual rollback is required:

```sh
docker rm -f ouf-caddy
docker rename <rollback-container> ouf-caddy
docker start ouf-caddy
```

## Invariants

- Caddy remains the TLS/reverse-proxy boundary for `auth.ouf-lab.it`.
- Keycloak remains reachable internally as `ouf-keycloak:8080` only behind Caddy for the public issuer path.
- No consumer gets a permanent `--add-host` override.
- No issuer rewrite is allowed.
- Production JWT validation remains fail-closed.
