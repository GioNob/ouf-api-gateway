#!/bin/sh
set -eu

IMAGE="${CADDY_IMAGE:-caddy:2.11.4}"
NAME="${CADDY_NAME:-ouf-caddy}"
CANDIDATE="${NAME}-next"
BACKEND_NETWORK="${OUF_BACKEND_NETWORK:-ouf-backend}"
EDGE_NETWORK="${OUF_EDGE_NETWORK:-ouf-edge}"
INTERNAL_ISSUER_HOST="${OUF_INTERNAL_ISSUER_HOST:-auth.ouf-lab.it}"
CADDYFILE="${OUF_CADDYFILE:-/opt/ouf/Caddyfile}"
CONFIG_VOLUME="${OUF_CADDY_CONFIG_VOLUME:-ouf-caddy-config}"
DATA_VOLUME="${OUF_CADDY_DATA_VOLUME:-ouf-caddy-data}"
PROBE_IMAGE="${OUF_CADDY_PROBE_IMAGE:-curlimages/curl:8.16.0}"
OIDC_DISCOVERY_URL="${OUF_OIDC_DISCOVERY_URL:-https://auth.ouf-lab.it/realms/ouf/.well-known/openid-configuration}"

rollback_name=""

rollback() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -n "$rollback_name" ] && docker inspect "$rollback_name" >/dev/null 2>&1; then
    docker rename "$rollback_name" "$NAME"
    docker start "$NAME" >/dev/null
  fi
}

for network in "$BACKEND_NETWORK" "$EDGE_NETWORK"; do
  docker network inspect "$network" >/dev/null
done

test -r "$CADDYFILE"

docker run --rm   -v "$CADDYFILE:/etc/caddy/Caddyfile:ro"   "$IMAGE"   caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

docker rm -f "$CANDIDATE" >/dev/null 2>&1 || true

docker create   --name "$CANDIDATE"   --network "$BACKEND_NETWORK"   --network-alias "$INTERNAL_ISSUER_HOST"   --restart unless-stopped   -p 80:80   -p 443:443   -v "$CONFIG_VOLUME:/config"   -v "$DATA_VOLUME:/data"   -v "$CADDYFILE:/etc/caddy/Caddyfile:ro"   "$IMAGE"   caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

trap 'docker rm -f "$CANDIDATE" >/dev/null 2>&1 || true' EXIT INT TERM

docker network connect "$EDGE_NETWORK" "$CANDIDATE"

if docker inspect "$NAME" >/dev/null 2>&1; then
  rollback_name="${NAME}-rollback-$(docker inspect --format '{{.Id}}' "$NAME" | cut -c1-12)"
  docker stop "$NAME" >/dev/null
  docker rename "$NAME" "$rollback_name"
fi

docker rename "$CANDIDATE" "$NAME"
trap - EXIT INT TERM

if ! docker start "$NAME" >/dev/null; then
  rollback
  exit 1
fi

if ! docker exec "$NAME" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null; then
  rollback
  exit 1
fi

if ! docker run --rm   --network "$BACKEND_NETWORK"   "$PROBE_IMAGE"   -fsS -o /dev/null   "$OIDC_DISCOVERY_URL"; then
  rollback
  exit 1
fi

printf '%s\n' "Caddy active as $NAME"
printf '%s\n' "Internal issuer DNS alias: $INTERNAL_ISSUER_HOST on $BACKEND_NETWORK"
printf '%s\n' "OIDC discovery probe: OK"
if [ -n "$rollback_name" ]; then
  printf '%s\n' "Rollback container preserved as $rollback_name"
fi
