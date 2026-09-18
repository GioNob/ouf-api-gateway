#!/bin/sh
set -eu

IMAGE="${CADDY_IMAGE:-caddy:2.11.4}"
NAME="${CADDY_NAME:-ouf-caddy}"
CANDIDATE="${NAME}-next"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECTION_TOOL="$SCRIPT_DIR/../../tools/apply_installation_projection.py"
INSTALLATION_PROJECTION="${OUF_INSTALLATION_PROJECTION:?OUF_INSTALLATION_PROJECTION is required}"
test -r "$INSTALLATION_PROJECTION"
test -x "$(command -v python3)"
BACKEND_NETWORK="$(python3 "$PROJECTION_TOOL" --projection "$INSTALLATION_PROJECTION" --get caddy.backendNetwork)"
EDGE_NETWORK="$(python3 "$PROJECTION_TOOL" --projection "$INSTALLATION_PROJECTION" --get caddy.edgeNetwork)"
INTERNAL_ISSUER_HOST="$(python3 "$PROJECTION_TOOL" --projection "$INSTALLATION_PROJECTION" --get caddy.internalIssuerHost)"
INTERNAL_API_HOST="$(python3 "$PROJECTION_TOOL" --projection "$INSTALLATION_PROJECTION" --get caddy.internalApiHost)"
OIDC_DISCOVERY_URL="$(python3 "$PROJECTION_TOOL" --projection "$INSTALLATION_PROJECTION" --get caddy.oidcDiscoveryUrl)"
CADDYFILE="${OUF_CADDYFILE:-/opt/ouf/Caddyfile}"
CONFIG_VOLUME="${OUF_CADDY_CONFIG_VOLUME:-ouf-caddy-config}"
DATA_VOLUME="${OUF_CADDY_DATA_VOLUME:-ouf-caddy-data}"
PROBE_IMAGE="${OUF_CADDY_PROBE_IMAGE:-curlimages/curl:8.16.0}"

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

grep -F "$INTERNAL_ISSUER_HOST" "$CADDYFILE" >/dev/null
grep -F "$INTERNAL_API_HOST" "$CADDYFILE" >/dev/null

docker create   --name "$CANDIDATE"   --network "$BACKEND_NETWORK"   --network-alias "$INTERNAL_ISSUER_HOST"   --network-alias "$INTERNAL_API_HOST"   --restart unless-stopped   -p 80:80   -p 443:443   -v "$CONFIG_VOLUME:/config"   -v "$DATA_VOLUME:/data"   -v "$CADDYFILE:/etc/caddy/Caddyfile:ro"   "$IMAGE"   caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

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
printf '%s\n' "Internal API DNS alias: $INTERNAL_API_HOST on $BACKEND_NETWORK"
printf '%s\n' "Installation projection: $INSTALLATION_PROJECTION"
printf '%s\n' "OIDC discovery probe: OK"
if [ -n "$rollback_name" ]; then
  printf '%s\n' "Rollback container preserved as $rollback_name"
fi
