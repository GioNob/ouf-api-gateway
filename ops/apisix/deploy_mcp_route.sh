#!/bin/sh
set -eu

MATERIALIZATION="${OUF_APISIX_MATERIALIZATION:?OUF_APISIX_MATERIALIZATION is required}"
ADMIN_KEY_FILE="${OUF_APISIX_ADMIN_KEY_FILE:?OUF_APISIX_ADMIN_KEY_FILE is required}"
APISIX_CONTAINER="${OUF_APISIX_CONTAINER:?OUF_APISIX_CONTAINER is required}"
CURL_IMAGE="${OUF_APISIX_CURL_IMAGE:-curlimages/curl:8.16.0}"

test -r "$MATERIALIZATION"
test -r "$ADMIN_KEY_FILE"
command -v python3 >/dev/null
command -v docker >/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
chmod 700 "$WORK"

python3 - "$MATERIALIZATION" "$WORK/route.json" "$WORK/meta" <<'PY'
import json,sys
src,out,meta=sys.argv[1:]
doc=json.load(open(src))
routes=doc.get("routes")
if not isinstance(routes,list) or len(routes)!=1:
    raise SystemExit("expected exactly one materialized route")
route=routes[0]
if route.get("uri")!="/mcp" or route.get("methods")!=["POST"]:
    raise SystemExit("materialization is not the governed POST /mcp route")
oidc=(route.get("plugins") or {}).get("openid-connect") or {}
ref=oidc.get("client_secret")
if not isinstance(ref,str) or not ref.startswith("$ENV://"):
    raise SystemExit("MCP OIDC secret must use an APISIX environment reference")
env_name=ref[len("$ENV://"):]
if not env_name or not env_name.replace("_","").isalnum():
    raise SystemExit("invalid APISIX OIDC secret environment name")
json.dump(route,open(out,"w"),sort_keys=True,separators=(",",":"))
open(meta,"w").write(route["id"]+"\n"+env_name+"\n")
PY

ROUTE_ID="$(sed -n '1p' "$WORK/meta")"
OIDC_ENV="$(sed -n '2p' "$WORK/meta")"

if ! docker inspect "$APISIX_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' |
     grep -q "^$OIDC_ENV=."; then
  echo "APISIX_OIDC_SECRET_ENV_MISSING"
  exit 1
fi

umask 077
printf 'X-API-KEY: %s\n' "$(cat "$ADMIN_KEY_FILE")" > "$WORK/admin.header"

PREVIOUS_STATUS="$(
  docker run --rm --network "container:$APISIX_CONTAINER"     -v "$WORK:/work:ro" "$CURL_IMAGE"     -sS -o /work/previous.json -w '%{http_code}'     -H @/work/admin.header     "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID" || true
)"

restore() {
  if [ "$PREVIOUS_STATUS" = "200" ]; then
    docker run --rm --network "container:$APISIX_CONTAINER"       -v "$WORK:/work:ro" "$CURL_IMAGE"       -sS -o /dev/null -X PUT       -H @/work/admin.header -H 'Content-Type: application/json'       --data-binary @/work/previous-route.json       "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID" || true
  else
    docker run --rm --network "container:$APISIX_CONTAINER"       -v "$WORK:/work:ro" "$CURL_IMAGE"       -sS -o /dev/null -X DELETE       -H @/work/admin.header       "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID" || true
  fi
}

if [ "$PREVIOUS_STATUS" = "200" ]; then
  python3 - "$WORK/previous.json" "$WORK/previous-route.json" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1]))
node=doc.get("value",doc)
if isinstance(node,dict) and "value" in node and isinstance(node["value"],dict):
    node=node["value"]
json.dump(node,open(sys.argv[2],"w"),sort_keys=True,separators=(",",":"))
PY
fi

PUT_STATUS="$(
  docker run --rm --network "container:$APISIX_CONTAINER"     -v "$WORK:/work:ro" "$CURL_IMAGE"     -sS -o /work/put.json -w '%{http_code}' -X PUT     -H @/work/admin.header -H 'Content-Type: application/json'     --data-binary @/work/route.json     "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID"
)"

case "$PUT_STATUS" in
  200|201) ;;
  *) echo "APISIX_ROUTE_PUT_HTTP=$PUT_STATUS"; exit 1 ;;
esac

READ_STATUS="$(
  docker run --rm --network "container:$APISIX_CONTAINER"     -v "$WORK:/work:ro" "$CURL_IMAGE"     -sS -o /work/read.json -w '%{http_code}'     -H @/work/admin.header     "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID"
)"

if [ "$READ_STATUS" != "200" ]; then
  restore
  echo "APISIX_ROUTE_READBACK_HTTP=$READ_STATUS"
  exit 1
fi

NEGATIVE_STATUS="$(
  docker run --rm --network "container:$APISIX_CONTAINER"     "$CURL_IMAGE" -sS -o /dev/null -w '%{http_code}'     -X POST http://127.0.0.1:9080/mcp
)"

case "$NEGATIVE_STATUS" in
  401|403) ;;
  *)
    restore
    echo "APISIX_MCP_NEGATIVE_HTTP=$NEGATIVE_STATUS"
    exit 1
    ;;
esac

echo "APISIX_MCP_ROUTE_ACTIVE id=$ROUTE_ID negative_http=$NEGATIVE_STATUS"
