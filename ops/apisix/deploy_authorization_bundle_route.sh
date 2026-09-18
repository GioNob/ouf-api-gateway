#!/bin/sh
set -eu

MATERIALIZATION="${OUF_APISIX_MATERIALIZATION:?OUF_APISIX_MATERIALIZATION is required}"
ADMIN_KEY_FILE="${OUF_APISIX_ADMIN_KEY_FILE:?OUF_APISIX_ADMIN_KEY_FILE is required}"
APISIX_CONTAINER="${OUF_APISIX_CONTAINER:?OUF_APISIX_CONTAINER is required}"
CURL_IMAGE="${OUF_APISIX_CURL_IMAGE:-curlimages/curl:8.16.0}"

test -r "$MATERIALIZATION"
test -r "$ADMIN_KEY_FILE"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
chmod 700 "$WORK"

python3 - "$MATERIALIZATION" "$WORK/route.json" "$WORK/meta" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1]))
routes=doc.get("routes")
if not isinstance(routes,list) or len(routes)!=1:
    raise SystemExit("expected exactly one materialized route")
route=routes[0]
expected="/internal/capabilities/v1/authorization/policy-bundle/active"
if route.get("uri")!=expected or route.get("methods")!=["GET"]:
    raise SystemExit("materialization is not the governed Authorization bundle route")
oidc=(route.get("plugins") or {}).get("openid-connect") or {}
ref=oidc.get("client_secret")
if not isinstance(ref,str) or not ref.startswith("$ENV://"):
    raise SystemExit("OIDC secret must use an APISIX environment reference")
json.dump(route,open(sys.argv[2],"w"),sort_keys=True,separators=(",",":"))
open(sys.argv[3],"w").write(route["id"]+"\n"+ref[len("$ENV://"):]+"\n")
PY

ROUTE_ID="$(sed -n '1p' "$WORK/meta")"
OIDC_ENV="$(sed -n '2p' "$WORK/meta")"
if ! docker inspect "$APISIX_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q "^$OIDC_ENV=."; then
  echo "APISIX_OIDC_SECRET_ENV_MISSING"
  exit 1
fi
umask 077
printf 'X-API-KEY: %s\n' "$(cat "$ADMIN_KEY_FILE")" > "$WORK/admin.header"

PREVIOUS_STATUS="$(docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" -v "$WORK:/work" "$CURL_IMAGE" -sS -o /work/previous.json -w '%{http_code}' -H @/work/admin.header "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID" || true)"
restore() {
  if [ "$PREVIOUS_STATUS" = "200" ]; then
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" -v "$WORK:/work" "$CURL_IMAGE" -sS -o /dev/null -X PUT -H @/work/admin.header -H 'Content-Type: application/json' --data-binary @/work/previous-route.json "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID" || true
  else
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" -v "$WORK:/work" "$CURL_IMAGE" -sS -o /dev/null -X DELETE -H @/work/admin.header "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID" || true
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

PUT_STATUS="$(docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" -v "$WORK:/work" "$CURL_IMAGE" -sS -o /work/put.json -w '%{http_code}' -X PUT -H @/work/admin.header -H 'Content-Type: application/json' --data-binary @/work/route.json "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID")"
case "$PUT_STATUS" in 200|201) ;; *) echo "APISIX_ROUTE_PUT_HTTP=$PUT_STATUS"; exit 1;; esac
READ_STATUS="$(docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" -v "$WORK:/work" "$CURL_IMAGE" -sS -o /work/read.json -w '%{http_code}' -H @/work/admin.header "http://127.0.0.1:9180/apisix/admin/routes/$ROUTE_ID")"
if [ "$READ_STATUS" != "200" ]; then restore; echo "APISIX_ROUTE_READBACK_HTTP=$READ_STATUS"; exit 1; fi
NEGATIVE_STATUS="$(docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" "$CURL_IMAGE" -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:9080/internal/capabilities/v1/authorization/policy-bundle/active")"
case "$NEGATIVE_STATUS" in 401|403) ;; *) restore; echo "APISIX_AUTH_BUNDLE_NEGATIVE_HTTP=$NEGATIVE_STATUS"; exit 1;; esac
echo "APISIX_AUTH_BUNDLE_ROUTE_ACTIVE id=$ROUTE_ID negative_http=$NEGATIVE_STATUS"
