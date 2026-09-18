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

python3 - "$MATERIALIZATION" "$WORK" <<'PY'
import json,sys

src,work=sys.argv[1:]
doc=json.load(open(src))
routes=doc.get("routes")
if not isinstance(routes,list) or len(routes)!=2:
    raise SystemExit("expected MCP and OAuth protected-resource routes")
by_id={route.get("id"):route for route in routes if isinstance(route,dict)}
mcp=by_id.get("public-mcp-endpoint")
metadata=by_id.get("public-mcp-oauth-protected-resource")
if not isinstance(mcp,dict) or not isinstance(metadata,dict):
    raise SystemExit("required governed MCP routes are missing")
if mcp.get("uri")!="/mcp" or mcp.get("methods")!=["POST"]:
    raise SystemExit("materialization is not the governed POST /mcp route")
if metadata.get("uri")!="/.well-known/oauth-protected-resource" or metadata.get("methods")!=["GET"]:
    raise SystemExit("materialization is not the governed protected-resource metadata route")
oidc=(mcp.get("plugins") or {}).get("openid-connect") or {}
ref=oidc.get("client_secret")
if not isinstance(ref,str) or not ref.startswith("$ENV://"):
    raise SystemExit("MCP OIDC secret must use an APISIX environment reference")
env_name=ref[len("$ENV://"):]
if not env_name or not env_name.replace("_","").isalnum():
    raise SystemExit("invalid APISIX OIDC secret environment name")
challenge=(((mcp.get("plugins") or {}).get("response-rewrite") or {}).get("headers") or {}).get("set") or {}
www_authenticate=challenge.get("WWW-Authenticate")
mocking=(metadata.get("plugins") or {}).get("mocking") or {}
try:
    metadata_body=json.loads(mocking["response_example"])
except (KeyError,TypeError,json.JSONDecodeError):
    raise SystemExit("invalid protected-resource metadata response")
resource=metadata_body.get("resource")
authorization_servers=metadata_body.get("authorization_servers")
scopes=metadata_body.get("scopes_supported")
metadata_url=resource.removesuffix("/mcp")+metadata["uri"] if isinstance(resource,str) else None
expected_challenge=f'Bearer resource_metadata="{metadata_url}", scope="{scopes[0]}"' if isinstance(scopes,list) and len(scopes)==1 else None
if not metadata_url or www_authenticate!=expected_challenge:
    raise SystemExit("MCP OAuth challenge and protected-resource metadata disagree")
if not isinstance(authorization_servers,list) or len(authorization_servers)!=1:
    raise SystemExit("exactly one governed authorization server is required")
json.dump(metadata,open(work+"/metadata-route.json","w"),sort_keys=True,separators=(",",":"))
json.dump(mcp,open(work+"/mcp-route.json","w"),sort_keys=True,separators=(",",":"))
open(work+"/meta","w").write(
    mcp["id"]+"\n"+metadata["id"]+"\n"+env_name+"\n"+metadata["uri"]+"\n"+
    metadata_url+"\n"+resource+"\n"+authorization_servers[0]+"\n"+scopes[0]+"\n"
)
PY

MCP_ROUTE_ID="$(sed -n '1p' "$WORK/meta")"
METADATA_ROUTE_ID="$(sed -n '2p' "$WORK/meta")"
OIDC_ENV="$(sed -n '3p' "$WORK/meta")"
METADATA_PATH="$(sed -n '4p' "$WORK/meta")"
RESOURCE_METADATA_URL="$(sed -n '5p' "$WORK/meta")"
RESOURCE_URL="$(sed -n '6p' "$WORK/meta")"
AUTHORIZATION_SERVER="$(sed -n '7p' "$WORK/meta")"
REQUIRED_SCOPE="$(sed -n '8p' "$WORK/meta")"

if ! docker inspect "$APISIX_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' |
     grep -q "^$OIDC_ENV=."; then
  echo "APISIX_OIDC_SECRET_ENV_MISSING"
  exit 1
fi

umask 077
printf 'X-API-KEY: %s\n' "$(cat "$ADMIN_KEY_FILE")" > "$WORK/admin.header"

snapshot_route() {
  route_id="$1"
  tag="$2"
  status="$(
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
      -v "$WORK:/work" "$CURL_IMAGE" \
      -sS -o "/work/previous-$tag.json" -w '%{http_code}' \
      -H @/work/admin.header \
      "http://127.0.0.1:9180/apisix/admin/routes/$route_id" || true
  )"
  case "$status" in
    200)
      python3 - "$WORK/previous-$tag.json" "$WORK/previous-$tag-route.json" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1]))
node=doc.get("value",doc)
if isinstance(node,dict) and "value" in node and isinstance(node["value"],dict):
    node=node["value"]
json.dump(node,open(sys.argv[2],"w"),sort_keys=True,separators=(",",":"))
PY
      ;;
    404) ;;
    *) echo "APISIX_ROUTE_SNAPSHOT_HTTP=$status" >&2; return 1 ;;
  esac
  printf '%s' "$status"
}

restore_route() {
  route_id="$1"
  tag="$2"
  previous_status="$3"
  if [ "$previous_status" = "200" ]; then
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
      -v "$WORK:/work" "$CURL_IMAGE" \
      -sS -o /dev/null -X PUT \
      -H @/work/admin.header -H 'Content-Type: application/json' \
      --data-binary "@/work/previous-$tag-route.json" \
      "http://127.0.0.1:9180/apisix/admin/routes/$route_id" || true
  else
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
      -v "$WORK:/work" "$CURL_IMAGE" \
      -sS -o /dev/null -X DELETE \
      -H @/work/admin.header \
      "http://127.0.0.1:9180/apisix/admin/routes/$route_id" || true
  fi
}

MCP_PREVIOUS_STATUS="$(snapshot_route "$MCP_ROUTE_ID" mcp)"
METADATA_PREVIOUS_STATUS="$(snapshot_route "$METADATA_ROUTE_ID" metadata)"

restore_all() {
  restore_route "$MCP_ROUTE_ID" mcp "$MCP_PREVIOUS_STATUS"
  restore_route "$METADATA_ROUTE_ID" metadata "$METADATA_PREVIOUS_STATUS"
}

put_route() {
  route_id="$1"
  route_file="$2"
  status="$(
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
      -v "$WORK:/work" "$CURL_IMAGE" \
      -sS -o /work/put.json -w '%{http_code}' -X PUT \
      -H @/work/admin.header -H 'Content-Type: application/json' \
      --data-binary "@/work/$route_file" \
      "http://127.0.0.1:9180/apisix/admin/routes/$route_id"
  )"
  case "$status" in
    200|201) ;;
    *) echo "APISIX_ROUTE_PUT_HTTP=$status" >&2; return 1 ;;
  esac
}

read_route() {
  route_id="$1"
  status="$(
    docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
      -v "$WORK:/work" "$CURL_IMAGE" \
      -sS -o /dev/null -w '%{http_code}' \
      -H @/work/admin.header \
      "http://127.0.0.1:9180/apisix/admin/routes/$route_id"
  )"
  [ "$status" = "200" ] || { echo "APISIX_ROUTE_READBACK_HTTP=$status" >&2; return 1; }
}

if ! put_route "$METADATA_ROUTE_ID" metadata-route.json ||
   ! put_route "$MCP_ROUTE_ID" mcp-route.json ||
   ! read_route "$METADATA_ROUTE_ID" ||
   ! read_route "$MCP_ROUTE_ID"; then
  restore_all
  exit 1
fi

METADATA_STATUS="$(
  docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
    -v "$WORK:/work" "$CURL_IMAGE" \
    -sS -o /work/metadata-body.json -w '%{http_code}' \
    "http://127.0.0.1:9080$METADATA_PATH"
)"
if [ "$METADATA_STATUS" != "200" ] || ! python3 - "$WORK/metadata-body.json" "$RESOURCE_URL" "$AUTHORIZATION_SERVER" "$REQUIRED_SCOPE" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1]))
expected_resource,expected_server,expected_scope=sys.argv[2:]
assert doc.get("resource")==expected_resource
assert doc.get("authorization_servers")==[expected_server]
assert doc.get("scopes_supported")==[expected_scope]
assert doc.get("bearer_methods_supported")==["header"]
PY
then
  restore_all
  echo "APISIX_MCP_METADATA_HTTP=$METADATA_STATUS"
  exit 1
fi

NEGATIVE_STATUS="$(
  docker run --rm --user 0:0 --network "container:$APISIX_CONTAINER" \
    -v "$WORK:/work" "$CURL_IMAGE" \
    -sS -D /work/mcp-negative.headers -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    --data-binary '{}' http://127.0.0.1:9080/mcp
)"

if [ "$NEGATIVE_STATUS" != "401" ] ||
   ! grep -Fqi "resource_metadata=\"$RESOURCE_METADATA_URL\"" "$WORK/mcp-negative.headers"; then
  restore_all
  echo "APISIX_MCP_NEGATIVE_HTTP=$NEGATIVE_STATUS"
  exit 1
fi

echo "APISIX_MCP_ROUTES_ACTIVE mcp_id=$MCP_ROUTE_ID metadata_id=$METADATA_ROUTE_ID negative_http=$NEGATIVE_STATUS"
