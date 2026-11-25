#!/usr/bin/env bash
# GW-58D-06. Run from the tested checkout on the Linux CI runner.
set -euo pipefail
umask 077
image=${1:?expected local image tag}
root=$(mktemp -d)
authority=
adapter=
cleanup() {
  for id in "$authority" "$adapter"; do
    if [[ -n "$id" ]]; then docker rm -f "$id" >/dev/null; fi
  done
  rm -rf -- "$root"
}
trap cleanup EXIT
# Name the failing check and show the captured container output (no secrets are logged).
trap 'echo "::error::smoke failed at line $LINENO"; for f in "$root"/*.log; do [[ -f $f ]] && { echo "== $f"; cat "$f"; }; done' ERR
mkdir -p "$root"/{pki,config,authority-store,iam-store}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=fixture-ca \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$root/ca.key" -out "$root/pki/ca.pem" 2>/dev/null
issue() {
  local name=$1 purpose=$2 san=$3
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$name" \
    -keyout "$root/pki/$name.key" -out "$root/$name.csr" 2>/dev/null
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
    "extendedKeyUsage=$purpose" "subjectAltName=$san" 'authorityKeyIdentifier=keyid' 'subjectKeyIdentifier=hash' \
    > "$root/$name.ext"
  openssl x509 -req -days 1 -in "$root/$name.csr" -CA "$root/pki/ca.pem" \
    -CAkey "$root/ca.key" -CAserial "$root/ca.srl" -CAcreateserial -out "$root/pki/$name.pem" \
    -extfile "$root/$name.ext" 2>/dev/null
}
issue server serverAuth DNS:localhost
issue gateway clientAuth URI:urn:fixture:gateway
issue observer clientAuth URI:urn:fixture:observer
openssl verify -x509_strict -purpose sslserver -CAfile "$root/pki/ca.pem" "$root/pki/server.pem"
openssl verify -x509_strict -purpose sslclient -CAfile "$root/pki/ca.pem" "$root/pki/gateway.pem" "$root/pki/observer.pem"
python -m deploy.authority.smoke_config "$root"

# Give the service group read access only to the material it needs.
mkdir "$root/server" "$root/authority-pki" "$root/authority-secret" "$root/iam-secret"
openssl rand -hex 32 > "$root/authority-secret/delegation"
openssl rand -hex 32 > "$root/iam-secret/resource-server"
cp "$root"/pki/{server.pem,server.key,ca.pem} "$root/server/"
cp "$root"/server/* "$root/authority-pki/"
cp "$root"/pki/{gateway.pem,gateway.key} "$root/authority-pki/"
for dir in "$root"/{server,authority-pki,config,authority-store,iam-store,authority-secret,iam-secret}; do
  sudo chgrp -R 65532 "$dir"
  chmod -R g+rX "$dir"
done
chmod 2770 "$root"/{authority-store,iam-store}
chmod g+w "$root"/{authority-store/gateway.db,iam-store/iam.db}
common=(--read-only --tmpfs /tmp:rw,nosuid,nodev,noexec --cap-drop ALL --security-opt no-new-privileges
        -v "$root/config:/config:ro" -e OUF_HOST_ADDRESS=0.0.0.0 -e OUF_HOST_PORT=8443
        -e OUF_HOST_CERT_FILE=/pki/server.pem -e OUF_HOST_KEY_FILE=/pki/server.key
        -e OUF_HOST_PROCESSES=1 -e OUF_HOST_THREADS=8 -e OUF_HOST_CONNECTIONS=8)
auth=(-v "$root/authority-pki:/pki:ro" -v "$root/authority-store:/state" -v "$root/authority-secret:/credential:ro")
iam=(-v "$root/server:/pki:ro" -v "$root/iam-store:/state" -v "$root/iam-secret:/credential:ro"
     -e OUF_KEYCLOAK_DECISIONS_CONFIG=/config/iam.json -e OUF_HOST_CLIENT_CA_FILE=/pki/ca.pem
     -e OUF_HOST_IDENTITY_FIELD=san-uri -e OUF_HOST_PROBE_PRINCIPAL=urn:fixture:observer)
rc=0
timeout 20 docker run --rm "${common[@]}" "${auth[@]}" -e OUF_ANALYSIS_CONFIG=/config/mismatch.json \
  "$image" authority >"$root/mismatch.log" 2>&1 || rc=$?
[[ $rc == 2 ]]
grep -Fxq AUTHORITY_HOSTING_MISMATCH "$root/mismatch.log"

authority=$(docker run -d -p 127.0.0.1::8443 "${common[@]}" "${auth[@]}" \
  -e OUF_ANALYSIS_CONFIG=/config/authority.json "$image" authority)
adapter=$(docker run -d -p 127.0.0.1::8443 "${common[@]}" "${iam[@]}" "$image" iam-adapter)
url() {
  local binding
  binding=$(docker port "$1" 8443/tcp)
  printf 'https://localhost:%s' "${binding##*:}"
}
metrics="$(url "$authority")/metrics"
decisions="$(url "$adapter")/decisions"
curl_opts=(--silent --ipv4 --noproxy '*' --max-time 3 --cacert "$root/pki/ca.pem")
client=(--cert "$root/pki/gateway.pem" --key "$root/pki/gateway.key")
post=(-H 'Content-Type: application/json' --data '{}')
# This handler checks gatewayTlsPrincipal before validating the payload.
probe() {
  curl "${curl_opts[@]}" --tlsv1.3 -o "$root/body" -w '%{http_code}' "${post[@]}" "$@" "$decisions"
}
for attempt in {1..30}; do
  if curl "${curl_opts[@]}" --tlsv1.3 --fail "$metrics" >"$root/metrics" &&
     [[ $(probe "${client[@]}") == 400 ]]; then break; fi
  for id in "$authority" "$adapter"; do
    if [[ $(docker inspect -f '{{.State.Running}}' "$id") != true ]]; then docker logs "$id"; exit 1; fi
  done
  sleep 1
done
grep -Fq 'gateway_analysis_slot_limit{service="analysis_mandate",traffic_class="control"} 2' "$root/metrics"
if curl "${curl_opts[@]}" --tls-max 1.2 "$metrics" >/dev/null; then exit 1; fi
spoof=(-H 'Remote-User: forged' -H 'SSL-Client-Verify: FAILURE')
[[ $(probe "${client[@]}" "${spoof[@]}") == 400 ]]
grep -Fq ANALYSIS_INPUT_INVALID "$root/body"
[[ $(probe --cert "$root/pki/observer.pem" --key "$root/pki/observer.key" \
  -H 'Remote-User: urn:fixture:gateway' -H 'SSL-Client-Verify: SUCCESS') == 403 ]]
grep -Fq ANALYSIS_AUTHORITY_DENIED "$root/body"
rc=0
code=$(probe -H 'Remote-User: urn:fixture:gateway' -H 'SSL-Client-Verify: SUCCESS') || rc=$?
[[ $rc != 0 && $code == 000 ]]
[[ $(probe "${client[@]}") == 400 ]]

# GW-58I-05. Both stores and file-backed credentials are local; peers are offline.
ready() {
  local container=$1
  shift
  curl "${curl_opts[@]}" --tlsv1.3 -o "$root/body" -w '%{http_code}' "$@" "$(url "$container")/health/ready"
}
[[ $(ready "$authority") == 204 && ! -s "$root/body" ]]
[[ $(ready "$adapter" --cert "$root/pki/observer.pem" --key "$root/pki/observer.key") == 204 && ! -s "$root/body" ]]
[[ $(ready "$adapter" "${client[@]}" -H 'Remote-User: urn:fixture:observer') == 403 ]]
rc=0
code=$(ready "$adapter" -H 'Remote-User: urn:fixture:observer' -H 'SSL-Client-Verify: SUCCESS') || rc=$?
[[ $rc != 0 && $code == 000 ]]
# Readiness is polled: wait up to 5 s for each transition and report what was observed.
expect_ready() {
  local want=$1 seen=() code
  for _ in 1 2 3 4 5; do
    code=$(ready "$authority") || true
    seen+=("$code")
    [[ $code == "$want" ]] && return 0
    sleep 1
  done
  echo "readiness expected $want, observed ${seen[*]}"; ls -ln "$root/authority-store"
  return 1
}
chmod a-w "$root/authority-store/gateway.db"
expect_ready 503
# SQLite recreates -shm with the database file's mode while it is read-only, owned by
# the service user: restoring write access covers every file of the store.
sudo chmod ug+w "$root"/authority-store/gateway.db*
expect_ready 204
for id in "$authority" "$adapter"; do
  docker inspect "$id" | python -c '
import json, sys
from pathlib import Path
c, = json.load(sys.stdin)
assert c["HostConfig"]["ReadonlyRootfs"] and "/tmp" in c["HostConfig"]["Tmpfs"]
assert all(m["Type"] == "bind" for m in c["Mounts"])
assert any(m["Destination"] == "/credential" and not m["RW"] for m in c["Mounts"])
for path in sys.argv[1:]:
    value = Path(path).read_text().strip()
    assert not any(value in entry for entry in c["Config"]["Env"])
' "$root/authority-secret/delegation" "$root/iam-secret/resource-server"
done
