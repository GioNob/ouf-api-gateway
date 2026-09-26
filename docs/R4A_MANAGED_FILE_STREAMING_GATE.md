# R4a managed-file upload: request-streaming release gate

PET Gateway v1.5 T25/T28 requires the HUMAN attachment upload to traverse the
Gateway with a bounded streaming request, then the Onboarding intake. The
lab APISIX-Runtime has passed an isolated request-streaming probe. The HUMAN
and delegated MCP product routes have not passed this requirement.

The default HUMAN route materialization omits `proxy-control`; the installer
now refuses to install that route set before taking a snapshot. A release
candidate may set `--streaming-runtime` on
`python3 -m tools.materialize_trusted_human_onboarding_runtime`; this adds
`proxy-control.request_buffering=false` only to the exact upload route.
The installer checks that the running APISIX advertises the HTTP plugin via
the Admin API before snapshot or mutation. Plugin discovery alone is **not**
proof of streaming. Apache APISIX documents that `proxy-control` requires
APISIX-Runtime; the stock APISIX image cannot be assumed equivalent.

Before installing or enabling an upload route, record the pinned Gateway
runtime image/digest, verify that it is an APISIX-Runtime build with this
plugin, and run a test through the real Gateway: send a bounded multipart or
CSV request slowly in chunks to a controlled intake that timestamps its first
received bytes. Intake must receive the first bytes before the client has
finished sending the body. Repeat with an oversized request and confirm 413,
no persisted partial asset, and bounded resource use. Verify allowed media
type, checksum mismatch and anonymous 401/403 independently. Keep the prior
route snapshot until rollback has been exercised. No arbitrary backend URL,
cross-network TLS claim, or attached CSV fixture is needed for this check.

The actual ChatGPT Agent Host attachment bridge, public HUMAN token flow, remote
upstream certificate verification, and end-to-end ingestion/search remain
separate release gates. A successful installation of the route alone does
not close R-SMOKE.

## Delegated MCP candidate

`tools/materialize_managed_upload.py` now builds a separate internal route
`/internal/capabilities/v1/execute/managed.file/upload`. It checks the MCP
workload token and signed HUMAN delegation, signs the declared file ID, size
and SHA-256 into an owner receipt, and never reads the request body in Lua.
Onboarding independently hashes and counts the forwarded bytes. This route
has `proxy-control.request_buffering=false` and is **not** included in the
current APISIX installer. The same runtime streaming proof above applies to
both the public HUMAN route and this internal route; the materializer and
Lua unit tests cannot replace the proof on the pinned VPS image.

The current candidate binds `ouf-onboarding:8080` on the lab backend network.
An installation with Gateway and owner on different machines requires a
versioned upstream endpoint and verified transport before materialization;
do not substitute a caller-supplied URL or an unverified upstream TLS flag.

## Isolated lab runtime probe (26 September 2026)

The live `ouf-apisix` image reports index digest
`sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d`.
Its `openresty -V` includes `APISIX_RUNTIME_VER=1.3.16` and
`apisix-nginx-module-1.19.9`; both plugin Lua files are present. These facts
identify the runtime; the behavioral evidence is recorded below.

On the VPS, from `/opt/ouf/gateway`, use the repository probe after fetching
the PR head. It runs host Python inside the APISIX container's network
namespace, listens on that namespace's loopback, creates one random temporary
APISIX route restricted to loopback, sends 4096 bytes, pauses for first-byte
arrival, sends the remaining 4096 bytes and removes the route in `finally`:

```bash
cd /opt/ouf/gateway
git show 04d9aa924e84db77b1e9135efef21b10158bc999:ops/apisix/probe_request_streaming.py \
  > /tmp/ouf-request-stream-probe.py
APISIX_PROBE_PID="$(sudo docker inspect -f '{{.State.Pid}}' ouf-apisix)"
if [ -z "$APISIX_PROBE_PID" ]; then
  echo 'APISIX_PID_EMPTY'
else
  sudo nsenter -t "$APISIX_PROBE_PID" -n \
    python3 /tmp/ouf-request-stream-probe.py \
    --admin-key /opt/ouf/secrets/apisix-admin-key
fi
```

PASS requires `FIRST_BYTE_BEFORE_CLIENT_FINISH=true`, `PROBE_HTTP_STATUS=204`
and `PROBE_ROUTE_REMOVED=true`. This probe does not send a user CSV, prove the
bounded oversized-request 413, install any product route, or establish the
MCP Agent Host attachment contract. An abnormal process termination can skip
the `finally` cleanup: before retrying, inspect the Admin API for an orphaned
`ouf-request-stream-probe-*` route and delete only the matching probe route.

### Lab observation, 26 September 2026

On the pinned Gateway commit `04d9aa924e84db77b1e9135efef21b10158bc999`,
the VPS operator ran the extracted probe in the running `ouf-apisix` network
namespace. It reported `FIRST_BYTE_BEFORE_CLIENT_FINISH=true`,
`PROBE_HTTP_STATUS=204`, and `PROBE_ROUTE_REMOVED=true`. A subsequent read-only
Admin API inventory returned HTTP 404 for both
`trusted-human-managed-file-upload` and `mcp-managed-file-upload`.
This closes the isolated APISIX-Runtime behavioral prerequisite for that image;
the product-route early-byte, size/media/error, owner persistence, rollback,
attachment bridge, and end-to-end gates remain open. Recheck the probe if the
runtime image or streaming configuration changes.
