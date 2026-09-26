# R4a managed-file upload: request-streaming release gate

PET Gateway v1.5 T25/T28 requires the HUMAN attachment upload to traverse the
Gateway with a bounded streaming request, then the Onboarding intake. The
current lab APISIX deployment has not been shown to satisfy this requirement.

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
