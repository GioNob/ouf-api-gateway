# ChatGPT attachment transfer boundary for R4a

## Decision from the live attempt (26 September 2026)

The enabled MCP server returned `ATTACHMENT_DNS_UNAVAILABLE` for an actual
ChatGPT CSV file parameter. No asset was created. The present MCP adapter
retrieves `download_url` directly from the MCP container; the laboratory
`ouf-backend` network does not resolve ordinary public names. The current
adapter and its no-static-origin rollout are **not PET-conformant** even if
container DNS is changed: MCP PET v1.4 section 38 forbids direct external
fetch from MCP, and Gateway PET v1.5 T11.3 forbids an unregistered URL from
becoming a southbound destination.

This is a boundary defect in the attachment path, not a defect in the CSV,
Onboarding intake, or the already installed streaming upload route. Do not
use a public DNS override, attach MCP to a public network, or route every
public HTTPS address through APISIX to make the live attempt succeed.

The subsequent read-only ChatGPT widget probe opened and reported
`BROWSER_FETCH`. That diagnostic does not distinguish failure to obtain a
temporary download URL from a CSP/CORS/redirect denial or body-read failure.
ChatGPT documents `getFileDownloadUrl` but does not guarantee that widget
JavaScript can read cross-origin response bytes. The probe was subsequently
revised to classify these stages, but the revision has no live result. Thus
browser byte delivery remains unproven. In addition, no browser-issued,
HUMAN-bound upload ticket route exists in Gateway. The current widget path
cannot complete the requested ChatGPT attachment -> Gateway -> Onboarding
transfer. Stop further VPS probes until a transport with a complete security
and identity boundary is implemented.

## Normative checks before enabling a replacement

* MCP PET v1.4 section 38 / MCP-GW-03: MCP calls a governed Gateway binding;
  it never retrieves the file from the external provider itself. Its runtime
  egress remains limited to Gateway, PostgreSQL, DNS and required telemetry.
* Gateway PET v1.5 T11.3 / GW-NET-01..04: an external destination derives
  from an approved, versioned endpoint binding and independently enforced
  network policy. The file parameter cannot select an unrestricted upstream.
  Dynamic provider DNS requires a suitable FQDN-aware network policy or
  equivalent; an application IP check alone does not fulfill the network gate.
* Gateway PET v1.5 T25/T28: the bytes of the upload pass through Gateway to
  managed intake, with 413/415, bounded streaming, timeouts and no file
  content in logs. Onboarding owns persistence and verifies actual bytes.
* Onboarding PET v1.6 section 92: an asset in staging precedes profiling,
  DRAFT, human approval, and eventual ingestion. A successful route
  installation never proves this end-to-end sequence.

## Replacement transport

First determine whether the ChatGPT Agent Host can send attachment bytes to
the existing Gateway upload route through a browser/widget bridge with
authenticated HUMAN context. This would avoid any OUF external fetch or
dynamic provider hostname. The documented ChatGPT `fileParams` descriptor
supplies a temporary download URL; it does **not** by itself prove that a
browser may read its bytes, that a widget can forward them, or that the
existing route can accept that widget's credentials. Test these three facts
before shipping this option. Do not put file bytes or bearer URLs in model
visible tool results or JSON tool arguments.

If Agent Host byte delivery is unavailable, use a Gateway-governed provider
fetch binding only after the provider destinations and independent egress
enforcement have been defined and approved. A worker hidden behind a Gateway
route is insufficient if it can fetch arbitrary public HTTPS destinations:
the endpoint registry and network boundary still apply. A dynamic hostname
without an approved binding remains blocked. The dedicated fetch component
may verify HTTPS, prevent redirects and DNS rebinding, and limit bytes, but
these checks supplement the Gateway and network policy; they cannot replace
either one.

## Implementable browser ingress without provider egress

The next implementation candidate is a ChatGPT app widget with a browser file
picker. The human selects the CSV in the widget; the browser owns a `File`
object and can stream those bytes without first reading a temporary
`oaiusercontent.com` URL. This requires a **second selection** when the same
CSV was already attached to the chat. Do not claim this UX reuses the chat
attachment automatically. Keep file-parameter auto-selection optional until
the host demonstrates readable bytes in this surface.

The browser file picker is only a transport and authorization adapter for the
**existing** capability `ouf.managed-source.file.upload`. It must call the
existing governed `POST /api/managed-sources/v1/files` binding and existing
Onboarding intake. The capability ID, human grant, owner, asset model and
post-upload profile/preview/DRAFT flow do not change. An MCP launch tool may
render the picker, but it is not a second upload capability or a second intake
API. The remaining engineering decision is how the widget obtains a short-lived
HUMAN-bound authorization accepted by that exact Gateway route without
exposing the user's OAuth token to the model or browser JavaScript. A
server-side THS session or a narrowly scoped upload credential are candidates;
neither is implemented. No arbitrary backend URL, direct MCP Internet access
or provider-host allowlist is involved.

Implementation prerequisites, all in one rollout artifact:

1. Versioned authentication adapter for the existing upload binding, precise
   CORS policy if the widget sends the request, and independently verified
   APISIX request streaming. No duplicate upload route or capability.
2. HUMAN identity and scope verified by Gateway and Onboarding; no credential
   or file bytes in logs, model-visible results or persistent browser state.
3. Browser streaming behavior demonstrated with a real CSV and oversized
   payload; 413/415, checksum mismatch, anonymous denial and no partial asset.
4. One idempotent installer with snapshot and automatic rollback for the
   changed MCP and Gateway configuration; no manual route or secret edits.

This is a candidate contract, not a deployed upload. The user must accept the
second file selection before it replaces the original attached-file UX. If
that UX is unacceptable, the remaining path is a versioned Gateway provider
binding with explicit destinations and independent FQDN-aware egress; it
cannot be enabled against arbitrary hostnames from `download_url`.

## Release state

**First-party picker implementation candidate:** The user accepted selecting
the local CSV again in OUF. The candidate now reuses the existing `ouf-ths`
server-side OIDC session and the existing HUMAN upload route. It adds only a
picker UI route and adapter, with no new business capability. See
`docs/R4A_FIRST_PARTY_FILE_PICKER.md`. Its `source.file.upload` MCP mode
returns the OUF picker link; the human selects and uploads on OUF, then brings
the asset ID back to chat. It is not a ChatGPT attachment byte bridge and has
not passed a live IAM login or CSV upload. The earlier widget and direct MCP
fetch conclusions still apply to those older modes.

Do not repeat the live CSV upload until one replacement has passed an actual
ChatGPT file transfer and the existing Gateway upload and Onboarding receipt
tests. The VPS now runs a read-only probe image, with `source.file.upload`
unavailable; a new image and a coordinated rollback-backed rollout are required. Keep the old
route snapshot and failed-run evidence. Profile, preview, DRAFT and
Semantic/Registry -> Ingestion -> UDP are pending because there is no asset.
