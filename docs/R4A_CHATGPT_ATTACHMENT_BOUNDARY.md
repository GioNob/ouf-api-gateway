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

## Release state

Do not repeat the live CSV upload until one replacement has passed an actual
ChatGPT file transfer and the existing Gateway upload and Onboarding receipt
tests. The VPS now runs a read-only probe image, with `source.file.upload`
unavailable; a new image and a coordinated rollback-backed rollout are required. Keep the old
route snapshot and failed-run evidence. Profile, preview, DRAFT and
Semantic/Registry -> Ingestion -> UDP are pending because there is no asset.
