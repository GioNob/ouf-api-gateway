# Onboarding MCP release family (R-050, D-087)

The source for the six tool declarations is `GioNob/ouf-mcp-server`,
`internal/manifest/capabilities.json` at `4b39568`. The version and source SHA-256
are recorded in `contracts/mcp-onboarding_mcp-capabilities.json`.

* `internal/adapter/httpclient/clients.go` dispatches the three authorization
  capabilities to `/execute/authorization/{read,propose,status}`. Their logical
  capability references stay in the JSON envelope. The read and propose schemas
  include the complete closed alternatives in the MCP manifest, including
  `view=CAPABILITIES` and the two assignment selectors.
* In `internal/kernel/kernel.go`, `registerGovernedTool` moves the optional
  `source.file.profile.commandKey` to the request identity's idempotency key
  and deletes the property before serializing the remaining arguments.
  Revision read retains its own `commandKey`. The Gateway signs the bytes it
  forwards using the installed reader for each route. The retained profile
  and revision-read Lua programs come from Gateway commit `ae87693`.
* With an upload handle the MCP client sends the raw reader as `text/csv`.
  The upload route checks delegated authority, file ID, idempotency key,
  content type, length (1 byte to 10 MiB) and the syntax of the declared SHA-256.
  Its signed receipt carries the expected hash and length for the owner.
  Request buffering is disabled. The APISIX installation must load
  `proxy-control`. The handoff dispatch remains separately governed.
* The policy bundle GET uses OIDC scope `authorization.bundle.read` and the
  four SERVICE clients declared in its RouteBinding. The owner receives the
  authenticated bearer after the Gateway removes the untrusted identity headers.

The execution profile supplies the existing Onboarding backend host, port and
receipt-key environment binding. Add the following fields before release.

| Installation field | Type | Source |
|---|---|---|
| `iam.workloadClients.semantic` | string | Semantic workload client registration |
| `gateway.rateLimits.onboardingMcp.count` | integer | Installed execute-route request quota |
| `gateway.rateLimits.onboardingMcp.timeWindowSeconds` | integer | Installed execute-route window in seconds |
| `gateway.rateLimits.authorizationPolicyRead.count` | integer | Installed active-policy GET request quota |
| `gateway.rateLimits.authorizationPolicyRead.timeWindowSeconds` | integer | Installed active-policy GET window in seconds |

## PET evidence

| ID | Observable assertion |
|---|---|
| GW-60b-01 | Canonical digest of the 31 original resources and provenance of the six declarations |
| GW-60b-02 | Seven updates on the sanitized family export, unchanged preview, replay and exact offline restore |
| GW-60b-03 | Foreign selector, missing target and stale restore readback stop the plan |
| GW-60b-04 | Removing CAPABILITIES, changing nested alternatives or reintroducing the profile key stops release generation |
| GW-60b-05 | Standalone install and restore cannot write a family route |
| GW-60b-06 | Both published upload Lua phases handle a CSV stream with body readers disabled |
| GW-60b-07 | APISIX HTTP owner receives the validated envelopes or CSV and matching signed receipts. Policy reads require an allowed SERVICE |

The tests are in `tests/test_release_family_onboarding_mcp.py`. GW-60b-02 uses
the read-only export when supplied in the worktree. GW-60b-07 runs through
`tests/test_execute_apisix_live.py` with `OUF_APISIX_LIVE_TEST=1`. The private
export covers this family and preview. The executor needs the complete current
inventory to assess installation-wide selector conflicts at rollout.
