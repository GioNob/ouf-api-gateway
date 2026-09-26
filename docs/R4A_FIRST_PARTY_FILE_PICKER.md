# First-party CSV picker for the existing upload capability

The Gateway PET v1.5 T25/T28 and Table 81 require a bounded streaming upload
through the Gateway at `POST /api/managed-sources/v1/files`. The browser picker
uses **that same** `ouf.managed-source.file.upload` binding. It does not add a
second file-intake capability or download a ChatGPT attachment URL.

An authenticated user opens `/trusted-human/managed-files/` on the OUF public
origin and chooses a local CSV. Onboarding's existing `ouf-ths` OIDC session
provides the HUMAN identity. The browser sends the file to the session-backed
picker adapter with a CSRF token. The adapter streams it to the existing APISIX
upload route with the user's access token; Onboarding then counts/hashes the
bytes, stores the staged asset, and returns its `asset_id`. Both Gateway
ingress paths use `proxy-control.request_buffering=false`; neither Gateway nor
the adapter buffers the full request body. JavaScript computes the SHA-256
over the selected file (limited to 10 MiB) before transfer.

This is an opt-in deployment. The picker controller requires the fixed internal
URL `http://ouf-apisix:9080/api/managed-sources/v1/files` in
`ouf.managed-file-picker.gateway-upload-url`. The `ouf-ths` OIDC client must be
bound to the optional `ouf.managed-source.file.upload` scope and request that
scope in its configured registration; its access token must have Gateway
audience, HUMAN actor and the expected tenant. Existing `ouf-admin` policy
grants alone do not add a scope to the THS client. The current public HUMAN
upload route, THS login routes, and session cookie configuration remain
prerequisites. A login and live upload with the actual client are required
before enabling the MCP picker mode.

`tools.materialize_managed_file_ths` validates the existing route binding and
emits only the picker UI route. `ops.apisix.deploy_managed_file_ths` snapshots
that route, installs it, reads it back, checks anonymous denial/redirect, and
restores the snapshot on failure. Do not treat a generated route, successful
installer, or anonymous denial as proof of an authenticated upload.

In MCP picker mode, the **same** `source.file.upload` tool returns the OUF URL
with `AWAITING_FILE_SELECTION`; it transfers no bytes and creates no asset.
The browser page shows the asset ID after a successful 201. For the initial
flow the user gives that ID back in chat for the existing profile, preview and
onboarding-create tools. Automated continuation after page completion is a
separate UX improvement, not part of this intake binding.
