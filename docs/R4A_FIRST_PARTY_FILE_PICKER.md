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
`ouf.managed-file-picker.gateway-upload-url`. The rollout overlays that property
and the exact `ouf-ths` registration scope using `SPRING_APPLICATION_JSON`;
Spring Boot gives this property source precedence over the mounted THS YAML.
The `ouf-ths` OIDC client must be
bound to the optional `ouf.managed-source.file.upload` scope and request that
scope in its configured registration; its access token must have Gateway
audience, HUMAN actor and the expected tenant. Existing `ouf-admin` policy
grants alone do not add a scope to the THS client. The current public HUMAN upload route and session cookie configuration remain
prerequisites. The picker installer installs the exact OIDC authorization and
callback routes together with the UI route. A fresh login and live upload with
the actual client are required for release acceptance after activation.

The Onboarding rollout script reads the THS registration (YAML or JSON form),
adds the existing upload scope to its Keycloak client with the repository's
exact scope-binding tool, verifies that the new source has no database
migration changes, builds an image from a pinned commit and retains the old
container. It creates and restore-tests a private database dump before the
swap; it restores the original container automatically if readiness fails.
It never restores a database automatically. See Onboarding
`docs/R4A_FIRST_PARTY_PICKER_ROLLOUT.md` for the pinned lab procedure.

The MCP `scripts/r4a_attachment_rollout.py --mode picker` checks that the
deployed Onboarding image and JSON overlay match the pinned revision, checks
the pre-existing HUMAN upload route is streaming and scope-protected, then
materializes and installs the picker UI plus its OIDC authorization and callback routes. The script swaps MCP into
picker mode with the same rollback snapshot. If activation fails, it restores
both changed components. Neither script transfers a CSV automatically.

`tools.materialize_managed_file_ths` validates the existing route binding and
emits the picker UI and the two exact OIDC paths (`/oauth2/authorization/ouf-ths`
and `/login/oauth2/code/ouf-ths`). `ops.apisix.deploy_managed_file_ths`
snapshots both route IDs, installs any missing route, reads them back, checks
the login redirect and anonymous picker response, and restores the snapshot
on failure. Existing route drift blocks the installer. The pinned
`ops/apisix/repair_managed_file_picker_login.py` applies this repair to an
already active picker without swapping MCP or rotating credentials. Do not treat a generated route, successful
installer, or anonymous denial as proof of an authenticated upload.

In MCP picker mode, the **same** `source.file.upload` tool returns the OUF URL
with `AWAITING_FILE_SELECTION`; it transfers no bytes and creates no asset.
The browser page shows the asset ID after a successful 201. The ChatGPT
widget reads the governed result with an app-only status tool and proposes
a follow-up in chat; ChatGPT shows an **Invia** confirmation before sending
it. The result read is part of the upload capability, not a second product
capability. Other MCP hosts need a portable MCP Apps widget or can use the
picker URL and manual Asset ID.

Live 27 September 2026: the first status poll passed scope admission but
APISIX returned HTTP 500 before contacting Onboarding. The generated
`execute_managed_file` Lua lacked the `OWNER_KEY_ENV` declaration while
calling `os.getenv(OWNER_KEY_ENV)`. Revision `e649d3e3b85ecfcee5aeaa89c57863c5ecd92d28`
adds that constant to the generator and
`scripts/r4a_managed_file_owner_key_repair.py` compares all four live
routes, snapshots them, and updates only that constant with rollback on
installation failure. The lab returned `MANAGED_FILE_OWNER_KEY_REPAIR=PASS
ROUTES=4`; snapshot:
`/etc/ouf/deploy-snapshots/managed-file-mcp-mb9jjday/previous.json`.
The subsequent first-party CSV upload generated a widget follow-up with
Asset ID `2b630dbb-5397-485c-95d2-0c4ecc431303`; the model received this
app-authored turn and profiling and redacted preview succeeded. The user
reported that the prompt was not visibly shown in the ChatGPT conversation
after the **Invia** confirmation. This proves the lab data path, but leaves
visible chat delivery, portability across MCP hosts, Semantic/Registry,
Ingestion and UDP open.
