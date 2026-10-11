# Owner publication bookmark HTTP profile v1

Follow [resilience policy v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md), Gateway PET1.5 and [private bookmark contract](OPERATIONAL_PUBLICATION_BOOKMARKS_REFERENCE.md). This is an opt-in READ position, never an operator receipt, grant, acknowledgement or renewed job budget.

The existing hidden `ouf.gateway.operations.incidents` and `ouf.ingestion.operations.incidents` fixed routes accept exactly these additional modes:
- Initial coverage: `{"snapshot":true,"coverage":true,"state":"OPEN","limit":50}`; optional state/limit, Ingestion alone may use sourceId.
- Coverage page: `{"cursor":"canonical-nonzero-uuid","coverage":true}`.
- Resume: `{"resumeFrom":"canonical-nonzero-uuid","limit":50}`; optional limit, all saved filters inherited.

No since cutoff, raw revision, changed source/state, mixed modes, null/duplicates or noncanonical token may enter the coverage path. Existing legacy/snapshot/cursor requests retain their separate behavior. Summary rejects publication modes. The fixed global MCP incidents route accepts the same closed syntax only as an opaque MCP vector; a raw owner token cannot become global authority. The MCP backend separately qualifies vector lookup, composition and public schema/tool integration in PR59–61; PR61 is merged after20 native push/PR gates. A global token resolves only under the current scoped MCP vector contract, never as a raw owner token.

The Gateway reference adapter performs fresh collection and per-row owner decisions with the exact PLATFORM/RESTRICTED_OPERATIONAL resource. Missing SDK fails closed. Each request receives a separate authorization view: no shared mutable current decision. Current revocation/policy/identity still controls every resume/page; metadata is not authority. Only complete nonredacted coverage may return publicationBookmark; consultationRecorded remains false.

Native gates must qualify schema/delegation and actual APISIX/OIDC transport, plus owner HTTP persistence/reopen/new login, current row redaction, revocation/identity/policy, closed invalid input before owner I/O and isolated authorization views. Reference SQLite hosting/SDK/HA/history compactor, MCP public vector linkage is repository-qualified in PR61; trusted client confirmation and actual target integration remain distinct open gates. No target changes or real notification are part of this work.


## Cross-owner qualification status — 2026-10-11

[MCP PR61](https://github.com/GioNob/ouf-mcp-server/pull/61) qualifies the public publication HTTP/tool path and persistent control accounting after20 gates. Historical coverage remains GATEWAY/INGESTION only; historical MCP self and other owner histories are not covered. [Current evidence and target limits](https://github.com/GioNob/ouf-deploy/blob/main/evidence/operational-publication-http-qualified-20261011.json). No client receipt, HUMAN consultation, checkpoint update, alert or production apply is implied.
