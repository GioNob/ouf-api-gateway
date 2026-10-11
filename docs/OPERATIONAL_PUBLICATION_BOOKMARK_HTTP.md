# Owner publication bookmark HTTP profile v1

Follow [resilience policy v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md), Gateway PET1.5 and [private bookmark contract](OPERATIONAL_PUBLICATION_BOOKMARKS_REFERENCE.md). This is an opt-in READ position, never an operator receipt, grant, acknowledgement or renewed job budget.

The existing hidden `ouf.gateway.operations.incidents` and `ouf.ingestion.operations.incidents` fixed routes accept exactly these additional modes:
- Initial coverage: `{"snapshot":true,"coverage":true,"state":"OPEN","limit":50}`; optional state/limit, Ingestion alone may use sourceId.
- Coverage page: `{"cursor":"canonical-nonzero-uuid","coverage":true}`.
- Resume: `{"resumeFrom":"canonical-nonzero-uuid","limit":50}`; optional limit, all saved filters inherited.

No since cutoff, raw revision, changed source/state, mixed modes, null/duplicates or noncanonical token may enter the coverage path. Existing legacy/snapshot/cursor requests retain their separate behavior. Summary rejects publication modes. The fixed global MCP incidents route accepts the same closed syntax only as an opaque MCP vector; a raw owner token cannot become global authority. The MCP backend must separately qualify vector lookup, composition and public schema/tool integration. Until then its explicit refusal remains authoritative.

The Gateway reference adapter performs fresh collection and per-row owner decisions with the exact PLATFORM/RESTRICTED_OPERATIONAL resource. Missing SDK fails closed. Each request receives a separate authorization view: no shared mutable current decision. Current revocation/policy/identity still controls every resume/page; metadata is not authority. Only complete nonredacted coverage may return publicationBookmark; consultationRecorded remains false.

Native gates must qualify schema/delegation and actual APISIX/OIDC transport, plus owner HTTP persistence/reopen/new login, current row redaction, revocation/identity/policy, closed invalid input before owner I/O and isolated authorization views. Reference SQLite hosting/SDK/HA/history compactor, MCP public vector linkage and client confirmation are distinct gates. No target changes or real notification are part of this work.
