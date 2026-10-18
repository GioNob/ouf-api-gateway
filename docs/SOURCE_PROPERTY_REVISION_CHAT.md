# Generic source revision mediation

Candidate only; no installed routes, IAM scopes or grants change through this commit. Current runtime acceptance remains technical8/8, functional4/6.

Two exact routes expose the Onboarding owner revision read/prepare capabilities. Each checks its independent scope, delegated HUMAN identity, MCP workload, tenant, envelope, exact path, body size, correlation/attempt/key and owner binding. A separate owner receipt purpose and HMAC domain bind exact unchanged JSON bytes; original bearer/delegation/caller-supplied owner headers are stripped. No approval/activation route is exposed to MCP. HTTP automatic retries are disabled.

The additive materializer requires the existing native review route and authenticated bounded execute template, validates frozen runtime bindings, refuses collisions/drift and preserves every existing route. It never creates signing keys, login sessions or runtime authority.

Prepare requires explicit acknowledgment NEW_PUBLICATION_MAY_START_ACQUISITION and a frozen parent version/hash/lock plus one stable commandKey. Only reconciliation rules of exact existing (propertyIri,sourceField) targets are accepted. Caller-defined configuration replacement, priorities, approval or acquisition suppression fields are rejected. Owner full validation remains authoritative. Read supports exact version or the original parentVersionId+commandKey after a lost response; it cannot silently create a successor.

Qualification includes real Lua receipt signing, closed schemas, denied scope/actor/owner/operation/key/path, additive route preservation/collision and native review preservation. Cross-language owner/MCP schema qualification and controlled target rollout remain separate acceptance steps. References: Gateway PET1.5, Onboarding PET1.6, MCP PET1.4, OUF resilience policy v3 and the generic linked-property specification at ouf-deploy83e2e85a0ae4107ba52486de7bdcbfe4502761cc.
