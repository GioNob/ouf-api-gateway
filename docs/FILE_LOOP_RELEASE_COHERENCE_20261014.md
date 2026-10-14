# Gateway file-loop release coherence — 2026-10-14

The proposal candidate `23b02bd2195d36499b6618750d52dd49d65c9a60`
and merged main `3a31a30ae67b606bf225710e580b53e98e93bdc8` have the same
tree. That tree omitted file-loop capabilities from the qualified deployment
line `c14d3f230684e3cb42c283b52f4210d5bfff3dc7`. Updating a deployment from
the candidate alone could lose working CSV and consultation pathways.

This restoration uses the three-way delta from common ancestor
`dbdc24b5481dc9473b21b360ab1142c9aef0194b`, retaining the current main
proposal command contract, Lua sandbox, JWT dependency and resilience-v3
operational owner/cursor/bookmark implementation. It restores the existing
managed CSV upload/profile/preview/handoff/create, semantic search/get, UDP
search, trusted-human namespaces and fixed M2M routing. The superseded
operational owner and summary/cursor implementation are not reintroduced.
Service/backend references for permission routes remain consistent with the
retained `ouf-onboarding` source profile; their scopes and actor policy do not
change.

The four new proposal routes remain
`/internal/capabilities/v1/execute/semantic/{create,validate,review,read}`.
They forward only fixed owner commands with a purpose-bound receipt; the
Gateway removes incoming bearer, cookie and untrusted OUF headers. They do
not approve, publish or activate an artifact.

## Installation integration

Use `tools.materialize_semantic_proposals.add_to_existing(existing, runtime,
delegation_key_env, semantic_owner_key_env)` with the retained materialized
installation. The CLI now requires `--existing`. All existing routes are
preserved, including upload streaming controls, THS and operational routes.
Duplicate proposal IDs or paths require reconciliation and are not replaced.
The `materialize` Python helper remains available for fresh fixture/runtime
construction, and must not replace an existing deployment document.

No target apply, signing authority, policy grant or service mutation is part of
this change. Restored historical operational scripts are source continuity,
not instructions to rerun consumed deployment operations.

## Qualification

Local: 457 tests and 13 subtests passed; three environment-gated tests were
skipped (native APISIX, external authorization fixture and UDP receipt export).
The existing network CI gate is restored to exercise APISIX → real UDP Java
owner → PostgreSQL, alongside all current operational mediation assertions.
The composed regression test includes upload, all four managed-file commands,
semantic consultation, UDP search and current operational routes before adding
the proposal routes, and checks exact preservation plus collision/authentication
denials. CI qualification is recorded on the pull request. This is not target
or complete CSV end-to-end acceptance.
