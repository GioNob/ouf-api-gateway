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

## Bounded review follow-up

The follow-up adds two delegated HUMAN draft operations, each with its own
explicit scope and the existing purpose-bound managed-file owner receipt:

| Gateway suffix under `/internal/capabilities/v1/execute/managed.file/` | Owner suffix under `/api/internal/v1/onboarding/managed-file-mcp/` | Capability / scope | Timeout |
| --- | --- | --- | --- |
| `review-prepare` | `review-prepare` | `ouf.managed-source.onboarding.review.prepare` | 10 s |
| `review-read` | `review-read` | `ouf.managed-source.onboarding.read` | 3 s |

Preparation accepts a stable command key, the expected onboarding lock version,
and an optional closed `executionProposal` matching the Onboarding owner
contract. It prepares a draft for human review. It does not confirm, activate,
or grant a policy. The Gateway binds the command key to the envelope idempotency
key and forwards the exact bounded payload under the owner receipt. All
upstreams have retries disabled. Use
`tools.materialize_onboarding_review.materialize(existing, runtime,
delegation_key_env, owner_key_env)` after retaining the existing route document.
It preserves every existing route and rejects conflicting new route IDs/paths
or a changed owner OAuth login route.

The same materializer adds `/trusted-human/onboarding/*` and
`/trusted-human/semantic/*` to the existing Onboarding OAuth-session/CSRF
boundary. Incoming bearer and OUF context headers are stripped from that
browser surface. HUMAN approval continues through owner-authenticated actions,
not an MCP approval tool.

Semantic HUMAN bindings and their existing materializer/installer are restored
from `3014f3c3738ffb1a53971cb46676dd71c119cee3`, another qualified branch omitted
from main. These preserve separate review, approve and publish scopes and
bounded path selectors. The selector compiler now rejects duplicate
method/URI/regex triples. Existing routes or grants are not replaced by this
source restoration.

Semantic proposal CREATE also accepts one bounded Turtle import draft:
`artifactType=ONTOLOGY`, `mediaType=text/turtle`, `rdfTurtle` up to 49,152
characters inside the existing 65,536-byte envelope, and an absent or empty
`definition`. The owner and MCP enforce the corresponding 49,152 UTF-8 byte
limit. Native definitions and RDF fields are mutually exclusive. Both branches
use the same command and owner receipt; there is no URL fetch or publication
shortcut. The actual-Lua owner fixture now contains five vectors including RDF.

Follow-up local qualification: 472 tests and 13 subtests passed, with the same
three environment-gated skips described above. New checks exercise actual Lua
receipts and header stripping, old-scope/AI-actor/intent denials, complete nested
execution payloads, route preservation and HUMAN selector separation. CI and
owner pairwise receipts are additional gates; these results do not establish
target installation or a complete CSV end-to-end result.
