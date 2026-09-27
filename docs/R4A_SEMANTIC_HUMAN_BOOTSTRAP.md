# R4a Semantic cold start: first HUMAN publication

The 27 September lab inventory found 42 APISIX routes and no matching route
for the first Semantic publication. The Registry had zero published sets and
zero ACTIVE artifacts. The managed-file asset
`8ec8ae90-808a-4d9e-907c-d56de119e376` has a completed profile, but no
governed Semantic reference or Onboarding configuration has been published.

This package adds eight versioned HUMAN RouteBindings:

| Operation | Capability | Route ID |
| --- | --- | --- |
| Create draft artifact | `ouf.semantic.propose` | `semantic-artifact-propose` |
| Import a bounded RDF draft | `ouf.semantic.propose` | `semantic-rdf-import` |
| Validate revision | `ouf.semantic.review.prepare` | `semantic-revision-validate` |
| Request approval | `ouf.semantic.approval.request` | `semantic-approval-request` |
| Read the complete HUMAN review card | `ouf.semantic.review` | `semantic-human-card` |
| Decide approval | `ouf.semantic.approve` | `semantic-human-decision` |
| Publish approved revision | `ouf.semantic.publish` | `semantic-human-publish` |
| Search published artifacts | `ouf.semantic.search` | `semantic-artifact-search` |

The existing `ouf.semantic.read` registration permits SERVICE only and is
immutable in Authorization. It continues to serve internal references and
exports. HUMAN review uses the challenge card, which includes the draft
definition, labels, validation hash and artifact identity; the installer does
not expose a HUMAN route under the SERVICE read capability.

The compiler carries a bounded, anchored `uriRegex` selector through to
APISIX `vars`. This separates POST `/decision` from POST `/publish` under the
same challenge namespace, each with its own exact OAuth scope. The
materializer enforces eight expected IDs, methods, scopes, selectors and the
installation's Semantic service binding. It preserves `Authorization` for
the owner, strips incoming trusted identity headers, validates OIDC/JWKS and
HUMAN actor type, and proxies to the installation-bound service. A remote
service outside the verified installation binding is rejected.

`ops.apisix.deploy_semantic_human` snapshots **only** these eight IDs before
any route write, refuses drift on an already installed ID, reads back every
route, checks anonymous denial on each concrete path and restores the
snapshot on failure. Its `--restore` mode accepts the initial seven-ID
snapshot as well as the new eight-ID snapshot.
The snapshot remains in the protected backup directory. It does not touch
managed-file upload, picker, login or the existing internal SERVICE route.

IAM before route activation:

1. In Onboarding, `r4a_semantic_human_scopes.py plan/apply/verify` reconciles
   the seven OIDC client scopes and OPTIONAL bindings to `ouf-human-admin`.
2. `r4a_semantic_authorization_bootstrap.py plan/apply` uses one verified
   `ouf-admin` device login per invocation, registers only missing exact
   Semantic capability descriptors, previews a single additive policy version
   with seven HUMAN grants, persists private draft state, publishes and
   verifies. It copies the active unconstrained admin grant's validity period.
3. Compile and project this Gateway catalogue using the active installation
   projection. Materialize with an APISIX environment secret reference. The
   route installer checks the materialization before mutation.

After installation, a fresh HUMAN token must contain the requested scopes.
Exercise each route with a valid token and a missing-scope token: exact 2xx/4xx
behavior through real APISIX and owner Authorization is still a live gate.
The first Semantic artifact and mapping require HUMAN review and approval;
none is pre-authorized by this bootstrap. R-SMOKE remains OPEN until the same
CSV reaches Onboarding DRAFT/ACTIVE, Ingestion, UDP, and search without a
fixture or manual SQL bypass.
