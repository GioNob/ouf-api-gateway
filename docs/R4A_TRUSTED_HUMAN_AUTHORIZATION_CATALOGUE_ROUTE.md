# R4a trusted-HUMAN Authorization namespace

Checkpoint 24 September 2026.

## Why this is a namespace, not a list of one-off routes

During R4a the capability reconciler first exposed a missing public route for
`/api/trusted-human/v1/authorization/capabilities`. After that route was
installed, the next read-only probes showed the same 404 for `/access` and
`/policies`. The defect was therefore architectural: the trusted-HUMAN
Authorization surface had never been materialized as a governed Gateway
namespace.

The Gateway now owns one bounded namespace:
`/api/trusted-human/v1/authorization/*`, with separate GET, POST, PUT and
DELETE route IDs. All four bindings require OIDC, scope
`authorization.policy.admin`, actor `HUMAN`, owner `authorization`, a
5 MiB request-body ceiling and a 10 second upstream timeout. The namespace is
not MCP-mediated.

The Gateway authenticates the HUMAN bearer and strips forged `X-OUF-*`
headers. It intentionally preserves the original Authorization bearer because
Onboarding is itself the authoritative trusted-HUMAN resource server:
Onboarding revalidates issuer, audience, identity and scope and establishes the
server-side `TrustedWriteProof` required for state-changing calls.

## Repeatable deployment

1. Compile `ouf-config`.
2. Apply the governed installation projection.
3. Materialize the namespace with
   `tools/materialize_trusted_human_authorization_runtime.py`.
4. Deploy only that materialization with
   `ops/apisix/deploy_trusted_human_authorization.py`.
5. Keep the emitted `BACKUP=.../previous.json` until acceptance completes.
6. Run anonymous smoke probes: capability catalogue, access review and policy
   collection must all return 401 rather than 404.
7. Only then execute authenticated trusted-HUMAN workflows.

The deployer snapshots the complete managed set before the first write,
including the two superseded capability-only route IDs. It verifies readback,
removes those legacy IDs, and restores the full previous set on any failure.

The 5 MiB request-body limit is enforced at the Gateway with APISIX
`client-control` and independently by the Onboarding Authorization boundary.

## Authorization lifecycle

Catalogue registration, PolicyBundle publication and grants remain three
separate actions. A successful namespace rollout does not register a
capability, change the ACTIVE bundle or grant access.

R4a must continue with a scripted HUMAN workflow that:
- exports the ACTIVE PolicyBundle without losing capabilities or grants;
- creates a new draft with monotonic version increment;
- previews and simulates before publish;
- publishes only through the trusted-HUMAN surface;
- verifies the new ACTIVE bundle and downstream refresh;
- proposes and confirms grants separately.

That workflow belongs in Source Onboarding and must be reusable for future
capabilities; it must not depend on chat history or direct database mutation.
