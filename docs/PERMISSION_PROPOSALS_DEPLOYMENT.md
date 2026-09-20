# Chatbot permission proposals and trusted human review

This increment extends the tested MCP status transport without exposing an authorization-admin proxy. Deploy Onboarding, Gateway, then MCP; publish the dedicated policy grants only after these components are ready. It does not change a running installation by itself.

## Boundaries

Three closed POST routes are materialized by `python3 -m tools.materialize_permission_proposals`:

| MCP capability | Gateway suffix under `/internal/capabilities/v1/execute/authorization/` | Owner suffix under `/api/internal/v1/authorization/permissions/` |
|---|---|---|
| authorization.permissions.read | read | read |
| authorization.permissions.propose | propose | propose |
| authorization.proposal.read | status | status |

The original status route remains closed to its original envelope. Each new route requires the configured MCP workload token, the signed human delegation and the capability scope. Identity fields in the request must match the verified delegation. Neither `confirm` nor `publish` is an MCP route.

The owner receipt binds method, owner path, capability, exact original request bytes, identity, tenant, roles, scope, idempotency key and a maximum 30-second lifetime. Forwarding the original JSON preserves empty arrays versus empty objects. Onboarding extracts `Arguments` only after verifying the receipt; body identity fields never become authority.

## Two distinct secrets and Unix permissions

Keep the existing MCP delegation key. Generate a **different** 32-byte random value, encoded as 64 ASCII hexadecimal characters, for `OUF_AUTHORIZATION_OWNER_KEY`. Share it only between APISIX and Onboarding; never mount it in MCP or include it in runtime JSON or chat.

APISIX receives this value through its protected container environment and `nginx_config.envs` must include `OUF_AUTHORIZATION_OWNER_KEY`. A generated Nginx directive may quote the name (`env "OUF_AUTHORIZATION_OWNER_KEY";`); validate the directive semantically, not by one exact string. Preserve existing OIDC/delegation environment entries.

Onboarding reads the same ASCII value from `ouf.authorization.delegation.key-file`. Mount that file read-only, readable by container UID/GID **10003:10003**, for example ownership 10003:10003 and mode 0400. APISIX runs as **636:636**: its YAML mount must be readable by that identity (0640 with matching group or 0400 with matching owner). Do not solve this by making secret files world-readable. Check readability inside the candidate container before switching. Preserve networks, aliases, existing mounts and restart policy. Keep the previous container stopped for rollback; do not remove it before an authenticated smoke test.

## Materialize and review

Compile the current repository configuration against the approved installation projection first, then:

```sh
python3 -m tools.materialize_permission_proposals \
  --runtime "$RUNTIME_FILE" \
  --oidc-client-secret-ref '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET' \
  --delegation-key-env OUF_GATEWAY_DELEGATION_KEY \
  --owner-key-env OUF_AUTHORIZATION_OWNER_KEY \
  --output "$PERMISSION_ROUTES_FILE"
```

The output includes existing MCP routes, three delegated permission routes, and three route groups for the owner THS. Back up affected APISIX route definitions through the existing protected Admin API before replacing only those IDs. This materializer does not install routes or provision secrets. Do not apply its output with an unrelated deploy helper that selects only status route IDs.

THS routing forwards only `/trusted-human/authorization/`, its two assets, its proposal API, `/oauth2/authorization/ouf-ths`, and `/login/oauth2/code/ouf-ths`. These routes preserve the owner session cookie, strip incoming authorization/OUF identity headers and do not authenticate through Gateway's bearer-only plugin. Onboarding performs OAuth2 login and CSRF checks. The public host must terminate HTTPS. Configure the owner's absolute OAuth callback and public origin as described in its `docs/PERMISSION_PROPOSALS.md`; do not derive them from untrusted forwarded headers. Keep owner port 8080 private.

## Verification and rollback

Check: unauthenticated MCP remains 401; invalid owner proof is 403; propose returns PENDING with the configured HTTPS approval link; ACTIVE remains unchanged; unauthenticated THS redirects to IAM; confirm without CSRF fails; exact reviewed confirmation publishes once; changing ACTIVE requires a new proposal. Reject a proposal and verify no policy activation. Repeating a confirmation must not publish twice.

Tests cover actual APISIX 3.18 OIDC/JWKS/Lua, altered identities/scopes/proofs, a separate owner signing key, and closed request schemas. Onboarding CI independently consumes an immutable Gateway Lua fixture to validate JVM interoperability. Browser tests use an API fixture; they do not certify a live IAM installation or close PET/roadmap gaps automatically.

Rollback removes the new permission/THS route IDs and restores saved original MCP route definitions plus the prior containers. Published policy changes are separate governed operations; do not delete audit/proposal history or roll back the database migration destructively.

## 2026-09-20: align role-catalogue inputs before deployment

Gateway `d78f6aa` rejected `authorization.permissions.read` with `view=GRANTS`
although MCP `5615fdc` and Onboarding `4f7ff50` supported it. The public `/mcp`
request returned 200 carrying an error, while the internal permission route
returned 400: `additional properties forbidden, found view`. Reauthentication
and policy grants cannot repair a request-schema mismatch.

The permission dispatch schema now matches the MCP input schemas pinned at
`5615fdcad8cbcad9ff41ec3d0ad2ccbf9423c042`: legacy grant reads, explicit
`GRANTS`, `ROLES` without grant selectors, and `REPLACE_ROLES` with bounded
nominal or organizational assignments. Unknown fields, ambiguous selectors,
and confirmation/publication arguments remain forbidden. Owner validation,
policy checks and human confirmation remain mandatory. The APISIX integration
gate exercises both accepted and rejected inputs through the materialized
routes and verifies the exact arguments forwarded to the owner.

Deploy this Gateway schema with those MCP/Onboarding versions. Regenerate both
the compiled runtime and permission materialization, back up all affected route
IDs, then replace the reviewed routes. Updating repository files alone does not
update the schemas already stored in APISIX. No container rebuild or Keycloak
change is needed for this schema correction. Do not disable request-validation
or set additionalProperties=true. Rollback restores the prior route snapshot;
it also restores the older contract limitation.

Fetch and merge the exact verified commit. A restricted remote fetch mapping
can leave `origin/main` stale even after `git fetch origin main` updates
`FETCH_HEAD`; verify HEAD and the required materializer before compilation.

For a nominal human admin, verify the `ouf-chatgpt` access token includes
`ouf_actor_type=HUMAN`, tenant, subject, audience and scopes before refreshing
the plugin. A missing actor claim causes Gateway 401 even after OAuth login
succeeds. Confirm the selected linked account and obtain a fresh token after
correcting an IAM attribute. Never log bearer tokens or relax actor validation.
