# Keycloak OUF current-right verifier

The installation serves `tools.iam_keycloak_decisions:application()` at the two private HTTPS URLs in the approved `ouf.iam-profile.v1` profile. The mandate Gateway points its `introspection` and `decisions` bindings at those URLs and enables `keycloakCurrentRights`. This is an installation adapter for `ouf.analysis.authority-check.v1`. A pre-existing IAM can continue to implement the original pair of endpoints.

## Private bindings (installation register D-065)

Set `OUF_KEYCLOAK_DECISIONS_CONFIG` to a private JSON file with these fields.

| Field | Installation binding |
|---|---|
| `profileFile` | Materialized, approved Keycloak OUF profile. The verifier consumes `trust.issuer`, `gatewayAudience`, `introspection`, `decisions`, the MCP and THS client IDs, the grant contract and the two IAM rates. The realm and any Keycloak base path come from the realm issuer. |
| `resourceServer` | Client ID of the confidential Authorization Services resource-server dedicated to assignment resources. The verifier takes this ID from `grant.resourceServer.clientId` in the approved profile. This optional configuration field must match the profile exactly or startup fails. Its service account is distinct from MCP and THS. |
| `secretEnv` | Environment binding for the credential identified by `grant.resourceServer.secretRef`. A map keyed by the profile reference selects the environment variable by exact match. The existing single variable-name form binds that variable to the profile's sole resource-server credential. The custodian materializes the referenced secret into that variable. |
| `caFile` | Private CA file resolved by the installation from `trust.caRef` for the native Keycloak HTTPS endpoint. Host verification is required. |
| `gatewayTlsPrincipal` | Server-authenticated TLS identity authorized to prepare and consume decisions. Configure the private mTLS terminator to require an approved client certificate and populate the WSGI variables `SSL_CLIENT_VERIFY=SUCCESS` and `REMOTE_USER` from certificate verification. Exclude direct access to the WSGI socket. The read-only qualification client may use ordinary introspection with its own certificate. |
| `store` | Existing, protected SQLite file on durable storage shared by every worker of this adapter installation. The adapter initializes its own two tables. Fence previous workers when changing the installation profile or restoring storage. |
| `timeoutSeconds` | Optional integer 1–30 seconds per connection or socket operation, default 5. |
| `clientCertFile`, `clientKeyFile` | Optional pair for installations requiring a separate TLS client identity on the native Keycloak connection. |

The two profile URLs must have distinct paths. The listener authorizes the clients for each path and disables credential, request-body and response-body logging. The issuer serves the native Keycloak APIs below. Secret rotation and TLS materialization belong to the installation custodian.

## Assignment selected at issue

The custodian provisions a user-owned Authorization Services resource of `grant.resourceType` with `ownerManagedAccess=true`. Its Keycloak owner ID is the verified HUMAN subject. The assignment credential has its own introspected `sub` under the shared MCP `client_id`. The lookup name is `ouf-analysis-` followed by SHA-256 of canonical UTF-8 JSON `[issuer,tenant,workload,workloadSubject]`. Select exactly one resource. Its native `_id` is the `grantRef`. A missing assignment denies issuance. Multiple matches yield 503. Replaying an issue against a replacement ID or policy conflicts with the original Gateway command.

| Resource attribute | Meaning |
|---|---|
| `issuer`, `tenant`, `workload`, `workloadSubject` | Exact issuer, verified tenant, MCP client ID and assignment principal. |
| `analysisId`, `profileHash`, `manifestChecksum` | Plan, SHA-256 of the exact canonical mandate profile, and pinned manifest. |
| `policyRef`, `grantExpiresAt` | Custodian-managed policy revision and absolute grant deadline in decimal Unix seconds. Rotate the revision on a change of policy identity. |
| `client`, `acr`, `roles` | Effective HUMAN context under this assignment. Interactive issue and revoke must match the verified delegation's client and ACR. Roles are a list of opaque references, empty when omitted. |

For every dispatch, including `semantic.discovery.status` and `semantic.discovery.candidates`, the verifier requires `resourceId == profile.profileId` on the subject's current assignment. The authenticated MCP reservation binds the discovery request ID to that plan and subject, and Semantic owns job deduplication. Job creation requires no IAM update.

Each scalar attribute is a one-element Keycloak string array. Configure scope-based permissions on the exact resource for the six action names and the supported mandate operation names. Keycloak policies must evaluate current HUMAN rights and the authenticated requesting principal for that assignment, including the separate administrative revoke permission. A generic shared MCP service-account subject cannot represent two independent assignments. The resource name, owner, scope and current policy are all checked. Only an explicit administrative grant can revoke on behalf of another assignment principal.

## Native Keycloak wire calls

All paths below are relative to the configured realm issuer. Configure the dedicated resource-server for service accounts, authenticated RFC 7662 introspection and its own Protection API (`uma_protection`). Keep only assignment resources in this resource-server. The verifier uses read operations on the Protection API. Realm administrator, user impersonation and realm-management roles are unnecessary.

| HTTP request | Credential and evidence |
|---|---|
| `POST /protocol/openid-connect/token/introspect` | Form `token, client_id, client_secret`. Obtain current activity, issuer, audience, actor type, tenant, client, principal and expiry. THS uses the established HUMAN claim and scope checks. |
| `POST /protocol/openid-connect/token` | Form `grant_type=client_credentials, client_id, client_secret`. Obtain a protection API token (PAT) for this resource-server. |
| `GET /authz/protection/resource_set?name={assignmentName}&exactName=true&max=2` | PAT. Select an exact assignment ID at issue. |
| `GET /authz/protection/resource_set/{grantRef}` | PAT. Read current resource metadata and verify the returned ID, owner and binding. An exact resource 404 denies. |
| `POST /protocol/openid-connect/token` | Actual assignment bearer in the Authorization header. Form `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket`, configured `audience`, `response_mode=permissions`, `submit_request=false`. Issue requests `permission={id}` to enumerate permitted scopes. Other actions request `{id}#{action}`, with `,{operation}` appended for dispatch. Require the same `rsid` and the necessary granted scopes. |

The UMA request pushes the exact decision bytes as a UTF-8 string and their digest in the single-valued claims `ouf.authorityRequest` and `ouf.requestHash` using a base64url JSON `claim_token` and Keycloak's `urn:ietf:params:oauth:token-type:jwt` claim format. Policies can constrain the exact dispatch resource or the THS renewal proposal and command. Use independently owned IAM bindings and authenticated identity for grants. Caller-supplied context alone cannot confer rights. Present an ordinary workload access token. The adapter rejects introspection evidence carrying RPT permissions.

## Decision and failure semantics

1. The Gateway authenticates the workload and verifies the HUMAN delegation where required. After constructing the v1 decision, it posts the bearer to the same private introspection connection with the optional form field `ouf_authority_request` containing the base64url-encoded decision bytes. Only the authenticated Gateway can use this extension.
2. The adapter introspects again, matches the verified principal and tenant to the request, and calls Keycloak UMA as that principal. It records a single-use result keyed by the digest of the exact bytes, including the nonce, and the verifier binding. The stored fields are expiry, grant ID and granted scopes. Acknowledgement to the Gateway echoes the request digest. The bearer and HUMAN command are never stored.
3. The Gateway sends the original v1 JSON to the decision endpoint. The verifier consumes the evidence atomically and checks the exact assignment at Keycloak. Its allow ends at the earliest of the assignment deadline, token expiry and the start of the second introspection plus `grant.revocationTtlSeconds.value`. A fresh command or poll repeats the IAM evaluation. Renewal binds the THS command hash, proposal, incident and generation through those exact bytes and the Gateway's verified delegation. Local mandate revocation and withdrawal of the IAM assignment are separate owner operations.

An explicit denial yields `allowed=false` and the byte hash. Missing or already consumed evidence, inconsistent result IDs or scopes, malformed replies, IAM authentication errors and timeouts fail closed with 503. If Keycloak rejects the permission parameter, a scoped read distinguishes a removed assignment from a malformed UMA request. Each new authorization after a crash needs fresh evidence. Expired handoffs are pruned during preparation and consumption. No transaction spans an HTTPS call.

Every native introspection consumes one `iam.introspectionsPerMinute` unit. Every PAT, Protection API and UMA call consumes one `iam.decisionsPerMinute` unit. Both use installation-wide, persisted 60-second windows. Configure the profile's positive `value, default, maximum`, with value and default each at most maximum. A normal existing-mandate check uses two introspections and three decision units. Successful issue uses two additional decision units for selection. Local exhaustion yields 429 with the remaining wait. Native unavailability yields 503 and carries a valid Retry-After in seconds. The existing caller owns bounded pause and recovery.

## Qualification

Run `python -m unittest tests.test_iam_keycloak_decisions` offline. GW-55H-01…06 exercise the normal mandate path with a controlled clock, two private TLS hops and a mutable Keycloak HTTP fixture. Re-run GW-51P-01…10 with the Gateway suite and correlate PET-authorization-121 with the Authorization owner. The release gate still needs the real-profile 55m probe, effective Keycloak policies, separate assignment principals and a correlated denied dispatch with zero owner forwards.
