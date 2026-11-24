# Gateway analysis mandates v1

Sprint 03, tranche T2. Task-51p adds a fourth internal POST binding to task-51n (`4ced53e`) so a paused MCP worker can observe its mandate under C.2 and C.3 of `ouf.analysis.mandate.v1`. The dispatch response preserves the owner status and bytes. `X-OUF-Analysis-Decision` and `X-Correlation-ID` identify the Gateway admission and are authenticated on the Gateway-to-MCP HTTPS connection. Clients must verify the Gateway certificate. Issue and interactive revoke carry the existing signed `X-OUF-Delegation` and the MCP workload bearer. Revoke without a delegation requires a positive IAM decision for `admin-revoke` on the specific mandate.

## Worker status during a pause

`POST /internal/analysis/v1/mandates/status` accepts exactly `{mandateId, generation}`. The ID is a UUID and the generation uses the same unsigned decimal string as dispatch. The worker presents its service bearer. The authority authenticates it through the dispatch introspection adapter. It checks issuer, tenant and workload against the mandate, then requests an IAM decision for the service principal to observe this specific mandate and protected HUMAN subject. The IAM adapter must independently establish that association. A shared MCP client ID or a subject copied from the target record alone cannot establish it. This read works with dispatch disabled and without an active attempt reservation.

| Result | Worker contract |
|---|---|
| 200 | Exactly `{mandateId, generation, state, expiresAt, decisionRef}`. An active mandate becomes `EXPIRED` at its recorded UTC deadline. An explicitly revoked mandate stays `REVOKED`. The opaque `decisionRef` identifies the audit entry for this read. |
| 403 / 404 | Invalid service credentials yield `403 ANALYSIS_AUTHORITY_DENIED`. Unknown IDs, foreign workloads or subjects, and denied observation yield `404 ANALYSIS_MANDATE_UNKNOWN` even with an incorrect generation. |
| 409 | After authorization, any generation mismatch returns only `ANALYSIS_STALE_EXECUTION`. Revocation advances the generation. A paused worker holding the previous generation must stop that execution and reconcile through MCP's authoritative state. It can observe `REVOKED` when it holds the current generation. |
| 429 / 503 | Local quota exhaustion returns `429 ANALYSIS_BACKOFF` and seconds until the window ends in `Retry-After`. An unavailable IAM decision yields `503 ANALYSIS_AUTHORITY_UNAVAILABLE`. The worker applies its existing bounded pause budget. |

The Gateway samples state and expiry after IAM returns, in the transaction that appends the read audit. Successful polls record the opaque mandate and workload references, requested generation and observed state. A poll preserves the mandate, expiry, command ledger and dispatch accounting. Both request and response have a 1024-byte ceiling.

## Installation register (D-065)

The private Gateway service exposes the WSGI factory `tools.analysis_service:application()` on an installation-managed HTTPS listener. It requires Python and the repository's `jsonschema` dependency. APISIX authenticates the caller with the established OIDC settings, then uses a verified HTTPS connection to that listener. Install the authority's CA in the APISIX Lua trust store. The authority independently authenticates the workload. The MCP reservation endpoint and IAM can each reside on a separate host.

| Installation field | Scope, bounds and activation |
|---|---|
| `services.bindings.ouf-gateway-analysis-mandates`, `services.ports.ouf-gateway-analysis-mandates` | Bundle host and port of the private Gateway listener. Use its certificate DNS name. Each RouteBinding governs its inbound body ceiling and relay timeout. |
| `OUF_ANALYSIS_CONFIG` | Path to private UTF-8 JSON configuration. Required `contract` is `ouf.analysis.installation.v1`. Reload by coordinated service restart. |
| `dispatchEnabled` | Optional installation boolean, default `false`. Activate only after IAM, reservation, owner verification, deduplication and capacity gates. Issue and revoke remain available independently. |
| `statusReadsPerMinute` | Optional integer 1–3600, default 60. Maximum authenticated status lookups per 60-second window across the installation's MCP workload. The first charged lookup starts the window. Unknown, denied and stale lookups count. All authority processes share the counter in the existing store. Coordinated restart applies a changed limit and preserves usage. |
| `store` | Existing Gateway SQLite file on durable local storage. All authority processes for this installation must open the **same file**. Mount loss fails startup. Run a single storage authority for remote APISIX replicas. Size and back up the database for the ledger and audit retention. |
| `manifestFile` | Immutable, installation-published MCP JSON snapshot. `manifestChecksum` is SHA-256 of the supplied file bytes. Each enabled entry must be ACTIVE and match the checked-in capability, owner, operation class, binding and schema. The provisional batch declaration alone cannot enable T2. |
| `issuer`, `audience`, `workload` | Required OIDC issuer, Gateway audience and MCP service client. Match the governed execute routes and projected OIDC settings. |
| `delegationKeyEnv` | Name of the existing Gateway delegation key environment binding. The owner receipt keys remain at the respective execute routes. |
| `introspection`, `decisions`, `reservations`, `execute` | Each populated endpoint has exactly `url`, `caFile`, `clientCertFile`, `clientKeyFile`. Use destination-specific TLS trust, client credentials and authorization. The first three URLs identify exact POST endpoints. `execute.url` is the HTTPS origin of the governed Gateway. `decisions: null` represents an installation without a remote current-right verifier and yields 503. |
| `timeoutSeconds` | Required integer 1–30 for each private HTTP connection and socket operation. No transport retries or redirects. |
| `mandateTtlSeconds`, `proofTtlSeconds` | Required integers 1–86400 and 1–30. The grant expiry bounds issuance. The worker credential, mandate, IAM decision and MCP reservation bound each proof. Activity cannot extend a deadline. |
| `maxResultBytes` | Required integer 1–1048576. The operation's manifest hard limit can lower this value. |

The service hosting layer must protect capacity for revocation and reconciliation while owner calls are blocked. A dispatch uses an independent SQLite connection and commits admission before starting the owner request. During a release, fence the previous authority processes before switching manifest, policy, activation or database. Rollback keeps the additive tables and stops autonomous dispatch. The predecessor remains readable without a schema downgrade.

## MCP reservation check

The private MCP endpoint authenticates the Gateway client certificate. It checks the **durable current reservation** for the attempt, worker, fence, plan, mandate, generation, operation, intent and exact arguments. It determines issuer, subject, tenant, profile and manifest from that reservation. For status/candidates it also proves the request ID belongs to that plan and owner subject. A successful reply grants a short admission lease through `validUntil`. The MCP must coordinate re-fencing or cancellation with this lease and Gateway revocation.

| Message | Fields |
|---|---|
| POST | `contract="ouf.analysis.reservation-check.v1"`, random `nonce`, `workload`, `mandateId`, `analysisId`, `generation`, `intentKey`, `attemptId`, `fence`, `operation`, `argumentsHash`, plus `requestId` when present in arguments |
| 200 | `requestHash`, `current` boolean, `issuer`, `tenant`, `subject`, `reservationRef`, `ordinalsRef`, `changeSeq`, `manifestChecksum`, `profileHash`, `validUntil` (Unix seconds), `requestId` (verified UUID for request-bound operations, explicitly null otherwise) |
| Errors | Missing or foreign scope/request returns 404. Superseded attempt, fence, generation, or a mismatch to the reserved arguments returns 409. Explicit pressure or unavailability returns 429 or 503 and may carry `Retry-After`. |

`requestHash` hashes the exact UTF-8 POST bytes. The profile and argument hashes use compact, UTF-8 JSON, lexicographically sorted keys, preserved array order, unescaped Unicode and decimal integers. All legal property names in these objects are ASCII. Binary64 rounding, normalization of user text and a hash over parsed form fields would change the reservation contract.

## Current authority adapter

The authority sends the service bearer only to the configured RFC 7662 introspection endpoint and to governed execute. Introspection must return active SERVICE identity, exact issuer, audience, MCP client ID, tenant, subject and live expiry. The separate decision adapter evaluates current grants for this issuer, actor, tenant, protected HUMAN subject and resource on every command and dispatch. OUF and pre-existing IAM installations may implement this interface with their own policy systems.

Each decision POST contains `contract="ouf.analysis.authority-check.v1"`, a fresh `nonce`, `action` (`issue`, `dispatch`, `revoke`, `admin-revoke`, `status` or `renew-budget`), `issuer`, `workload`, `workloadSubject`, `tenant`, `subject`, `actor`, `actorRef`, `analysisId`, full `profile` and `manifestChecksum`. Existing mandates add `mandateId`, `grantRef` and `policyRef`. Dispatch adds `operation`, `intentKey`, `argumentsHash` and `resourceId`. HUMAN commands add `delegatedClient`, `delegatedScope` and `acr`. The adapter must authorize the exact action, including the administrative role when requested. For `status`, the decision and its validity bounds cover current observation rights, including observation after the execution mandate expires or is revoked.

A denial returns the request hash and `allowed=false` or HTTP 403. An allow returns exactly `requestHash`, `allowed=true`, `policyRef`, `grantRef`, `decisionRef`, `validUntil`, `grantExpiresAt` (Unix seconds), `allowedOperations`, `roles`, `acr`, and `client` for the effective HUMAN context. The Gateway intersects operations with delegated scope, pinned catalog and the five-operation allowlist. Discovery retains its common execute scope. The adapter must obtain decision and expiry evidence from the actual IAM.

## THS renewal channel (D-091)

| Caller and route | Credentials and body |
|---|---|
| Browser → Onboarding, `GET /trusted-human/analysis-renewal/{reviewRef}` | Onboarding's existing OAuth session. The GET binding also serves page assets in that directory. The shared login and callback stay with Onboarding. |
| Browser → Onboarding, `POST /trusted-human/analysis-renewal/{reviewRef}/decision` | Onboarding authenticates the session, checks CSRF and ties the path reference to the submitted command. Both browser routes preserve the path and cookies and strip caller-supplied authorization and OUF headers. |
| Onboarding → Gateway → MCP, `POST /internal/analysis/v1/renewals/read` | Current HUMAN access token for the configured THS client with scope `ouf.analysis.renewal.read`. The JSON body contains only `reviewRef`. MCP resolves the reference within the verified subject and tenant and checks current read rights before returning the proposal. |
| Onboarding → Gateway → MCP, `POST /internal/analysis/v1/renewals/decide` | Same client, scope `ouf.analysis.renewal.decide`. The JSON body has exactly `reviewRef, proposalVersion, proposalHash, expectedSeq, commandKey, decision, items`. Decisions are `APPROVE`, `CHANGES_REQUESTED` and `CLOSE_PARTIAL`. Each item has exactly `field, comment`. |
| MCP → Gateway, `POST /internal/analysis/v1/mandates/renewal-check` | Current MCP SERVICE bearer with scope `ouf.analysis.mandate.renewal-check` and the opaque decision delegation from the authenticated THS hop. MCP sends the exact seven command fields plus `analysisId, incidentId, mandateId, generation` from its durable proposal. |

The command uses a lowercase UUIDv4 key, a SHA-256 proposal digest and a canonical decimal sequence. The Gateway preserves the representation of the owner's positive proposal version (JSON integer or canonical decimal string, at most 2^63−1) throughout hashing and authorization. Changing that representation changes the signed command. MCP supplies the proposal under `ouf.analysis.renewal.v1`, including the five dimensions `Calls, Attempts, Objects, Bytes, Millis`.

APISIX relays the private requests over verified HTTPS to the Gateway service. For read and decide, the service introspects the HUMAN token, including issuer, audience, authorized client, subject, tenant, expiry and exact scope. It sends canonical command bytes over client-authenticated TLS to the same path on the configured MCP origin. Only content type and the Gateway-generated `X-OUF-Delegation` travel on this hop. The signed context uses a distinct purpose for each route (`analysis-renewal-read` or `analysis-renewal-decide`) and contains the SHA-256 `requestHash` of the forwarded bytes. MCP authenticates the Gateway's client certificate, checks the context, hash and expiry on this connection, and returns the decision proof unchanged to the Gateway for the check. The delegation signing key stays at the Gateway.

For a decision, MCP first resolves the current proposal within the verified scope and checks its version and hash. The Gateway verifies the decision signature and command hash, matches the HUMAN to the durable mandate holder, and requests a fresh `renew-budget` decision. The IAM query carries the stored grant and policy, exact mandate, generation, analysis, incident, proposal version and hash, review reference, expected sequence, command key, decision and command hash. The IAM response must bind the complete query including its nonce. The Gateway re-reads state and generation after IAM returns, in the same transaction as the audit.

The successful check contains exactly `requestHash, decisionRef, grantRef, validUntil`. This `requestHash` hashes the **exact incoming check bytes**. The verifier supplies the decision and grant references. The minimum of the mandate, grant, IAM decision, workload credential, THS proof and installation proof lifetime bounds `validUntil` in Unix seconds. MCP verifies that receipt against its own request and checks validity, fence, state and consumption at commit. Only `APPROVE` can increase a budget. Dispatch still performs its own fresh admission.

| HTTP result | Renewal outcome |
|---|---|
| 400 | `ANALYSIS_INPUT_INVALID` for invalid input, including duplicate or extra command fields |
| 403 / 404 | `ANALYSIS_AUTHORITY_DENIED` for absent authority or changed grant. `ANALYSIS_MANDATE_UNKNOWN` for a foreign or unknown mandate or owner scope |
| 409 | `ANALYSIS_STALE_EXECUTION` for superseded generation or proposal. MCP returns `ANALYSIS_COMMAND_CONFLICT` for key reuse with different content and `ANALYSIS_RENEWAL_USED` for a second renewal of the incident |
| 410 | `ANALYSIS_MANDATE_EXPIRED` at the mandate deadline |
| 429 / 503 | `ANALYSIS_BACKOFF` or `ANALYSIS_AUTHORITY_UNAVAILABLE`, preserving `Retry-After` when supplied |

The Gateway relays the MCP response bytes and status. Identical replay goes to MCP with the same command key and fresh THS evidence. MCP rechecks read rights before returning the original receipt and owns the single durable consumption. Neither Gateway hop retries a mutation. Following an ambiguous outcome MCP reconciles the original command.

The decide relay is re-entrant. It keeps one request of the Gateway service open while MCP calls `renewal-check` on the same service. The hosting layer must therefore serve at least two concurrent requests per authority, besides the capacity reserved for revocation and reconciliation. Otherwise the nested check waits behind the relay and the decision fails after the hop timeout, leaving MCP to reconcile it.

The optional installation profile field `renewalChannel` contains exactly `thsClient` and `mcp`. The former identifies the THS OIDC client and must differ from the MCP workload. The latter uses the existing `url, caFile, clientCertFile, clientKeyFile` endpoint shape with an HTTPS origin. With this field absent the new review relay returns 503. The predecessor configuration and SQLite schema remain compatible. The versioned RouteBindings set the request body ceiling (default and maximum 131072 bytes) and hop timeout (default and maximum 30 seconds). Installations may lower either to a positive integer. The relay also applies the existing `timeoutSeconds`, `proofTtlSeconds` and `maxResultBytes` profile.

The D-087 release adds five RouteBindings. On the same projection the canonical predecessor array of 35 resources has SHA-256 `80a5a70402ae0d74cec097be9d6dd6ba487e275583954809694927b22218d976`. Use the read-only plan family `analysis-renewal` for these five routes and its restore readback to detect intervening changes. GW-55C-01 through GW-55C-04 exercise synthetic policy, revocation, release equivalence and restore. The real IAM verifier, MCP transaction and Onboarding session/CSRF require their respective owner qualifications.

## Durable state and reconciliation

| Additive table | Purpose |
|---|---|
| `analysis_mandate_v1` | Protected authority record per subject and plan, with profile, manifest, issuer, workload, policy, grant, limits and generation |
| `analysis_command_v1` | Actor-scoped command fingerprint and exact reply for issue/revoke replay |
| `analysis_discovery_v1` | Stable subject, intent, owner key hash and argument fingerprint across discovery retries |
| `analysis_attempt_v1` | Atomic admission, attempt uniqueness, fence, ordinal and reservation references, owner outcome and revocation crossing |
| `analysis_audit_v1` | Decision, protected scope and profile hashes, operation, generation, effect and MCP change sequence when available |
| `analysis_status_quota_v1` | Single installation-wide row containing the end of the status window and its lookup count |

Revocation marks admitted or uncertain attempts in the same transaction that advances the generation. Its audit row contains the in-flight count. An owner response crossing revocation returns 409 and authenticated `X-OUF-Analysis-Effect: IN_FLIGHT`; the durable attempt retains the observed owner status and request ID when available. A crash can leave an ADMITTED row or an UNCERTAIN outcome. Recovery uses MCP accounting, owner status and Semantic deduplication with the original owner key and fingerprint. Automatic deletion, retry and budget renewal are outside this Gateway owner.

Disable credential and payload logging on the private listener, proxies and IAM/MCP adapters. Audit contains protected references and outcomes. Keep raw arguments, tokens, owner response bodies, signed proofs and installation coordinates out of logs. Audit retention/backup and qualification with actual installation IAM, MCP and owners are release responsibilities.
