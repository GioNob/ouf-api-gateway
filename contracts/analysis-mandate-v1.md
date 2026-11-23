# Gateway analysis mandates v1

Sprint 03, tranche T2. Predecessor `3d69cb4` (task-51m). The three internal POST bindings implement C.2 of `ouf.analysis.mandate.v1`. The dispatch response preserves the owner status and bytes. `X-OUF-Analysis-Decision` and `X-Correlation-ID` identify the Gateway admission and are authenticated on the Gateway-to-MCP HTTPS connection. Clients must verify the Gateway certificate. Issue and interactive revoke carry the existing signed `X-OUF-Delegation` and the MCP workload bearer. Revoke without a delegation requires a positive IAM decision for `admin-revoke` on the specific mandate.

## Installation register (D-065)

The private Gateway service exposes the WSGI factory `tools.analysis_service:application()` on an installation-managed HTTPS listener. It requires Python and the repository's `jsonschema` dependency. APISIX authenticates the caller with the established OIDC settings, then uses a verified HTTPS connection to that listener. Install the authority's CA in the APISIX Lua trust store. The authority independently authenticates the workload. The MCP reservation endpoint and IAM can each reside on a separate host.

| Installation field | Scope, bounds and activation |
|---|---|
| `services.bindings.ouf-gateway-analysis-mandates`, `services.ports.ouf-gateway-analysis-mandates` | Bundle host and port of the private Gateway listener. Use its certificate DNS name. The three RouteBindings govern the inbound body ceiling and relay timeout. |
| `OUF_ANALYSIS_CONFIG` | Path to private UTF-8 JSON configuration. Required `contract` is `ouf.analysis.installation.v1`. Reload by coordinated service restart. |
| `dispatchEnabled` | Optional installation boolean, default `false`. Activate only after IAM, reservation, owner verification, deduplication and capacity gates. Issue and revoke remain available independently. |
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

Each decision POST contains `contract="ouf.analysis.authority-check.v1"`, a fresh `nonce`, `action` (`issue`, `dispatch`, `revoke` or `admin-revoke`), `issuer`, `workload`, `workloadSubject`, `tenant`, `subject`, `actor`, `actorRef`, `analysisId`, full `profile` and `manifestChecksum`. Existing mandates add `mandateId`, `grantRef` and `policyRef`. Dispatch adds `operation`, `intentKey`, `argumentsHash` and `resourceId`. HUMAN commands add `delegatedClient`, `delegatedScope` and `acr`. The adapter must authorize the exact action, including the administrative role when requested.

A denial returns the request hash and `allowed=false` or HTTP 403. An allow returns exactly `requestHash`, `allowed=true`, `policyRef`, `grantRef`, `decisionRef`, `validUntil`, `grantExpiresAt` (Unix seconds), `allowedOperations`, `roles`, `acr`, and `client` for the effective HUMAN context. The Gateway intersects operations with delegated scope, pinned catalog and the five-operation allowlist. Discovery retains its common execute scope. The adapter must obtain decision and expiry evidence from the actual IAM.

## Durable state and reconciliation

| Additive table | Purpose |
|---|---|
| `analysis_mandate_v1` | Protected authority record per subject and plan, with profile, manifest, issuer, workload, policy, grant, limits and generation |
| `analysis_command_v1` | Actor-scoped command fingerprint and exact reply for issue/revoke replay |
| `analysis_discovery_v1` | Stable subject, intent, owner key hash and argument fingerprint across discovery retries |
| `analysis_attempt_v1` | Atomic admission, attempt uniqueness, fence, ordinal and reservation references, owner outcome and revocation crossing |
| `analysis_audit_v1` | Decision, protected scope and profile hashes, operation, generation, effect and MCP change sequence when available |

Revocation marks admitted or uncertain attempts in the same transaction that advances the generation. Its audit row contains the in-flight count. An owner response crossing revocation returns 409 and authenticated `X-OUF-Analysis-Effect: IN_FLIGHT`; the durable attempt retains the observed owner status and request ID when available. A crash can leave an ADMITTED row or an UNCERTAIN outcome. Recovery uses MCP accounting, owner status and Semantic deduplication with the original owner key and fingerprint. Automatic deletion, retry and budget renewal are outside this Gateway owner.

Disable credential and payload logging on the private listener, proxies and IAM/MCP adapters. Audit contains protected references and outcomes. Keep raw arguments, tokens, owner response bodies, signed proofs and installation coordinates out of logs. Audit retention/backup and qualification with actual installation IAM, MCP and owners are release responsibilities.
