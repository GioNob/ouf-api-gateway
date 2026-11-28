# Gateway mandate for the first round of BATCH_V1

Run the opt-in Gateway listener with `python -m tools.analysis_batch_service --profile <installation-profile>`. Materialize the authenticated MCP ingress with `--analysis-start-key-env <name>` and mount that environment key on APISIX and the listener. The existing 60-second delegation remains available.

The private HTTPS listener validates the client certificate chain and pins the MCP leaf certificate SHA-256 per installation. The HUMAN relay uses its own pin. The listener derives the peer role from TLS. Keep it behind the installation's network boundary.

## Ingress

All commands use JSON POST under `/internal/analysis-batch/v1/`. The stage server returns `mandateRef`, `generation`, `version`, `state`, `analysisId` and `expiresAtMs`. UUIDs and hashes use lowercase. The analysis ID and policy epoch use MCP's batch encodings.

| Command | Peer | Exact request fields |
|---|---|---|
| `prepare` | MCP | `startProof` from the Gateway's `X-OUF-Analysis-Batch-Start` on the same authenticated HUMAN `source.analysis.plan(BATCH_V1)` |
| `issue` | MCP | `mandateRef`, `generation`, `commandKey` |
| `dispatch` | MCP | `mandateRef`, `generation`, `analysisId`, `operation`, `arguments`, `attemptId`, `correlationId` |
| `expire` | MCP | `mandateRef`, `generation`, `expectedVersion` |
| `revoke` | HUMAN relay or MCP | `mandateRef`, `generation`, `expectedVersion` and a HUMAN bearer in `Authorization` |

MCP calls `prepare` before persisting the analysis and stores the resulting reference and generation with its start command. `prepare` creates an inert record and replays by issuer, tenant, subject and command key. The same authenticated plan can recover a lost prepare response. After its durable commit MCP calls `issue` with the same key. A retry can recover the committed result without the original proof. It sees the current state, including terminal states. Start proofs and bearer tokens are request-local. A pending start expires within 24 hours of its signed plan. An active mandate expires within 24 hours of activation.

To finish the first round or close the analysis, MCP durably fences scheduling, exposes the transition to the MCP state endpoint and calls `expire`. MCP finalizes the transition after the Gateway confirms the terminal state. Dispatch also connects an observed terminal phase to the same registry expiry. The shared registry is authoritative at the admission commit. Revocation and expiry block all later admissions. An admitted call may still return and its request ID can be reconciled.

The Gateway pins the discovery owner key and argument digest to the first-round work reference at admission. It records the request UUID after a successful Semantic response. If the response or the commit recording it is lost, MCP can recover using Semantic's atomic deduplication under the same subject, owner key and arguments. A different key or body for the same work reference fails. Status and candidates require the UUID in that durable binding. The Gateway makes one attempt per dispatch and relays bounded `Retry-After`. MCP owns the versioned retry budget and reconciliation.

## Authoritative evidence

The listener calls two configured HTTPS endpoints using mTLS and hostname verification. Each request includes a fresh nonce. Each response must bind `requestHash` to SHA-256 of the exact request body and supply `clockSynchronized: true`, `observedAtMs`, and `validUntilMs`. Timestamps are UTC epoch milliseconds from a synchronized clock. Validity is at most 30 seconds. The Gateway bounds skew using round-trip uncertainty and rechecks evidence at admission. It compares wall time to a monotonic clock and persists a UTC high-water mark across replicas and restarts.

Both endpoints receive the mandate context `contract` (`ouf.analysis.batch.mandate.v1`), `action`, `installation`, `version`, `issuer`, `tenant`, `subject`, `client`, `workload`, `analysisId` (null on MCP's issue query), `generation`, `startRef`, and the original `mode`, `assetId`, `profileId`, `schemaHash`, `commandKey` and `scope` array. Dispatch adds `operation`, `argumentsHash`, `attemptId`, and `requestId` for existing discovery jobs. `argumentsHash` hashes UTF-8 JSON with sorted keys, ASCII escapes and compact separators.

- **MCP state** returns `bound`, `analysisId`, `policyEpoch` and `phase` (`FIRST_ROUND`, `FIRST_ROUND_COMPLETE`, `CLOSED`, `CANCELLED`). `bound: true` attests the durable analysis, verified profile and start command for this subject. On dispatch it attests that `attemptId` and the exact arguments belong to the currently fenced first-round work, or that the analysis is leaving that phase. Discovery operations return `workRef`, a stable SHA-256 work reference across request, status and candidates.
- **Current rights** for issue and dispatch returns `active`, `allowed`, `policyEpoch`, `decisionRef`, `acr`, `scope` as a space-separated string, `roles` as an array, and `grants` mapping the four operation names to SHA-256 fingerprints of the currently effective grants and their constraints. The authority evaluates the subject, tenant, original client, verified profile and requested operation against current IAM and policy. Issue covers all four operations and the profile. A changed effective scope, grant, policy epoch, role set or ACR denies dispatch. An inability to verify current rights denies.
- **Current rights** for revoke independently authenticates the bearer and returns `active`, `allowed`, `actorType`, `issuer`, `tenant`, `subject`, `client`, and `operatorAuthorized` when applicable. An operator must use the configured THS client and have current authority to revoke this mandate in the bound tenant. The Gateway forwards the bearer only to this rights endpoint. A local clock incident still permits revocation using fresh synchronized remote evidence.
- **Current rights** also accepts `action: "clock"` with `installation` and the nonce for the bounded sweep of absolute expirations. It returns the common time evidence fields.

## Installation profile

Set `contract` to `ouf.analysis.batch.installation.v1`. Provide `installationId`, `issuer`, `audience`, `workload`, `thsClient`, `storageEpoch` (64 lowercase hex digits), and `store` (existing Gateway operations DB). Supply independent key environment names through `startKeyEnv`, `semanticReadKeyEnv`, and `semanticDiscoveryKeyEnv`. Each of `rights`, `mcpState` and `semantic` supplies `url`, `caFile`, `certFile`, `keyFile`. Semantic takes an origin. The `listen` object supplies `host`, `port`, `caFile`, `certFile`, `keyFile`, `mcpCertSha256` and `humanRelayCertSha256`.

Set `clockSkewMs`, `timeoutSeconds`, `sweepSeconds`, `dispatchCapacity`, `maxResultBytes` and `ratePerMinute`. The last maps the four operation names to budgets enforced across replicas. Allocate the batch and interactive budgets together against the installation's Semantic limits.

Replicas share the same local SQLite database and filesystem locking domain. The tables are additive. Fence all listeners before a snapshot restore or storage replacement. A stale snapshot can contain a pre-revocation record. Reopening the mandate path requires explicit reconciliation of tombstones and a governed storage-epoch migration. The liveness probe observes the listener. The readiness probe checks current store and sweep evidence. If the DB is unavailable, denials go to the service logger with the same redacted fields.
