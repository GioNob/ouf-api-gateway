# Gateway mandate for the first round of BATCH_V1

Run the opt-in Gateway listener with `python -m tools.analysis_batch_service --profile <installation-profile>`. Materialize the authenticated MCP ingress with `--analysis-start-key-env <name>` and mount that key on APISIX and the listener. The interactive delegation remains valid for at most 60 seconds.

The listener validates the peer certificate chain and pins distinct MCP and HUMAN relay leaf certificates per installation. Authorization authenticates the Gateway's separate outbound mTLS identity and owns the mandate registry, current rights, admission audit, revocation and deadline. Gateway replicas can use distinct local filesystems.

## Gateway ingress

Use JSON POST under `/internal/analysis-batch/v1/`. The mandate view contains `mandateRef`, `generation`, `version`, `state`, `analysisId` and `expiresAtMs`. UUIDs and hashes use lowercase. The analysis ID and policy epoch use MCP's batch encodings.

| Command | Peer | Exact request fields |
|---|---|---|
| `prepare` | MCP | `startProof` from the Gateway's `X-OUF-Analysis-Batch-Start` on the same authenticated HUMAN `source.analysis.plan(BATCH_V1)` |
| `issue` | MCP | `mandateRef` (the pending start reference), `generation`, `commandKey`, `analysisId`, `policyEpoch`, `startBinding`, and optional `startProof` |
| `dispatch` | MCP | `mandateRef`, `generation`, `analysisId`, `mandateBinding`, `operation`, `arguments`, `attemptId`, `correlationId` |
| `expire` | MCP | `mandateRef`, `generation`, `expectedVersion`, `mandateBinding` |
| `read` | MCP | `mandateRef`, `generation`, `mandateBinding` |
| `revoke` | HUMAN relay or MCP | `mandateRef`, `generation`, `expectedVersion` and a HUMAN bearer in `Authorization` |

APISIX signs the plan after IAM verification, including the verified OIDC `auth_time` claim. `prepare` derives a stable UUIDv4-shaped start reference from installation, issuer, tenant, subject and command key, and signs the original plan binding as `startBinding`. The pending view uses version 0 and shows the start proof deadline. MCP persists the pending reference, signed binding and original policy epoch with the analysis. After its durable commit, MCP calls `issue` in the same HUMAN plan using the original, unexpired start proof. Gateway verifies fresh MCP work evidence and attests to Authorization with a validity of at most 30 seconds. Start proofs and bearer tokens stay request-local.

MCP repeats the identical issue fields with the same key to reconcile an ambiguous response. It can omit `startProof` for replay, including after the original evidence expires. Authorization can return an already committed state and requires fresh proof to create a mandate. A successful active issue returns Authorization's reference, distinct from the pending start reference, and a signed `mandateBinding`. MCP persists both for work and reconciliation. The signed bindings carry context across replicas. Every dispatch still needs a fresh Authorization admission. This ingress supports the first generation.

To end the first round, close or cancel, MCP durably fences work, exposes its phase and calls `expire`. Gateway also sends expiry when dispatch observes a terminal phase. Authorization materializes absolute expiry during its commands. `read` retrieves the primary view for reconciliation. Gateway forwards the bearer only on `revoke`. After an ambiguous revocation it reads the owner for local reconciliation and reports uncertainty to the caller. A valid MCP reconciliation request can retrieve the current state through `read`.

## Work proof, admission and Semantic

Gateway exchanges nonce-bound JSON with the configured MCP state and receipt-context endpoints over mTLS with hostname verification. The response must bind `requestHash` to SHA-256 of the exact request and supply `clockSynchronized: true`, `observedAtMs`, and `validUntilMs`. Evidence is valid for at most 30 seconds. Gateway checks round-trip uncertainty and wall-clock drift, including after the admission response.

The context contains `contract` (`ouf.analysis.batch.mandate.v1`), `action`, `installation`, `version`, `issuer`, `tenant`, `subject`, `client`, `workload`, `analysisId`, `generation`, `startRef` and the original `mode`, `assetId`, `profileId`, `schemaHash`, `commandKey` and `scope` array. Dispatch adds `operation`, `argumentsHash`, `attemptId` and `requestId` for discovery status and candidates. The arguments hash uses the 67a canonical JSON encoding with sorted keys, ASCII escapes and compact separators.

- **MCP state** returns `bound`, `analysisId`, `policyEpoch`, and `phase` (`FIRST_ROUND`, `FIRST_ROUND_COMPLETE`, `CLOSED`, `CANCELLED`). It attests the durable analysis, verified profile, start command and fenced attempt with the exact arguments. Discovery also supplies the stable SHA-256 `workRef` and the durable `discoveryArgumentsHash` for the creation arguments. MCP persists the `X-OUF-Analysis-Discovery-Binding` returned with a successful Semantic creation response and supplies it as `discoveryBinding` in status/candidates evidence. Gateway verifies that the signature binds the Semantic request UUID to the installation, analysis, mandate, generation, work reference and create digest. The same human's different analyses receive separate Semantic idempotency keys, even if the original keys match. A retry derives the same Semantic key for the same work and relies on Semantic's atomic deduplication.
- **Receipt context** supplies the fresh `active`, `allowed`, `policyEpoch`, `decisionRef`, `acr`, `scope` (space-separated) and `roles` (array) fields for the existing Semantic envelope and receipt. Gateway includes the issued policy epoch in this request. This remains a separate call because the Authorization mandate view carries no receipt claims. The receipt-context endpoint also accepts `action: "clock"` for readiness.
- **Authorization** receives one mTLS POST to `/api/internal/v1/authorization/analysis-mandates/admit` immediately before each Semantic dispatch that passes work and receipt validation. This includes retries using the same attempt ID and both discovery reads. The request includes the signed mandate reference and generation, expected version, analysis, policy epoch, pinned MCP workload, operation, canonical input digest and attempt/correlation UUIDs. Discovery reads include the bound request UUID. Only a matching committed 200 permits dispatch. A call admitted before revocation commits can finish. Gateway preserves bounded `Retry-After` from recognized transient errors. MCP owns the durable retry and reconciliation budget.

## Installation profile

Set `contract` to `ouf.analysis.batch.installation.v2` and provide `installationId`, `issuer`, `audience` and `workload`. Configure independent signing keys using `startKeyEnv`, `bindingKeyEnv`, `semanticReadKeyEnv` and `semanticDiscoveryKeyEnv`. Listeners in the same installation use the same binding key while issued work remains eligible for dispatch or reconciliation. This key also derives Semantic idempotency keys for discovery. Fence active work before changing it.

Each of `authorization`, `rights`, `mcpState` and `semantic` provides `url`, `caFile`, `certFile` and `keyFile`. Authorization and Semantic take HTTPS origins. Configure Authorization with the installation's trusted CA and Gateway leaf pin for the client certificates used by its replicas. Supply `host`, `port`, `caFile`, `certFile`, `keyFile`, `mcpCertSha256` and `humanRelayCertSha256` under `listen`.

Set `clockSkewMs`, `timeoutSeconds`, `readinessSeconds`, `dispatchCapacity` and `maxResultBytes`. The per-listener concurrency limit protects ingress and reserves capacity for control commands. The profile leaves installation-wide rate policy to the owner. The optional `store` points to a local Gateway operations DB for redacted audit. Legacy SQLite mandates, bindings and rate counters have no effect on admission. Liveness observes the listener. Readiness checks the Authorization TLS connection and synchronized clock evidence. Each command still fails closed when Authorization cannot complete its registry decision.
