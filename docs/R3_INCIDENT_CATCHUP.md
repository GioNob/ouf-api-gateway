# R3 — incident timeline and bounded catch-up

Baseline: Ingestion PET v1.3 §46, MCP PET v1.4 §33, Gateway operational-awareness contract. This increment covers persistent incidents and incident catch-up; it does not declare all R3 matrix gaps closed.

The Inspector client used for latency diagnosis is temporary test equipment. It is not a production Keycloak configuration or a prerequisite of this implementation.

Deployment requires coordinated review of all three branches. No production deployment or merge is performed by this change.

## Persistent owner and authenticated path

The existing SQLite incident store appends a transition in the same transaction as each lifecycle update. The collector initializes/backfills the transition table. The read-only Java GatewayIncidents endpoint queries it using a fixed watermark and time window, bounded pages and tenant/principal-bound cursors. It requires a body/path/capability-bound Gateway receipt and owner-local authorization on every page. An absent or unmigrated store fails unavailable rather than returning a complete empty result.

`tools.materialize_incidents` layers three closed incident execution bindings over the existing summary profile. These accept the delegated HUMAN identity only over the authenticated MCP workload route. Scope is operations.incident.read. Upstreams remain fixed, Gateway retries remain zero, arbitrary headers are stripped, and only the MCP owner receives the verified delegation proof. Java producers receive short-lived signed receipts using the existing per-owner key configuration. Deployment must select this materializer; existing summary-only profiles are not silently activated.

Gateway incidents refer to endpoints, not Ingestion source/run IDs: source/job-filtered Gateway pages contain no matches. Restricted projections mark partial and expose no raw logs. The Python owner contract mirrors this behavior; the HTTP Java endpoint is the deployable producer.

## Verification

Python tests cover SQLite restart, stable pages during updates, owner denial, cursor binding and bounded Lua dispatch. Java tests cover read-only SQLite pagination, redaction, forged-header rejection and real Lua receipt vectors. CI additionally runs the existing APISIX/delegation and summary regression gates. The dedicated incident stack gate must use the coordinated MCP and Ingestion commit refs.
