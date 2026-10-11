# Durable finite alert outbox — owner reference implementation

Mandatory [resilience policy v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md). Status: reference implementation and local tests; native qualification pending. No email is sent by construction: there is no transport client, address, credential or implicit recipient configured. This is Gateway-owned control-plane notification state, not a central platform incident authority.

## Deduplication and durable reconciliation

The outbox reconciles the existing immutable owner transition ledger in short transactions, at most64 owner groups per call, prioritizing current unresolved critical incidents. Owner transitions and their queue receipts are committed atomically by the reconciler; capacity failure leaves receipts uncommitted and owner evidence pending. The original owner incident write remains independent. Equivalent transitions retain one delivery per owner incident/destination/lifecycle episode/notification phase.5,000 reports of one unavailable dependency produce one problem delivery; affected jobs remain a separate owner concern. Critical escalation and proved owner recovery create their own distinct, deduplicated delivery phases. An actual RESOLVED→OPEN owner crossing permits a new episode; repeated RESOLVED metadata does not.

A queued intent freezes its payload and delivery key. A changed destination intent cannot reuse the same destination reference. No metadata update, new job ID, restart or unchanged configuration creates a fresh automatic budget for that delivery. Owner/current-issue reconciliation means a newly configured channel sends actionable current state, not thousands of expired historical messages. Historical issues remain available through owner Operational Awareness.

## Authority and privacy

The host injects a fresh owner-local authorization port for CONFIGURE, ENQUEUE, DISPATCH, RECONCILE and RENEW_EXHAUSTED_BUDGET. Decisions bind exact server-resolved resource, Gateway platform/restricted scope, principal, tenant, actor and current policy reference; dispatch requires both collection and delivery-resource decisions before a claim. Destination creation and budget renewal require HUMAN. Development delegation is not this runtime grant.

Destinations contain only governed recipient/transport/secret references, never an email address or credential copied from a chat. Same-reference configuration is idempotent; changed intent is rejected. The transport must match the configured reference. Alert payload≤4KiB includes safe owner incident reference/severity/phase/code/impact, requires current authorization for details, and excludes recipient/transport secret references. Budget and configuration history retain actor/tenant/decision/policy provenance. These internal port operations are not yet public capabilities: actual host SDK wiring, reviewed capability identities and Gateway routes remain OPEN.

## Finite delivery and uncertainty

Profile `ouf.alert-delivery.finite.v1`:5/15/60/300/900seconds with±20%jitter, capped repeated900second delay,128attempts and24hours including attempt duration. First limit wins. Respect a proved Retry-After within the remaining lifetime. Each transport call has a5second single-attempt contract; no transport-owned retry multiplication, blocking sleep or RPC under a DB transaction. Next due time, attempts, deadline, frozen key and version persist across restart.

Only `TRANSIENT_NOT_ACCEPTED` from a qualified owner transport can schedule another attempt. Acceptance requires an authoritative receipt. Permanent failures PAUSE. Timeout/exception/unknown result or a lost worker lease becomes UNKNOWN; no assumption that SMTP/provider timeout means not sent. Reconciliation is a separate bounded, authoritative read outside DB locks (at most8 queries per delivery); unsupported/ambiguous evidence leaves UNKNOWN. Provider-proved not accepted permits safe resumption within the same remaining budget. Provider-proved accepted never resends.

A HUMAN may grant a NEW128attempt/24hour budget after EXHAUSTED using expected-version CAS, current resource authority and a reason. Old sessions and cumulative attempts remain; the same frozen delivery key/intent persists. Only one active session is referenced. UNKNOWN must be authoritatively reconciled first; a new budget cannot bypass ambiguity, revocation, changed configuration or capacity. Concurrent/stale renewals fail.

Provider acceptance is neither human reading nor acknowledgement, incident resolution, execution recovery or checkpoint advancement. No automatic recursive alert is generated for a failed alert. A lost/stale dispatcher outcome is fenced and cannot overwrite a newer decision.

## Capacity, testing and pending integration

At most32destinations,4,096retained deliveries,1,024nonterminal deliveries,128nonterminal deliveries/destination,200,000transition receipts,16in-flight globally and2in-flight/destination. Capacity blocks new notification admission while preserving owner incident writes and pending history; it never silently drops a quarantine/job. Retention pruning of terminal notification/history remains OPEN, so reaching retained capacity is explicit backpressure rather than permission to delete audit history.

20 focused reference groups pass locally, including5,000 equivalent reports, restart,24hour/128attempt bounds, Retry-After, stable keys, HUMAN renewal/history/CAS, revocation/tenant/resource denial, critical escalation/recovery, capacity rollback, ambiguous outcomes/reconciliation,8-query control limit, malformed receipt/outcome and late worker fencing. Native full Gateway/Authorization/APISIX must pass before merge.

Actual SMTP/provider adapter and its finite timeout/idempotency/reconciliation proof, secret custody/recipient resolution, scheduler/quotas, actual owner-local policy evaluator, HA persistence/retention and independent monitoring remain OPEN. The primitive does not activate an email channel or create runtime HUMAN authority. No production deploy, VPS action or R9/R10 replay is included.
