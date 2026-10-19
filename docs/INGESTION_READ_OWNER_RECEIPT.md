# Ingestion READ owner receipt

The two compiled status/history routes retain their capability IDs, paths, methods, approved upstream, OIDC, signed MCP mediation, scope ingestion.operations.read and request limits. They now replace generic identity headers with X-OUF-Ingestion-Read-Receipt, a distinct HMAC-SHA256 receipt in domain ouf-ingestion-read-owner-v1. It binds the exact downstream JSON bytes, POST/path/capability, verified HUMAN identity and roles/scopes, issuer/audience/workload, correlation/attempt/idempotency and decision reference, with at most30seconds and no extension beyond the parent delegation.

The owner key reference is explicit, must differ from the MCP delegation key reference, and Lua also rejects equal key values. No key is emitted into route artifacts or delivered to MCP. Missing/invalid owner key denies the request; no generic-header fallback. Other operational producers remain unchanged.

Installation requires separately reviewed owner receipt key-file, approved issuer/audience/workload and feature enablement in Ingestion, plus two Gateway function replacements referencing the corresponding Gateway secret environment. This repository change issues no runtime authority, source activation or HUMAN approval. Use a new governed package; do not replay the completed route/owner/projection actions. Distributed installations must place both secret references through approved configuration without assuming shared filesystems.

Basis: GatewayPET1.5 T29.7 and AuthorizationPET1.5 section4.3; the owner always reevaluates policy. Test vectors use a public fixture key and fixed clock and are never deployment credentials.
