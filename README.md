# OUF Urban API Gateway

Gateway 1A/1B/1C establishes the PET v1.3 configuration, controlled-publication and MCP capability-binding boundary for Apache APISIX 3.18.x. It validates versioned runtime projections, resolves their references fail-closed and deterministically compiles APISIX routes. Publication is serialized, hash-pinned and can become ACTIVE only after all verification gates pass; failures preserve the last-known-good revision. It contains no ETL, semantic mapping, object resolution or direct database access.

The first micro-pairwise fixture preserves the existing Onboarding contract:

`GET /internal/object-storage/v1/content?ref=object://...`

Only an authenticated internal service identity may use that route. The caller cannot supply an upstream URL, host or port.

Run `scripts/verify.sh`. Generated artifacts are evidence and are not committed.

Gateway 1B provides the publication state machine and a test control-plane adapter. A real APISIX/etcd adapter, infrastructure fault injection and production activation evidence are deliberately not claimed by this increment.

Gateway 1C adds the governed MCP dispatch adapter and exact MCP→Gateway→UDP contract fixture. Authenticated identity and authorization references must match the admitted envelope; backend destinations remain registry-owned and backend governance errors are returned without retry or reinterpretation.

Gateway 1D adds deterministic MCP attempt-recovery mediation. The owner service and outcome path are compiled from registry configuration; callers cannot supply a physical target. See `docs/GATEWAY_1D_TRACEABILITY.md`.
