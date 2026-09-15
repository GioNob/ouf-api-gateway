# OUF Urban API Gateway

Gateway 1A establishes the PET v1.3 configuration boundary for Apache APISIX 3.18.x. It validates versioned runtime projections, resolves their references fail-closed and deterministically compiles APISIX routes. It contains no ETL, semantic mapping, object resolution or direct database access.

The first micro-pairwise fixture preserves the existing Onboarding contract:

`GET /internal/object-storage/v1/content?ref=object://...`

Only an authenticated internal service identity may use that route. The caller cannot supply an upstream URL, host or port.

Run `scripts/verify.sh`. Generated artifacts are evidence and are not committed.

