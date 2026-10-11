# Gateway incident priority and catch-up — resilience v3

[Platform policy](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md), MCP PET1.4 §33.

The SQLite reference owner adapter now selects unresolved/severity/action/time/identity order before LIMIT. Summary counts cover the full requested time window, not merely returned items, and expose truncation. The private owner API honors timezone-aware since for both incidents and summary, filtering last_seen_at so a recovery update of an older incident remains visible after reconnect; invalid/naive timestamps are rejected. Incident lists read one bounded lookahead row and expose truncated. No cursor/checkpoint/alert or new authorization is implemented.

This qualifies the existing reference adapter only, not a production Gateway datastore or cross-tenant deployment. Window summary describes that window, not current full-platform health. Owner authority and existing access controls remain; production tenant/visibility/hosting closure, source-scoped queries, cursor and complete history retention remain open.

Regression tests cover an old critical incident ahead of twenty recent resolved incidents, full-window counts with limit1, catch-up of old recovery, timestamp offsets, malformed timestamps and stable action/identity ordering.
