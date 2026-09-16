# etcd snapshot/restore runbook

This runbook is subordinate to the Gateway PET v1.3 and does not replace cluster-vendor procedures.

1. Block new Gateway publication before snapshot restore or quorum repair.
2. Preserve the last-known-good APISIX data plane; do not delete active revision metadata merely because etcd is unavailable.
3. Restore only from a governed snapshot whose provenance, checksum and environment binding are known.
4. Restore the three-member etcd topology using the adopted operator/platform procedure.
5. Require quorum and healthy storage before allowing publication.
6. Read back the active publication revision and compare it to Git desired state.
7. Compare the complete route set and upstream set to desired state; partial, extra or wildcard state is a hard failure.
8. Reject any restored upstream outside the governed allowlist.
9. Re-run APISIX convergence checks before reopening publication.
10. Record snapshot identifier, checksum, restore timestamp, quorum evidence, APISIX convergence evidence and operator identity in the release evidence package.

## Hard stops

Do not reopen publication when quorum is absent, storage is slow, pending proposals exceed the governed backpressure threshold, the active revision differs from desired state, or route/upstream convergence is incomplete.
