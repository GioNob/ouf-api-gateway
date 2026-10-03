# Atomic provider address-set refresh

`tools/materialize_southbound_lease_refresh.py` compiles one nft batch for the
selected owned inet/bridge provider sets. It does not execute nft, inspect an
installed table, authenticate resolution evidence, read DNS snapshots, or run a
refresh worker. All network/table/source/endpoint/port/private exception bindings
remain explicit through the existing validated kernel configuration.

Both families' provider sets are flushed and then replaced inside a **single**
native transaction. No chain/rule/static infrastructure flow or shared table is
rewritten; no whole-ruleset flush or broad established-connection accept is added.
The existing per-packet checks on timed sets remain active in both directions,
including established TCP. New valid resolutions replace the whole destination
set, so removed addresses lose admission immediately on successful commit.

Input resolution must match each configured endpoint/ref/evidence binding and
family/private address policy, have finite fresh monotonic timestamps and explicit
historicalEvidenceOnly=false. The future trusted worker must produce those values
from a fresh governed query; dictionary fields alone are **not provenance proof**.
Historical private DNS snapshots cannot authorize this compiler. Missing/failed,
expired, historical or invalid resolution produces a deny-only batch that empties
all provider sets, including otherwise valid providers, without partial admission.
An invalid ownership/configuration cannot safely name a table to revoke, so it is
rejected; the future worker must retain finite leases and let them expire, never
reinstall cached admission.

Remaining monotonic lifetime is rounded down and capped by the configured lease
limit. An explicit bounded apply budget is deducted before emitting each kernel
timeout. mustApplyByMonotonic is part of the result. A worker must compile immediately
before execution, enforce that deadline, atomically apply and read back both tables,
and revoke if execution/readback misses its budget. It must not retry old compiled
relative timeouts, reuse wall-clock snapshots, refresh after process/reboot failure,
or treat one family's readback as full success. These worker/lifecycle/ownership
guards are still installation gates; this pure compiler does not implement them.

Five pure tests cover exact scoped batch vocabulary, both-family replacement,
missing/stale/historical/future/invalid resolution revocation, no partial refresh,
address/private-exception expansion and finite clocks/remaining-budget bounds.
Existing mandatory actual netns and Docker/native bridge packet tests now also
refresh both sets, inject a last-statement failure to prove whole-batch rollback,
and empty sets on missing resolution to prove immediate denial. Existing expiry
of new and established sockets, unregistered-workload denial, shared rule structure
preservation and cleanup proofs remain required. Only controlled fixture peers
are used. No prior operator manual fixture needs rerunning for this increment.

No real deployment network/table is changed or acceptance claimed. DNS namespace/
forwarding/authenticatable policy, governed registration, fresh query→monotonic
worker→kernel readback, persistence/reboot/offload/IPv6, production workload bypass,
dedicated runtime mounts/identity/OIDC and provider exchange remain open.
