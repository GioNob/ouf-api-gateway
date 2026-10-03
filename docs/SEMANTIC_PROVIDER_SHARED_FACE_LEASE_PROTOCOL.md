# Shared faces and guard/lease coordination

## Contract and scope

OUF must support adoption by thousands of entities, colocated services on one
server/subnet and distributed services on distinct hosts/networks. Network
position is not identity, tenant authority or approval. This change supplies a
Linux enforcement backend and a backend-independent lease protocol core; neither
is a general platform requirement for Docker, bridge names or laboratory IPs.
Service identity, OIDC/purpose, TLS/revocation and tenant isolation remain
cumulative controls. Approved transport pairs do not grant application authority.

The current VPS remains RUNTIME_EMPTY under the original EMPTY_ONLY guard and
sealed cohort. These new modules are not installed, enabled or activated there.
There is no host installer or startup authorization in this change.

## Shared-face backend

`tools/materialize_semantic_shared_faces.py` accepts only an exact schema with
bounded explicit workload attachments and governed static infrastructure flows.
Each selected attachment names its workload and binding reference, root-netns
port name/ifindex, bridge, unicast MAC and exact IPv4. Each flow supplies purpose,
authority reference, exact source/destination/protocol/port and peer ingress
kind/index. Authority references are required input bindings, not proof that an
authority has approved them. No provider Internet flow or broad CIDR is inferred.

Bridge prerouting/input/forward/output select the protected port by numeric
ifindex. The per-port chain rejects a changed parent bridge, wrong source MAC,
forged ARP source or non-governed traffic. Incoming flows also check the approved
peer's ingress port for same-bridge traffic, so forging its IP and MAC from a
different port does not create a grant. inet input/output/forward adds scoped
host/routed enforcement for protected addresses; ROUTED and HOST peer kinds
have distinct ingress constraints. Other bridge ports are not dispatched to a
blanket deny chain. Renaming a selected port keeps its ifindex enforcement;
reparenting is denied. IPv6, VLAN and other ungoverned data frames on selected
ports are denied in this initial IPv4 backend. IPv6 on unrelated peers is retained.

A deployment verifier must prove namespace/ifindex/iflink/parent/MAC/IP and
workload generation before execution, and coordinate recreation/removal. Reused
ifindexes are not identity and stale rules must not authorize a new attachment.
The compiler does not discover interfaces or turn bindingRef into live proof.

**Bind and protect before process launch.** Never attach a Docker event listener
that races after container start and call it fail-closed. The selected runtime
must supply an ordering primitive that materializes/verifies network protection
before application execution (for example a governed runtime hook or CNI
integration). The current never-started Docker candidates do not establish this
ordering or live veth bindings. No install/start recipe is proposed until that
gate is implemented and tested. Do not mutate sealed manifests or recreate
production networks to make the profile fit.

The native fixture tests both same-subnet shared-bridge and routed-network
traffic, host-local access, permitted/denied ports, other-peer preservation,
IPv4/MAC and forged peer-IP+MAC port denial, selected IPv6 denial, unrelated IPv6
preservation and interface rename. Routed namespaces model network behavior;
they do not prove real multi-server, multi-tenant or thousands-of-entities SLOs.

## Lease protocol

`tools/semantic_provider_lease_coordination.py` supplies `Coordinator`,
`PrivateJournal` and `hold_common_lock`. The future installer provides a new
sealed owner configuration, explicit transaction/configuration/structure hashes,
an existing private coordination journal and the existing shared boot lock.
The protocol cannot adopt the current runtime-transition journal: its schema and
EMPTY_ONLY state are deliberately incompatible.

| State | Behavior |
| --- | --- |
| LEASE_READY | Refresh requires leaseAuthorized=true; structural guard permits only finite sets consistent with the fresh-cycle receipt. It does not grant Docker startup. |
| LEASE_UPDATING | Persisted before DNS/apply; guard and additional refresh deny. |
| QUIESCING | Persisted before revocation; refresh and structural pre-start deny until readback proves both families empty. |
| QUIESCED | Empty sets and unchanged owned structure required; structural pre-start check passes, startAuthorized remains false. No automatic lease reactivation. |
| BLOCKED | Failed refresh/configuration/publication; no refresh/start, ownership-checked revocation attempted and finite expiry remains fallback. |

Refresh holds the common flock across a fresh LeaseOwner DNS cycle, both-family
atomic apply/readback and receipt publication. Concurrent cooperating guard or
refresh receives a lock denial. Quiesce disables lease authority persistently,
then revokes and verifies empty sets before publishing QUIESCED. A failure/crash
cannot publish completion early. DNS/owner configuration and expected handle hash
are frozen at construction and rechecked; journal transaction/configuration,
state, schema and authority fields must match. startAuthorized is always false.

The guard verifies finite bounded TTL, equal family membership, addresses within
the last trusted cycle's receipt and source-family/private-exception bounds.
Expiry can reduce membership; it never expands it. Unknown/new addresses,
partial family readback, recreated handles or foreign structure deny. This core
never recreates tables or silently rebinds handles. A separately governed
installer must reconcile an empty, verified new structure and sealed owner
binding before reactivation. Never replay cached relative TTL or disk DNS
observations.

PrivateJournal reads existing root:root 0600 single-link files under safe root
ancestors, rejects symlinks/duplicates/unbounded bytes, compare-and-replaces via
an exclusive private temporary file, fsyncs file and parent, and preserves a
changed/foreign journal. The caller must hold the common lock around every
write. hold_common_lock validates/reuses the existing inode without creation.
External non-cooperating privileged writers remain outside the lock contract;
the guards reject observed drift, not claim a globally atomic host snapshot.

## Validation and remaining integration

Nine regressions cover input injection/ambiguity, source/authority fields,
incomplete/old journals, unreceipted members, foreign handles, failed
refresh/revoke, lock contention, owner/DNS/config drift, private journal
publication/metadata and lock inode. Two opt-in native tests run under
unshare --net --fork: real packets in peer/routed namespaces, plus real local
A+AAAA DNS, nft timeout sets, common flock, private fsynced journal, quiesce,
fresh reactivation, incomplete-phase denial and changed-handle refusal.
All DNS is a local fixture; no external provider request occurs.

Still required before target staging/install/start: approved infrastructure
bindings, runtime network-before-process mechanism and attachment generation
checks, sealed installer/recovery/rollback for this new profile, owner/guard
service lifecycle (including bounded lock contention), old EMPTY_ONLY migration,
source-specific coverage across all relevant faces, actual OIDC/purpose/TLS/
revocation admission, real IPv6 policy where needed, real distributed/tenant
acceptance and reboot. Preserve R-SMOKE/R-INSTALL and business evidence.
Do not enable the old lease service under EMPTY_ONLY.

PET basis: Gateway v1.5 T11/T11.3 GW-NET-01..05, Semantic v1.3 sections 9.2/10–11.
Transport controls do not transfer Semantic/THS adoption authority.

## Preexec installation/recovery protocol core (2026-10-03)

`tools/semantic_provider_preexec.py` adds a dependency-injected protocol core,
not a deployable OCI hook or a Docker runtime registration. Its driver must
provide root-private sealed configuration, bounded input/commands, the exact
prepared namespace/bundle/port bindings, a native backend and both existing
private journals. No namespace/container creation, service installation,
runtime registration, start or lease activation is performed by this core.

The common guard/lease lock covers binding checks, lease ownership/quiescence,
table readback and every journal publication. Only QUIESCED with unauthorized,
empty provider sets is admitted. A distinct inet/bridge table pair carries the
unique transaction comment; the expected footprint must be independently
compiled from the sealed policy and include both comments. The backend must
create both tables exclusively in one atomic transaction, reject partial pairs
and command/read errors, and remove only the verified owned pair atomically.
Never derive the expected footprint from a preexisting target table.

State progression is STAGED -> INSTALLING -> PROTECTED. INSTALLING is published
before the native transaction; the observed structure hash including handles
is persisted before PROTECTED. Apply cannot be replayed. A crash after native
creation but before hash publication requires explicit reconcile: both tables
must match the independently sealed, transaction-tagged footprint, all bindings
must still match and the lease cohort must remain quiescent. An existing hash
cannot be silently rebound to recreated tables. Changed structure, footprint,
binding, profile, authority, journal or contended lock denies the operation.

Rollback requires INSTALLING/PROTECTED/REMOVING, proven ownership if tables are
present, and a proven dead previously recorded process generation. Uncommitted
present tables require explicit reconcile before rollback. REMOVING is durable
before deletion; a crash after deletion can finish with ROLLED_BACK without
recreation. ROLLED_BACK is terminal. A backend must treat inability to prove a
generation dead as a denial, not infer death from an unreadable proc entry.

`before_process` is an interface intended for a synchronous createRuntime hook.
It requires explicit infrastructure and application-start authority, OCI
identity/status/PID, complete PROTECTED state and stable prepared live bindings.
It persists PID/start ticks/network namespace inode under the common lock,
rechecks rules and generation, and denies a replacement generation until an
explicit reconcile after the old one is proven dead. Profile start authority is
separate from the lease journal, which always retains startAuthorized=false.
The method itself cannot prove it was called before the application: only a
validated runtime hookup and negative process-execution tests can prove that.

Ten additional regressions exercise interruption boundaries, exclusive
ownership, readback failure, explicit reconcile, rollback, false start authority,
OCI identity, quiescence, binding/lock/profile/journal drift and live/replaced
generations. The opt-in native suite adds real nft table transactions and
handles, fsynced journals, flock, prepared veth/namespace bindings and a fixture
process generation. That process is already running: this test proves the
generation/lifecycle protocol, **not OCI before-process enforcement**. CI runs
19 regressions and three native cases; use the exact commit's CI result for
pass/fail evidence. All authority in these fixtures is synthetic.

Next required software increment: root-private source-sealed driver and
configuration/staging, independently compiled native footprint, real synchronous
OCI success/failure tests proving no application execution on denial, explicit
runtime integration and owned service migration/recovery. Docker registration
and the VPS's runtime compatibility remain unproven. Current VPS evidence stays
RUNTIME_EMPTY/EMPTY_ONLY with two never-started candidates; no new VPS command,
automatic start, replay or merge is authorized by this implementation.
