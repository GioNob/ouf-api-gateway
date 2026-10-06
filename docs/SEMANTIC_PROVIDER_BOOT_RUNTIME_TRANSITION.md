# Semantic provider boot/runtime custody transition

The existing deny-only boot guard cannot accept runtime timeout sets. The new
scripts coordinate its replacement with the two owned nft tables while preserving
the running Docker service, the stopped candidates and the original sealed cohorts.

## Target evidence and next operator action

On 2026-10-03 the custody inventory passed, then transition intent
plan/apply/verify passed at
`/etc/ouf/deploy-snapshots/semantic-provider-transition-intent-20261003-151036/prepared`.
This is a laboratory receipt binding, not a product default. Two candidates have
never started; startup is not authorized; no kernel lease exists. No rules, units
or containers changed. The intent records the three prior custody hashes,
runtime/lease input seals, owned tables and the normalized shared structure under
the existing boot lock.

Private runtime staging plan/apply/verify passed at
`/etc/ouf/deploy-snapshots/semantic-runtime-transition-stage-20261003-160211/prepared`.
The subsequent runtime plan and apply/verify passed; the journal is `RUNTIME_EMPTY`.
The owned guard/drop-in and both runtime tables are installed, provider sets are
empty, Docker was not restarted and startup remains unauthorized. The original
deny-only receipts remain historical evidence. Do not replay these commands.
The next target action is **read-only runtime readiness inventory**, after its CI.
This verifies the completed journal, current native structure and separate lease
hash, installed/loaded guard, unchanged Docker PID and never-started candidates
under the original boot lock. It reports unproven authority/packet/admission and
active-lease lifecycle gates without promoting inventory PASS to startup readiness.
It performs no DNS/IAM request or rule/unit/container mutation. All roots, source
pins/hashes, tool paths, endpoint reference and lease ceiling are explicit inputs.
Do not replay stopped creation or normalize networks. Do not call old cold
verifiers that require empty networks. All original and failed artifacts remain.

## Implemented scripts

- `prepare_semantic_provider_transition_intent.py` creates the completed private
  preflight evidence; its apply writes evidence files only.
- `stage_semantic_runtime_transition.py` revalidates that exact original intent,
  derives planned gateway→adapter and selected UDP/TCP DNS flows from the sealed
  manifest/runtime binding, and keeps provider addresses empty. It reuses the
  frozen lease kernel compiler. A child under explicit `unshare --net --fork`
  compiles the rules with real nft and reads back an independent template.
  The child refuses the parent's network namespace; no host table is touched.
  Plan creates no prepared snapshot; apply creates private configuration/template,
  guard unit/drop-in and receipt files; verify rechecks. No installed unit, Docker
  state, IAM/DNS/provider call or shared runtime rule changes.
- `restore_semantic_runtime_boot_guard.py` checks the sealed configuration and
  compiler, common boot lock and private transition journal. Incomplete or
  rolled-back phases refuse startup. Exact present empty runtime structure is
  read-only; both tables absent may be reconstructed atomically from the verified
  compiler; partial/foreign structure refuses. This initial profile is
  **empty-only**: active lease elements block instead of being silently flushed.
- `transition_semantic_runtime_guard.py` supplies plan/apply/verify, explicit
  reconcile and owned rollback. Runtime apply is implemented and native-tested,
  and target apply/verify have passed in the initial empty-only scope.

Staging is not complete infrastructure authority: no WORKLOAD_GATEWAY, IDENTITY
or TELEMETRY permission is invented. The shared backend/control networks are
excluded from dedicated guards. Planned IPs remain unproven as live endpoints.
Source-specific protection on shared faces, IAM reachability/authority and
packet/spoofing/bypass/IPv6 acceptance remain startup gates. The receipt therefore
sets infrastructureAuthorityComplete=false, liveAddressAllocationProven=false,
leaseLifecycleActivationReady=false and startAuthorized=false.

## Journalled runtime apply and recovery

The installer takes the existing boot lock, rechecks the sealed stage/intent,
candidate IDs/image/labels/never-started/restart=no, dedicated network ownership,
runtime/lease sources, current shared structure and original Docker PID/command.
It only replaces byte-identical owned old/new unit files and the two owned tables.
No Docker/candidate restart or provider request exists in this operation.

| Journal phase | Required behavior |
| --- | --- |
| PREPARING | Fsynced intent before mutation; new guard refuses startup. |
| GATE_FILES_WRITTEN | Dedicated guard/drop-in atomically published; originals retained. |
| GATE_LOADED | systemd graph and exact pre-start verified; Docker PID unchanged. |
| RULES_APPLIED | One nft transaction replaces both owned tables with empty provider sets. |
| RUNTIME_EMPTY | Native compiled layout, empty sets, shared structure, inputs/PID/pre-start rechecked; lease structure hash recorded; completion persisted last. |
| ROLLBACK_BLOCKED | Incomplete gate remains blocked while rollback reconciles only owned artifacts. |
| ROLLED_BACK | Original logical deny profile and loaded unit commands restored; no automatic legacy custody adoption. |

After interruption, retain the stage/journal and use explicit reconcile or
rollback after diagnosis; **never replay apply**. Unknown journal phases, foreign
files/tables, running/foreign candidates, active leases and changed shared
structure block. Reconcile rechecks the independently compiled template before
recording a new lease structure binding. It does not infer ownership from an
arbitrary observed hash. A failed nft transaction must retain both old tables.

Rollback atomically restores the original deny pair and then original installed
unit commands, preserving the running dependent PID and shared structure. Table
recreation changes nft handles: the old logical boot footprint may match while
the old manifest/custody hash does not. The journal explicitly marks
legacyCustodyReconciliationRequired; it does not fabricate an original custody
PASS. Preserve the rollback evidence for a separate new custody reconciliation.

## Hashes, locks and lifecycle limits

The runtime boot footprint removes metadata/handles and provider set elements.
The frozen lease backend's structure hash removes elements but keeps metadata/
handles. The hashes are distinct. Restoration reports lease reconciliation when
handles differ; no automatic lease owner installation/activation or cached TTL
replay occurs. A later active-lease/Docker lifecycle requires a separately
coordinated profile. This empty-only guard intentionally blocks active elements.

The shared-structure comparison preserves shared set membership, while ignoring
counter values, expiry metrics and handles. The boot lock coordinates cooperating
boot/install operations only; external Docker/firewall/network writers can race.
It is not a globally atomic host snapshot. RuntimeDirectoryPreserve retains the
common lock inode across the new guard lifecycle.

## Verification

The root CI suite contains eight private-file/lock/profile regressions and three
real native systemd/nft/Docker fixture cases. It tests isolated template staging,
plan/apply/verify, missing-table reconstruction before a separate dependent
start, handle reconciliation, foreign/partial denial, interrupted reload,
post-rule crash recovery, owned rollback, real atomic nft parser failure,
foreign-file preservation and unchanged running dependent PID. The synthetic
Docker candidates are created, never started and removed with owned cleanup.
Native tests must execute with no owner/native skips; general unprivileged
discovery skips the root/native fixtures. No provider/DNS call or production
Docker restart/reboot occurs.

These tests are not target runtime acceptance. Real VPS reboot, live namespace/
packet bindings, fresh A+AAAA bounded DNS leases, OIDC/purpose receipt/TLS/
hostname/revocation, migration-aware Semantic rollout, Discovery/THS adoption,
chatbot-assisted mapping/HUMAN ACTIVE, immediate file ingestion or API
scheduler-before-ingestion and UDP identity remain separate open gates.

## Readiness and active-lease design boundary

`inventory_semantic_runtime_readiness.py` loads the original private installer
only after checking an explicit SHA256, root ownership, mode 0600, single link,
size bound and no symlink. It reuses that sealed installer's independent custody
checks, reads twice under the existing lock and rejects incomplete journals,
source/artifact drift, active elements, changed handles or loaded-unit mismatch.
No original cohort is edited. Only hashes/counts/purpose labels and explicit
unproven gates are printed; raw configs/env/mounts/commands/endpoints are omitted.
Stable reads do not establish a globally atomic host snapshot.

Do not run the legacy deny-only custody inventory against the transitioned
runtime, and do not rerun the old intent verifier that expects original tables.
The new readiness inventory validates current runtime custody instead.

The active lease owner is already native-tested in isolation, but cannot be
activated under the installed EMPTY_ONLY guard. Its fresh-DNS populate/revoke
cycle and table-handle binding require a later coordinated guard/owner lifecycle.
A future active profile must gate incomplete transitions, preserve foreign tables,
reconcile handle changes, avoid cached TTL replay, serialize recreation against
owner writes and deny readiness/start on unproven authority/admission. It must
also define safe Docker pre-start versus active lease behavior and stop/restart
revocation. Selecting that profile is engineering work, not implicit activation.

The native runtime fixture additionally runs the readiness inventory after a real
transition and verifies both table bytes, journal and dependent PID unchanged.
Five additional regressions cover journal/handle/active-element drift, read drift,
redacted errors and source hash/mode/link checks. Target network namespaces remain
unproven because the two provider candidates have never started; planned Docker
addresses and inventory PASS cannot substitute for packet/live acceptance.
