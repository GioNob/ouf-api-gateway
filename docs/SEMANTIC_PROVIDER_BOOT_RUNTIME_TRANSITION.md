# Semantic provider boot/runtime custody transition

This procedure continues an existing stopped deployment. It neither recreates
networks nor replays sources. All installation roots, executables, identities,
interfaces, destinations and timing bounds are explicit inputs or references to
sealed, hash-bound installation evidence. Main, PR software and target evidence
remain separate.

## Current boundary

Target custody inventory passed on 2026-10-03: two candidates have never started;
the installed boot profile is DENY_ONLY; no kernel lease exists; startup is not
authorized. The returned manifest, creation-journal and boot-install-journal
hashes must be explicit preconditions, not reconstructed from branch heads.
The inventory was read-only and did not take a lock; it is not an atomic host
snapshot or a release acceptance.

The installed restore helper rejects sets and removes nft handles/metadata only
when computing its footprint. It must not be pointed at a runtime profile.
The frozen lease backend separately removes set elements from its structure
hash but retains handles/metadata. These hashes are not interchangeable.

## Implemented next step: private transition intent

`scripts/prepare_semantic_provider_transition_intent.py` provides plan, apply and
verify. Here **apply means write new private evidence files only**. There is no
nft write, systemd mutation/reload, container change, IAM/DNS/provider call or
lease activation. The existing custody helper is its only executable dependency,
loaded only after root-private ownership and caller-pinned SHA256 validation.

The helper checks the three operator-returned custody hashes; revalidates the
installed boot files, loaded Docker pre-start and PID via custody; acquires the
existing boot lock inode with nonblocking flock; and takes two bounded readbacks
under that lock. It seals runtime receipt/binding/plan hashes, the nine-file
frozen lease cohort and its boot linkage, both owned nft tables and the normalized
shared structure. It rejects changed evidence, lock contention/replacement,
foreign/started candidates, existing/partial intent roots, mismatched saved
evidence and source drift. Boot lock path must match the runtime directory in
the verified boot profile. No new lock file is created.

The snapshot contains root0600 `transition-intent.json`, `owned-before.json` and
`shared-before.json` in an exclusive root0700 directory. Partial snapshots remain
for reconciliation; apply cannot overwrite or resume them blindly. The boot lock
coordinates cooperating boot operations only: Docker/network/firewall writers
outside that lock may race, so globalAtomicSnapshotProven is explicitly false.
An eventual installer must repeat all preconditions at point of mutation.

Eight tests use real private files and flock with simulated host readbacks.
They cover custody hashes, runtime/lease drift, shared/owned changes, saved
tampering/collisions, lock contention/symlinks/absence, interrupted writes,
untrusted imports and output redaction. They do not prove target nft/systemd or
runtime packets. A dedicated root CI job runs these tests without owner skips.

## Required activation protocol — design, not implemented

1. Compile a new immutable profile with the existing kernel compiler and
   `empty_provider_sets=True`. Declare exact gateway→adapter, selected DNS and
   governed identity/infrastructure flows. Use only dedicated guarded interfaces;
   preserve shared backend/control networks. Provider addresses start empty;
   historical DNS evidence is never a seed. Planned stopped addresses are not
   proof of live allocation or packet source identity.
2. Implement a new sealed runtime boot guard and transition gate using the same
   existing boot lock. The loaded Docker ExecStartPre must refuse startup while
   a transition is incomplete; an installer-held lock alone is insufficient
   after a crash. Gate installation must be journalled and loaded/verified before
   rule replacement. Never edit the old sealed stage or lease source cohort.
3. Under that lock, recheck candidate ownership/never-started, private input
   hashes, Docker PID/command, installed/loaded files and both owned tables.
   Record an fsynced intent before mutation. Replace only the two owned tables
   atomically in one nft transaction, with empty timeout sets. At every failure,
   prevent startup and keep default-deny. Shared structure must remain equal.
4. Compare native readback with the independently verified compiled rule
   structure; do not adopt an arbitrary observed hash as trusted ownership.
   Publish the sealed runtime boot files, verify systemd graph/pre-start and
   unchanged Docker PID/command, then mark the journal complete last. No Docker
   restart, reboot, candidate start or provider request belongs to this apply.
5. Runtime restore must distinguish exact present structure, both tables absent,
   partial tables and foreign structure. Only the verified missing pair may be
   restored. Sets are empty on restore/start validation; active elements must be
   governed separately and revoked without accepting unrelated structure. After
   table recreation, the lease backend's handle-bound structure hash requires an
   explicit trusted reconciliation; no silent adoption or cached TTL replay.
6. Reconcile crashes by journal phase and exact owned files/rules. Rollback must
   restore the old deny-only pair/profile and loaded pre-start while holding the
   common lock, without removing foreign files, altering shared services or
   restarting Docker. Retain original and failed artifacts. An unknown partial
   state must remain blocked, not be solved by blind apply or table deletion.

Before any target activation, test these phases natively: failed file publication,
failed daemon reload, failed nft transaction/readback, interrupted phases,
lock contention, partial/foreign tables, preservation of shared structure and
running dependent PID, and restoration before an isolated dependent start.
Real VPS reboot remains a separate gate with a prepared maintenance plan.

After coordinated apply, separate gates remain for live namespace/source binding,
packets/spoofing/direct bypass/IPv6, fresh A+AAAA DNS/TTL leases, OIDC admission,
purpose receipt/TLS/hostname/revocation, migration-aware Semantic PR30 rollout,
Discovery authority and THS adoption, chatbot-assisted mapping and HUMAN ACTIVE,
immediate file ingestion or API scheduler-before-ingestion, and UDP identity.
