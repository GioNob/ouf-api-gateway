# Gateway 1H-B/C — etcd resilience and disaster recovery

Normative baseline: Urban API Gateway PET v1.3, especially T33.9, T33.10, GW-ETCD-01..06 and GW-A17..A20.

## CI evidence

- publication fails closed when etcd quorum is unavailable;
- slow storage blocks new publication;
- pending proposals above the governed threshold require backpressure;
- restore validation requires exact active revision convergence;
- restore validation rejects partial/extra routes and upstreams;
- restore validation rejects wildcard and non-allowlisted upstream state;
- last-known-good data-plane continuity is not simulated by this gate and remains deployment evidence.

## Evidence boundaries

The Python gate is control-plane safety logic and CI evidence only. It is **not** evidence that a real etcd cluster survives member loss, partition, slow disk, snapshot restore or APISIX reconvergence.

The following remain `EVIDENCE PENDING` until executed against the adopted deployed APISIX/etcd environment:

- GW-A17 slow-storage fault injection and alert/backpressure timing;
- GW-A18 mass-change batching/coalescing under real etcd write load;
- GW-A19 data-plane last-known-good continuity during etcd outage;
- GW-A20 member loss/restart/quorum/restore;
- measured WAL fsync/backend commit/pending proposal/leader-change signals;
- snapshot creation, restore rehearsal and post-restore desired-state convergence.

No PET deviation is introduced.
