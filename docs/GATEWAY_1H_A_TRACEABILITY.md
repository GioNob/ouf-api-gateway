# Gateway 1H-A — Kubernetes HA topology

Normative baseline: Urban API Gateway PET v1.3 T33.9 and T33.16 deployment/HA requirements.

| Obligation | Evidence | Status |
|---|---|---|
| northbound HA | 3 replicas + HPA 3..10 + PDB minAvailable 2 | CI CANDIDATE |
| southbound HA | 2 replicas + PDB minAvailable 1 | CI CANDIDATE |
| control-plane HA | 2 replicas | CI CANDIDATE |
| etcd quorum topology | 3-member StatefulSet | CI CANDIDATE |
| topology spread | DoNotSchedule host-level spread for northbound/southbound/etcd | CI CANDIDATE |
| graceful drain baseline | 60s termination grace and preStop on APISIX data planes | CI CANDIDATE |
| probes/resources/non-root | readiness/liveness, requests/limits, runAsNonRoot, seccomp RuntimeDefault | CI CANDIDATE |
| deployed rollout/drain evidence | real Kubernetes cluster | EVIDENCE PENDING |
| HPA behavior under real load | capacity test environment | EVIDENCE PENDING |
| etcd quorum/member-loss/restore | Gateway 1H-B/C fault environment | EVIDENCE PENDING |

This increment defines and tests the HA deployment contract. It does not claim Kubernetes scheduler, CNI, APISIX readiness endpoints, HPA dynamics or etcd failure behavior as deployment-verified until exercised in the adopted runtime environment.
