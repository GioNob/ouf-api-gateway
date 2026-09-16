# Gateway 1H-D — Runtime Configuration Catalog closure

Normative baseline: Urban API Gateway PET v1.3 T33.6.

This increment closes the catalog gap identified by the PET consistency audit. The runtime catalog now covers the operational properties introduced through 1H-A/B/C, including HA replicas/HPA/PDB, graceful drain, etcd quorum/backpressure and restore safety gates.

Every governed entry exposes type, unit, default, minimum, maximum, runtime scope, environment scope, secret classification and reload/restart behavior. CI fails if required metadata or currently governed operational keys are missing.

This is configuration-governance evidence. It does not convert scheduler/HPA/etcd/restore behavior from `EVIDENCE PENDING` to deployment-verified.

No PET deviation is introduced.
