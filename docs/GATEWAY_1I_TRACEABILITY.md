# Gateway 1I — observability, capacity and operations

Normative baseline: Urban API Gateway PET v1.3 T33.11, T33.12, T33.13 and T33.16.

Implemented CI evidence:
- reproducible capacity fixture declares route/capability/source cardinalities, request mix, payload distribution, stream concurrency and backend latency distribution;
- observability contract declares data-plane, publication and etcd metrics, SLO targets and mandatory alerts;
- CI validates percentile ordering, request-mix completeness and presence of PET-required etcd signals.

Evidence boundaries:
- no deployed performance numbers are claimed;
- no dashboard screenshot, alert firing evidence, HPA scaling behavior, saturation result, SBOM signing/provenance or real load-test report is claimed by this increment;
- those remain EVIDENCE PENDING until produced in the adopted deployment environment.

No PET deviation is introduced.
