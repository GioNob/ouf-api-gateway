# Gateway 1G-A — Configuration completeness and activation gates

Normative baseline: Urban API Gateway PET v1.3, especially T33.2 repository/configuration completeness, T33.4 compatibility, T33.6 Runtime Configuration Catalog and T33.14 cross-module reference-integrity activation gates.

| PET obligation | Evidence | Status |
|---|---|---|
| T33.6 typed runtime catalog | `config/runtime-catalog-v1.yaml`: type/unit/default/min/max/scope/reload | CI CANDIDATE |
| environment-specific governed configuration | explicit `config/environments/{dev,test,prod}.yaml`; unknown environments rejected | CI CANDIDATE |
| T33.4 compatibility declaration | `config/compatibility-v1.yaml`; current generation and fail-closed unknown generation policy | CI CANDIDATE; true N/N-1 exercised when N-1 exists |
| T33.14 capability reference gate | exact `id@version` binding checked before stage | CI CANDIDATE |
| T33.14 source-runtime reference gate | exact `id@version` binding checked before stage | CI CANDIDATE |
| T33.14 extraction/source consistency | extraction must exist and bind same source | CI CANDIDATE |
| T33.14 backend/source consistency | `service://` source owner must match backend service | CI CANDIDATE |
| T33.14 Authorization gate | pluggable authoritative binding gate blocks missing binding when available | CI CANDIDATE at port boundary; real Authorization EVIDENCE PENDING |
| activation before control-plane staging | Publisher executes governance/reference gates before `plane.stage` | CI CANDIDATE |
| no false Authorization evidence | absence of Authorization module remains explicit rather than simulated as verified | VERIFIED by design boundary |
| T33.2 full repository layout (`policies/`, Helm/deploy/security/e2e/SBOM) | not completed in 1G-A; scheduled in security/runtime and supplier-evidence tranches | PARTIAL |

## Sequencing

1G-A deliberately precedes 1G-B adopted APISIX/etcd runtime and 1G-C security/network enforcement. The superseded runtime-policy PR #9 was closed without merge after PET review showed these activation prerequisites must be closed first.
