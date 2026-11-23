# R2b owner route contracts

R2b adds workload-only publication/exact-reference, Lake and durable-handoff route declarations and authorized object read/search routes. Managed content read admits both the existing Onboarding consumer and Ingestion explicitly. Lake/handoff capabilities are not MCP tools and do not grant read permission.

Namespace routes only accept one terminal `/*`, with the identical backend namespace. The compiler omits URI rewriting for them, preserving the actual object/source path rather than sending a literal wildcard upstream. Every backend retains final resource/capability enforcement.

The governed release owns the six internal R2B routes below. The two public OIDC routes `r2b-object-read` and `r2b-object-search` retain their separate release path. The source-to-serving regression uses laboratory HTTP and source adapters. The PULL endpoint `/internal/sources/v1/fetch` requires a deployed governed southbound binding adapter. GW-01 and environment acceptance stay open.

The runtime source-to-serving test exercises real Onboarding, Ingestion, UDP and MinIO; final immutable commit/run evidence is recorded in the Semantic coordination repository. Backend fixtures never become production authentication providers.

## Contratto del piano dati e finestra mista D-086

| ID | Metodo e URI | Scope | Workload |
|---|---|---|---|
| `r4a-udp-runtime-lake-write` | POST `/api/internal/v1/lake/objects` | `datalake.write` | Ingestion |
| `r4a-udp-runtime-handoff-write` | POST `/api/internal/v1/handoffs` | `udp.candidate.write` | Ingestion |
| `r2b-semantic-reference` | GET `/api/semantic/v1/references:resolve` | `ouf.semantic.read` | Ingestion, UDP |
| `r2b-semantic-reference-batch` | POST `/api/semantic/v1/references:resolve-batch` | `ouf.semantic.read` | Ingestion, UDP |
| `r4a-onboarding-runtime-publications-list` | GET `/api/onboarding/v1/runtime/publications` | `ouf.onboarding.configuration.read` | Ingestion, UDP |
| `r2b-publication-resolution` | GET `/api/onboarding/v1/runtime/publications/*` | `ouf.onboarding.configuration.read` | Ingestion, UDP |

Le tre rotte R2B con prefisso `r4a-` sono state create in APISIX prima della governance. Il bundle adotta gli ID in esercizio, così il rilascio aggiorna le risorse esistenti senza duplicarle.

Il contratto del lotto è `ouf.semantic.reference-batch.v1`. APISIX applica 262.144 byte alla richiesta, conserva query e bearer e usa i timeout di 10 secondi della GET. Il Registry verifica cardinalità, riferimenti e visibilità del tenant e compone la risposta compatta. Il Gateway configura zero retry upstream anche sulle scritture.

Le dichiarazioni GET e lotto descrivono l'attore logico `SERVICE_IDENTITY`. Il claim Keycloak verificato è `ouf_actor_type=SERVICE`, già richiesto dalla GET in `6be7707` e riconosciuto dal convertitore JWT del Registry. La lettura wildcard delle pubblicazioni conserva anche il nome `SERVICE` nella dichiarazione. Il binding risolve gli ID client da `iam.workloadClients.ingestion` e `iam.workloadClients.udp`. La fase rewrite elimina ogni header client `X-OUF-*`. Dopo la verifica OIDC di firma, issuer e audience, la guardia controlla scope, attore e client (`client_id` o `azp`) e proietta principal, tenant, attore, contesto di autenticazione, issuer, audience, scope e `Gateway-Verified`. L'owner riceve anche il bearer per la propria autorizzazione.

Il profilo proposto usa `remote_addr`. La guardia che proietta `X-OUF-Service-Principal` è una `serverless-post-function` in access. Il contatore viene valutato prima di quella proiezione. Il gate APISIX 3.18 verifica l'ordine osservando il credito consumato da un workload con scope valido ma client escluso. Dietro Caddy i runtime condividono il credito della singola rotta e istanza APISIX. Le rotte hanno contatori distinti anche quando condividono la stessa classe di configurazione. Gli header `X-RateLimit-Limit`, `X-RateLimit-Remaining` e `X-RateLimit-Reset` sono abilitati anche per verificare il 429. I valori e il dosaggio vanno coordinati tra i processi che condividono l'indirizzo. [Parametri del bundle](GATEWAY_RELEASE_BUNDLE.md#limiti-r2b-dinstallazione)

### Confronto con l'installazione

La forma candidata ricostruisce il contratto dalle dichiarazioni. La base contiene già un materializzatore per GET semantica e publication-resolution. Quella versione incorpora gli ID client in Lua, rimuove una lista chiusa di header e verifica i claim senza proiettarli. La candidata usa label degli ID client, verifica esplicita dell'issuer, proiezione completa, dimensione del body e timeout. Se il VPS contiene la forma di quel materializzatore, il plan mostrerà differenze anche fuori quota. Il valore di 60/min osservato sul lake non identifica la configurazione delle altre rotte.

Per il primo rilascio Claude confronta il **plan governato in sola lettura** con `GW-51D-PLAN`. Sono attese cinque rotte esistenti e una creazione per il lotto. I soli percorsi di update ammessi sono `plugins.limit-count.count`, `plugins.limit-count.time_window`, `plugins.limit-count.key`, `plugins.limit-count.show_limit_quota_header`, `labels.ouf-installation` e `labels.ouf-installation-revision`. Ogni rotta può mostrarne un sottoinsieme. Una creazione inattesa, una collisione sullo stesso metodo/URI con altro ID, una modifica delle label workload, dei selettori, della guardia, di OIDC o dell'upstream richiede la riconciliazione della forma effettiva prima dell'apply. Il test offline fissa la forma ipotizzata con digest indipendenti dal codice di generazione. La ricevuta del plan resta necessaria.

| Prova D-082 | Esecuzione ed evidenza |
|---|---|
| GW-51D-PLAN | `python -m pytest -q -s tests/test_r2b_release.py` stampa azione e percorsi attesi per ID di rotta. |
| GW-51D-LIVE | `tests/test_execute_apisix_live.py::test_real_apisix_oidc_delegation_and_execute` esegue `check_r2b_mixed_window` sul bundle qualificato da `config-contract`, con APISIX 3.18 e JWT firmati dalla fixture. |
| GW-51D2-ADOPTION | `tests/test_r2b_release.py::test_adopted_route_ids_and_unique_selectors` verifica gli ID adottati e le collisioni tra selettori di rotta nel bundle. |
| GW-51D2-RESOURCE-PARITY | `tests/test_r2b_release.py::test_release_resources_match_6ae4886_with_original_ids` ripristina i tre ID per il confronto e verifica il digest delle risorse di `6ae4886`. |
| GW-51D3-BASELINE-PARITY | `tests/test_r2b_release.py::test_release_resources_and_placeholders_match_9064a5f` confronta risorse e segnaposto con i digest del generatore di `9064a5f`. |
| GW-51D3-RETIRED-METADATA | `tests/test_r2b_release.py::test_retired_routes_are_declared_as_v2_metadata` verifica le due sostituzioni. Il lettore condiviso dal gate APISIX verifica il formato v2 e il digest dei ritiri, poi carica le sole risorse. |
| GW-51D3-RETIRED-VALIDATION | `tests/test_gateway_release_bundle.py::test_invalid_retirements_stop_bundle_generation` verifica che una dichiarazione di ritiro non valida blocchi la generazione. |

Queste prove contribuiscono a PET-gateway-008 (TECH-07) e PET-gateway-040
(GW-C12). La chiusura del primo richiede osservazione in esercizio, metrica,
alert e isolamento per client. Per il secondo serve la ricevuta d'integrazione
del profilo IAM con gli owner effettivi.
