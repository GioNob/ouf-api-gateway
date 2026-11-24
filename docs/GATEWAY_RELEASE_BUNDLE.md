# Rilascio Gateway D-081

## Discovery semantica e revisione onboarding (D-087, 51j)

Il bundle v2 adotta gli ID APISIX `mcp-semantic-discovery-request`,
`mcp-semantic-discovery-status`, `mcp-semantic-discovery-candidates`,
`mcp-semantic-discovery-adopt` e `mcp-managed-file-review-prepare`.
Il dispatch richiede il workload MCP autenticato e una delega HUMAN. Le prime
tre rotte firmano con il riferimento `gateway.semanticDiscoveryOwnerKeyEnv`.
`adopt` usa `gateway.semanticProposalOwnerKeyEnv` e `review-prepare` usa
`gateway.sourceRevisionOwnerKeyEnv`. Il profilo privato deve associare ciascun
riferimento alla chiave già verificata dal rispettivo owner.

`contracts/mcp-discovery-review-capabilities.json` contiene le cinque righe del
manifest MCP `868daf3` (1.15.3-next-step-v1), in ordine sorgente. Integra lo
snapshot generale preservandone la provenienza. In `internal/kernel/kernel.go`
il MCP esegue `delete(input, "analysisId")` prima di `json.Marshal(input)`.
La proiezione del Gateway esclude quel contesto locale. Su `candidates`
`requestId` è obbligatorio e `includeState` è un booleano facoltativo.
La mediazione firma e inoltra i byte acquisiti prima della validazione.

Per le prime tre discovery il massimo dell'envelope è 264.192 byte, secondo
la derivazione 50f. Il kernel limita la chiamata Semantic a 262.144 byte.
Su `review-prepare` il manifest consente `WITHDRAW` e `RESTART_DRAFT` in
alternativa a `executionProposal`. I riferimenti semantici della proposta
rientrano nel budget MCP di 2 MiB per gli argomenti e nel limite Gateway di
3 MiB per il corpo.

La delega delle quattro rotte Semantic conserva lo scope installato
`ouf.semantic.discovery`. Il manifest dichiara scope specifici per
`status`, `candidates` e `adopt`. La chiusura della divergenza richiede una
verifica IAM delle deleghe emesse nell'installazione. La ricevuta di `adopt`
identifica la capability `ouf.semantic.discovery.adopt`.

I PET `GW-51J-MANIFEST`, `GW-51J-SCHEMA`, `GW-51J-FORWARD`, `GW-51J-SCOPE`,
`GW-51J-REVIEW`, `GW-51J-IDEMPOTENCY` e `GW-51J-LEGACY` sono in
[`test_discovery_review_release.py`](../tests/test_discovery_review_release.py).
`GW-51J-WIDE` verifica una proposta con 1.024 riferimenti in
[`test_onboarding_review.py`](../tests/test_onboarding_review.py).
`GW-51J-PARITY` verifica il digest delle precedenti 24 risorse in
[`test_r2b_release.py`](../tests/test_r2b_release.py).

## Pagine THS, approvazioni e autorizzazione (D-087, 60f)

Onboarding gestisce sessione e CSRF per le pagine e i callback. Le API di approvazione
e le operazioni amministrative GET e POST conservano il bearer per la verifica dell’owner.
Prima del rilascio, il profilo dell’esecutore deve fornire `count` e `timeWindowSeconds`
per `gateway.rateLimits.thsApprovals` e `gateway.rateLimits.thsAuthorization`.
I quattro valori sono interi e provengono da `limit-count.count` e `limit-count.time_window`
delle rispettive rotte installate. PUT e DELETE amministrativi restano da valutare con l’owner.

I PET da `GW-60f-01` a `GW-60f-08` verificano il sottoinsieme di base, i corpi APISIX,
i conflitti, il ritorno, i deployer legacy e gli header inoltrati. La prova sull’inventario
richiede i due export sanificati del task. [Test della famiglia](../tests/test_release_family_ths_pages.py)

## Rotte del rilascio

| ID rotta | Metodo e percorso | Capability | Backend logico |
| --- | --- | --- | --- |
| `semantic-human-terms` | `GET /api/trusted-human/v1/semantic-published-terms` | `ouf.semantic.review@1.0.0` | `ouf-semantic-registry:8080`, stesso percorso |
| `trusted-human-resolution-review` | `GET`, `POST /trusted-human/resolution/*` | `resolution.issue.read` (label della pagina con sessione Onboarding) | `ouf-onboarding:8080`, stesso percorso |
| `ths-resolution-package-read` | `GET /api/udp/v1/governance/resolution/issues/package` | `resolution.issue.read` | `ouf-udp-object-resolution:8080`, stesso percorso |
| `ths-resolution-package-confirm` | `POST /api/udp/v1/governance/resolution/issues/package/confirm` | `resolution.match.approve` | `ouf-udp-object-resolution:8080`, stesso percorso |
| `semantic-proposal-create` | `POST /internal/capabilities/v1/execute/semantic/create` | `ouf.semantic.propose` | `ouf-semantic-registry:8080/api/semantic/v1/proposal-commands/create` |
| `mcp-managed-file-create` | `POST /internal/capabilities/v1/execute/managed.file/create` | `ouf.managed-source.onboarding.create` | `ouf-onboarding:8080/api/internal/v1/onboarding/managed-file-mcp/create` |
| `mcp-source-revision-prepare` | `POST /internal/capabilities/v1/execute/source.revision/prepare` | `ouf.onboarding.revision.prepare` | `ouf-onboarding:8080/api/internal/v1/onboarding/source-revision-mcp/prepare` |

La rotta dei termini semantici richiede un bearer OIDC con attore `HUMAN` e scope
`ouf.semantic.review`. APISIX confronta il solo percorso con il selettore
`uri` e inoltra la query `revisionIds` al registro semantico. Il limite del
corpo è 65.536 byte e il timeout upstream è 10 secondi.

Per le tre rotte di risoluzione il limite del corpo è 1.048.576 byte.
I timeout di connessione e invio sono 3 secondi. Il timeout di lettura è
30 secondi per la pagina e 20 secondi per le API UDP. La conferma conserva
la validazione del corpo. [Schema della conferma](../schemas/ths-resolution-package-confirm-v1.json)

Il bundle incrementale contiene le risorse APISIX in tabella e quelle del
secondo giro D-085 riportate più avanti.
Il contratto `ouf.gateway-release-bundle.v3` usa i segnaposto D-058 per host,
porta intera, discovery OIDC, audience, riferimento al segreto client e label
d’installazione. Il manifest `ouf.gateway-release-manifest.v3` riporta commit,
workflow, ID del run e digest.

Nell’elenco `retired` le due rotte sostituite duplicano percorso, metodo e
`vars` delle rotte Ingestion governate. Le due voci riportano i `vars` letterali
della rotta legacy: le classi di caratteri sono scritte in un altro ordine, con la stessa
semantica, e l’esecutore rimuove solo una rotta con quei `vars` esatti. Bundle e manifest riportano
`retiredSha256`, lo SHA-256 del JSON canonico di `retired`.
[Elenco versionato e motivazioni](../ouf-config/release/retired-routes.json)

| Rotta da rimuovere | Rotta sostitutiva |
| --- | --- |
| `r4a-ingestion-human-run-read` | `trusted-human-ingestion-run-read` |
| `r4a-ingestion-human-run-resume` | `trusted-human-ingestion-run-resume` |

Le due copie disattivate della ricerca correlata hanno `supersededBy: null`.
Per ciascun ID il digest copre anche il motivo pubblico e il `match` letterale
di selettori, stato ed etichette. Un campo assente nell’export vale `null`.
Prima del rilascio v3 va attivato l’esecutore aggiornato di `ouf-deploy` (task-60k).
Il plan HUMAN mostra l’ID e «da rimuovere (obsoleta: motivo)» oppure «già assente».
L’apply verifica il corpo approvato e conferma ogni assenza. Al ritorno l’esecutore
ripristina e rilegge il corpo del primo snapshot se l’ID è libero. Un corpo diverso
richiede riconciliazione. Un ID già assente al primo plan resta assente.
I PET `GW-60J-01`–`03` verificano la parità con `3d69cb4` e le quattro identità
in `tests/test_r2b_release.py`. I PET `GW-60J-04`–`06` coprono gli errori statici,
il caricamento in CI e i valori JSON letterali in `tests/test_gateway_release_bundle.py`.

Il job `config-contract` genera il bundle dal commit testato sia su `push` sia
su `pull_request` e risolve i segnaposto con un profilo di test. Il gate esegue
tre avvii indipendenti di APISIX e si ferma al primo errore. Prima dei dispatch
attende un diniego OIDC `401` su `/mcp` e su ogni rotta di dispatch del bundle.
Per i termini semantici verifica l’inoltro della query, i dinieghi di
autorizzazione e i mancati match per metodo o percorso. Su pull request, a gate
superato, l’artefatto `gateway-release-bundle-<runId>` contiene `bundle.json`,
`manifest.json` e `SHA256SUMS`. I comandi seguenti riproducono il formato in
locale con un ID di prova.

```sh
python -m tools.gateway_release_bundle --output generated/gateway-release-bundle --workflow-path .github/workflows/ci.yml --run-id 33
python -m pytest -q tests/test_gateway_release_bundle.py tests/test_semantic_human_routes.py tests/test_resolution_ths.py
```

## Recupero run e dispatch D-085

| ID rotta | Metodo e percorso | Capability o scope | Percorso owner |
| --- | --- | --- | --- |
| `mcp-managed-file-preview` | `POST /internal/capabilities/v1/execute/managed.file/preview` | `ouf.managed-source.preview` | Onboarding `/api/internal/v1/onboarding/managed-file-mcp/preview` |
| `mcp-managed-file-handoff` | `POST /internal/capabilities/v1/execute/managed.file/handoff` | `ouf.managed-source.file.upload` | Onboarding `/api/internal/v1/onboarding/managed-file-mcp/handoff` |
| `mcp-managed-file-handoff-issue` | `POST /internal/capabilities/v1/execute/managed.file/handoff-issue` | `ouf.managed-source.file.handoff-issue` | Onboarding `/api/internal/v1/onboarding/managed-file-mcp/handoff-issue` |
| `mcp-managed-file-review-read` | `POST /internal/capabilities/v1/execute/managed.file/review-read` | `ouf.managed-source.onboarding.read` | Onboarding `/api/internal/v1/onboarding/managed-file-mcp/review-read` |
| `semantic-proposal-read` | `POST /internal/capabilities/v1/execute/semantic/read` | `ouf.semantic.proposal.read` | Semantic `/api/semantic/v1/proposal-commands/read` |
| `trusted-human-ingestion-run-recovery` | `GET`, `POST /trusted-human/ingestion-run-recovery/*` | Sessione THS | Onboarding, stesso percorso |
| `trusted-human-ingestion-run-read` | `GET /api/trusted-human/v1/ingestion/runs/{id}` | `ingestion.run.read` | Ingestion, stesso percorso |
| `trusted-human-ingestion-run-resume` | `POST /api/trusted-human/v1/ingestion/runs/{id}/resume` | `ingestion.run.resume` | Ingestion, stesso percorso |
| `trusted-human-ingestion-run-abort` | `POST /api/trusted-human/v1/ingestion/runs/{id}/abort` | `ingestion.run.abort` | Ingestion, stesso percorso |

Onboarding gestisce sessione e CSRF. La pagina preserva i relativi cookie e
header e rimuove il bearer e gli header `x-ouf-*` del client. Le API Ingestion
richiedono OIDC HUMAN e rimuovono gli header `x-ouf-*` del client. Il bundle
risolve l'upstream da `services.bindings.ouf-ingestion-runtime` e
`services.ports.ouf-ingestion-runtime`. Le rotte hanno `retries: 0`: la decisione
versionata e il budget di recupero restano responsabilità di Ingestion.

### Selettore dei file (D-087, D-089)

Entrambe le rotte richiedono il workload MCP e una delega HUMAN con lo scope
`ouf.managed-source.file.upload`. Il Gateway firma il percorso owner e l’hash
dell’envelope. Per l’emissione verifica anche la corrispondenza del
`commandKey` con la chiave di idempotenza. Le due rotte hanno un limite di
65.536 byte, tre timeout upstream di 3 secondi e zero retry.

Per aggiornare le sole due dichiarazioni dal checkout MCP qualificato eseguire
`python -m tools.sync_picker_contracts <checkout-mcp>`.
L’opzione `--check` confronta le due righe del manifest con
`contracts/mcp-picker-capabilities.json`. Gli argomenti di lettura derivano da
`handoffInputSchema` della capability upload e quelli di emissione da
`inputSchema` della capability interna. I backup legacy a quattro rotte
ripristinano profile, preview e create. Il bundle governa il ripristino della lettura.

### Link THS emessi da Onboarding (D-085 B.2 e B.4)

| ID della rotta | URI Gateway | Percorso owner (`ouf-onboarding`) | Argomenti |
| --- | --- | --- | --- |
| `mcp-ingestion-run-recovery-link` | `POST /internal/capabilities/v1/execute/<nome del gatewayBindingRef>` del link di recupero | `POST /api/internal/v1/onboarding/ths-links/ingestion-run-recovery` | `sourceId`, `runId`, `expectedVersion` |
| `mcp-semantic-review-link` | `POST /internal/capabilities/v1/execute/<nome del gatewayBindingRef>` del link di revisione | `POST /api/internal/v1/onboarding/ths-links/semantic-review` | `challengeId` |

Onboarding restituisce `{reviewUrl, expiresAt}`. Il Gateway richiede il client
MCP M2M e la delega HUMAN con lo scope del manifest. Inoltra solo gli argomenti
in JSON canonico UTF-8 e firma il percorso owner e l'hash dei byte inoltrati
nella ricevuta managed-file. Entrambi i link applicano un limite di richiesta
di 65.536 byte, timeout upstream di 3 secondi e `retries: 0`.

Le due dichiarazioni usano gli ID del manifest MCP. Il Gateway deriva lo schema
e l'URI di dispatch da quel manifest. Il task 51d sincronizza lo snapshot dal
commit MCP `f81e9611e73fef4ee7673e8e1f224a1c95e6e261`. Cambia
`nextPolicies` e la sezione `capabilities` conserva gli stessi schemi.

## Dispatch MCP e tipi di valore D-084

Il Gateway valida l’envelope completo e firma i byte ricevuti. Per la proposta
semantica ammette un `DATATYPE` con 1–32 componenti o un `VALUE_MAP` con pin al
vocabolario, 1–2.000 voci `code`/`concept` ed etichette opzionali `it`/`en`.
I codici hanno al massimo 128 punti di codice, senza spazi Unicode White_Space
agli estremi né controlli C0 e C1. I concetti hanno al massimo 512 caratteri.
La rotta rifiuta codici duplicati prima di firmare la ricevuta. La proposta
può includere `rationale.sourceColumn` fuori dalla definizione. Il Registry
verifica pubblicazione e appartenenza al vocabolario.
[Contratto delle value map](../contracts/ouf-value-maps-v1.json)

Per creazione e revisione il Gateway ammette lettori con `transformParams`,
costruttori e composizioni strutturate fino a quattro livelli. Un componente `MANY` accetta builder singoli in
`items` o un costruttore `LIST_SPLIT_V1` con i parametri del lettore degli elementi.
Le violazioni dello schema e i codici duplicati restituiscono `INVALID_TOOL_ARGUMENTS`.

Il Semantic Registry verifica le definizioni e il grafo dei tipi. Onboarding
risolve i pin, controlla cardinalità, compatibilità, appartenenza al vocabolario
e stato `ACTIVE` di ogni tipo richiesto nella preparazione. Le regole di rilettura
dei bundle pubblicati sono nel [contratto comune](../contracts/ouf-value-types-v1.json).

| Comando | Budget dichiarato da MCP | Limite Gateway sull’envelope firmato |
| --- | --- | --- |
| `semantic.propose` con `VALUE_MAP` | 1.048.576 byte di argomenti | 1.048.576 byte |
| `semantic.propose`, altri tipi | 65.536 byte di richiesta | 65.536 byte |
| `source.onboarding.create` | 2.097.152 byte di argomenti | 3.145.728 byte |
| `source.onboarding.revision.prepare` | 65.536 byte di argomenti | 65.536 byte |

Il budget dell’envelope comprende identità, correlazione e metadati. MCP e
Registry verificano il limite di 786.432 byte sulla definizione canonica. Il
gate APISIX include una definizione di queste dimensioni con 2.000 codici
da 128 caratteri, verifica la firma della ricevuta sul backend di prova e
controlla il limite HTTP di entrambi i tipi di proposta.

Nel candidato Onboarding task-40, `ManagedFileMcpApi` ammette 3 MiB per la creazione,
ma `PermissionDelegationVerifier.verifyBound` applica 65.536 byte alla ricevuta
sullo stesso corpo. La fascia superiore richiede una verifica pairwise dell’owner.

Nel profilo D-058, `gateway.delegationKeyEnv` identifica la chiave di delega.
`gateway.semanticProposalOwnerKeyEnv` e `gateway.sourceRevisionOwnerKeyEnv`
identificano le chiavi dei verificatori Semantic e Onboarding. Le due rotte
Onboarding raggiungono lo stesso verificatore e usano domini MAC distinti.
Il bundle risolve le label prima del caricamento in APISIX. L'URL dell'issuer
è risolto in `openid-connect.claim_validator.issuer.valid_issuers`. La funzione
Lua legge lo stesso valore per verificare il token di servizio e la delega.

APISIX 3.18 rifiuta gli identificatori assoluti nello schema inline di
`request-validation`. I tre materializzatori omettono il `$id` radice dal
`body_schema` e conservano i riferimenti JSON Pointer locali alla busta. Il
catalogo conserva il `$id` per dare a ciascuno schema la propria radice quando
viene usato come ramo di un documento più ampio.

In APISIX 3.18 `request-validation` valida il body JSON contro lo schema chiuso
e poi lo ricodifica. Le rotte `semantic.propose` e
`source.onboarding.revision.prepare` catturano i byte originali in `rewrite`,
prima della validazione, con limiti rispettivamente di 1 MiB e 64 KiB. In
`access` usano quei byte per i controlli dell'envelope, l'hash della ricevuta e
l'inoltro all'owner, preservando la precisione numerica e la rappresentazione
JSON. Per `semantic.propose` il limite rimane 64 KiB per gli artefatti diversi
da `VALUE_MAP`. Entrambi gli owner rifiutano le chiavi duplicate. Semantic
Registry usa `STRICT_DUPLICATE_DETECTION` in `SemanticProposalReceiptVerifier`.
Source Onboarding usa `FAIL_ON_READING_DUP_TREE_KEY` in `SourceRevisionApi`
quando legge l'envelope con `readTree`.

Per confrontare gli schemi e le tre fixture con una checkout locale del MCP,
eseguire `python -m tools.sync_value_type_schemas <checkout-mcp> --check`.
Lo stesso comando senza `--check` aggiorna le copie. Il confronto verifica
anche l’identità di entrambi i contratti. La CI esegue le prove offline con
`python -m pytest -q tests/test_value_type_schemas.py`.

## Limiti R2B d'installazione

Ogni prefisso in tabella richiede tre valori nel profilo privato. Il campo
`.count` è il numero di richieste per finestra, `.timeWindowSeconds` è la
durata in secondi ed entrambi sono interi positivi. Il campo `.key` è il nome
di una variabile APISIX, stringa senza prefisso `$`. Le due letture delle
pubblicazioni condividono il profilo. Scrittura lake, handoff, lettura
puntuale e lettura a lotti hanno costi e frequenze distinti.

| Prefisso esatto | Rotta |
|---|---|
| `gateway.rateLimits.r2bLakeWrite` | Lake |
| `gateway.rateLimits.r2bHandoffWrite` | Handoff |
| `gateway.rateLimits.r2bSemanticGet` | Risoluzione GET dei runtime precedenti |
| `gateway.rateLimits.r2bSemanticBatch` | Risoluzione POST a lotti |
| `gateway.rateLimits.r2bPublication` | Feed e risoluzione della pubblicazione |

Il bundle contiene soltanto segnaposto tipizzati. Per lo sviluppo locale il
frammento `config/development/r2b-rate-limits.yaml` fornisce
il blocco `gateway.rateLimits` da unire alla proiezione. Test e produzione
richiedono un profilo esplicito. Per la qualifica è proposta la variabile
`remote_addr`. Caddy aggrega i chiamanti sullo stesso indirizzo. APISIX applica
la quota per rotta e restituisce `X-RateLimit-Limit`, `X-RateLimit-Remaining`
e `X-RateLimit-Reset`. `X-RateLimit-Reset` è espresso in secondi frazionari,
per esempio `59.97`. Il `429` di APISIX 3.18 non porta `Retry-After`: i runtime
ricavano l'attesa da `X-RateLimit-Reset`. Il budget di produzione dipende dalla
qualifica R-043.
[Contratto delle rotte e ordine dei plugin](R2B_OWNER_ROUTES.md)

**Registro D-065 · gateway.r2b-rate-limits.v1.** Il Gateway possiede i 15
campi di configurazione pubblicamente censiti in `config/runtime-catalog-v1.yaml`.
Il profilo d'installazione privato ne conserva i valori. La quota non contiene
segreti. La cattura privata associa i valori alla revisione, al digest del
bundle e alle sei risorse del prefisso APISIX routes in etcd. Per il ripristino
si ripristinano prima IAM, riferimenti OIDC e binding dei servizi, poi il profilo
e il bundle della revisione, con confronto del plan e readback delle rotte.
La prova di ripristino deve verificare chiamata autorizzata, diniego e 429 con
i tre header. I contatori locali in memoria ripartono sulla nuova istanza.
La CI esercita la risoluzione del bundle e il transito HTTP. La ricevuta su un
secondo host compete alla qualifica dell'installazione.
