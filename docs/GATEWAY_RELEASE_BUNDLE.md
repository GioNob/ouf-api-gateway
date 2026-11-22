# Rilascio Gateway D-081

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
Il contratto `ouf.gateway-release-bundle.v1` usa i segnaposto D-058 per host,
porta intera, discovery OIDC, audience, riferimento al segreto client e label
d’installazione. Il manifest riporta commit, workflow, ID del run e digest.

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

Il binding `mcp-ingestion-run-recovery-link` è dichiarato in
[`ouf-config/routes/northbound/mcp-ingestion-run-recovery-link.json`](../ouf-config/routes/northbound/mcp-ingestion-run-recovery-link.json).
Il manifest MCP `da9827061cccd62e2e22f86bcb20334e3da0a4bf` è privo della capability
per il link. Impostare `capabilityId` dopo la sincronizzazione del manifest che
la dichiara e verificare il percorso canonico derivato da `gatewayBindingRef`
con il client MCP. Il test
`test_recovery_link_capability_is_present_in_pinned_manifest` segnala questo
blocco. La rotta è esclusa dalla pubblicazione finché il binding è incompleto.
La prova con fixture controlla delega, scope, corpo e ricevuta. Il verificatore
reale Onboarding per `POST /api/internal/v1/onboarding/ths-links/ingestion-run-recovery`
e il rollout D-086 richiedono ancora la verifica integrata.

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
