# Pacchetto di rilascio Gateway

Il pacchetto di PR #93 aggiorna un Gateway già installato. Contiene sette risorse Admin API di tipo `routes`, con upstream e plugin inline. La linea D comprende `mcp-source-revision-prepare` e `mcp-source-revision-read`. La linea C comprende `mcp-semantic-discovery-adopt` e le quattro `semantic-proposal-{create,validate,review,read}` che incorporano lo stesso Lua aggiornato. La lettura consente la riconciliazione di un comando di adozione.

Il generatore compila `ouf-config/`, applica la proiezione D-058 con valori simbolici e costruisce i prerequisiti execute e HUMAN con i materializzatori del repository. Il delta comprende le risorse restituite dai materializzatori di revisione e proposte. L'applicazione in esercizio deve verificare la corrispondenza delle rotte preesistenti e del backend della revisione HUMAN con l'installazione autorizzata. Le risorse assenti dal delta restano di competenza dei rispettivi rilasci.

## Generazione e formato

Da un checkout con le dipendenze di `requirements-dev.txt`, indicare la directory di destinazione.

```sh
python -m tools.gateway_release_bundle --output generated/gateway-release-bundle
python -m pytest -q tests/test_gateway_release_bundle.py
```

| File | Contenuto |
| --- | --- |
| `bundle.json` | `schema` uguale a `ouf.gateway-release-bundle.v1`, `sourceCommit` uguale al SHA completo di `HEAD`, `resources` e `resourcesSha256`. |
| `manifest.json` | `schema` uguale a `ouf.gateway-release-manifest.v1`, lo stesso `sourceCommit`, `files` come mappa da nome file a SHA-256 e `installationPlaceholders` come elenco ordinato dei nomi distinti. |

Ogni risorsa ha esattamente `kind`, `id` e `body`. L'ID è la chiave della risorsa in `/apisix/admin/{kind}/{id}`. Il corpo contiene la configurazione APISIX. Le risorse sono ordinate lessicograficamente per `(kind, id)`. L'esecutore applica solo gli ID dichiarati.

Gli hash sono SHA-256 esadecimali minuscoli. I file usano UTF-8 senza BOM e terminano con un singolo LF. `files["bundle.json"]` copre tutti i byte del file, LF compreso. Il manifest è coperto dal digest dell'artefatto Actions. `resourcesSha256` copre i byte UTF-8 del solo array `resources`, prima della sostituzione, con chiavi ordinate ricorsivamente, senza spazi o LF finale. La serializzazione di riferimento è `json.dumps(resources, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.

## Profilo di installazione

Un segnaposto è un intero valore JSON, ad esempio `{"$installation":"services.ports.ouf-onboarding"}`. L'esecutore risolve il nome esatto nel profilo privato di root e sostituisce l'oggetto con il valore del tipo indicato. Un nome assente, un tipo errato o un oggetto segnaposto con campi aggiuntivi impedisce l'applicazione. La CI usa un profilo sintetico in memoria.

| Nome | Valore da fornire |
| --- | --- |
| `installationId`, `revision` | Stringhe per le label APISIX. Convertire la revisione della proiezione nella sua rappresentazione testuale. |
| `gateway.issuerUrl` | Issuer HTTPS canonico, senza barra finale, corrispondente all'issuer del token. |
| `caddy.oidcDiscoveryUrl` | URL HTTPS della discovery dello stesso issuer. |
| `gateway.requiredAudience`, `iam.workloadClients.mcpServer` | Audience del Gateway e identità del workload MCP dalla proiezione D-058. |
| `gateway.oidcClientSecretRef` | Riferimento APISIX con prefisso `$ENV://` o `$secret://`. Il segreto viene risolto nel runtime. |
| `gateway.delegationKeyEnv`, `gateway.sourceRevisionOwnerKeyEnv`, `gateway.semanticProposalOwnerKeyEnv` | Nomi delle variabili d'ambiente esposte ai worker APISIX per le rispettive chiavi. Usare nomi distinti conformi a `[A-Z][A-Z0-9_]{0,127}`. |
| `services.bindings.ouf-onboarding`, `services.bindings.ouf-semantic-registry` | Host dei servizi logici nella proiezione. |
| `services.ports.ouf-onboarding`, `services.ports.ouf-semantic-registry` | Porte TCP intere da 1 a 65535 per gli stessi servizi. Le rotte condividono il backend del rispettivo owner. |

I nodi upstream usano la forma APISIX con `host`, `port` e `weight`. Il codice Lua distribuito legge issuer, audience, identità e nomi delle variabili dalle label della rotta selezionata da APISIX. I valori del profilo rimangono dati JSON durante tutta la sostituzione.

## Qualificazione CI e verifica prima dell'applicazione

1. Su `pull_request` il job `config-contract` genera i due file dal checkout effettivo. Nella configurazione Actions attuale è il merge commit di prova della PR.
2. Il gate **Real APISIX OIDC and delegation** apre quei file, controlla hash, commit ed elenco dei segnaposto. Risolve le rotte in memoria e le carica nel provider YAML dell'immagine APISIX 3.18.0. Verifica il rifiuto delle richieste anonime su ogni rotta, attraversa entrambe le rotte di revisione e prova adozione e lettura contro gli owner di test.
3. Dopo il successo del gate, Actions carica i due JSON originali come `gateway-release-bundle-<runId>`. Una riesecuzione può produrre un nuovo ID e digest dell'artefatto. Per il rilascio, vincolare repository, workflow e run/tentativo riusciti, commit autorizzato, ID immutabile e digest SHA-256 dell'archivio restituiti da Actions. Un checksum presente nel pacchetto da solo non prova la provenienza.
4. Verificare il digest dell'archivio scaricato e il suo contenuto atteso. Verificare schema, `sourceCommit` di entrambi i file, hash del payload, hash canonico delle risorse, unicità delle coppie `(kind,id)` e corrispondenza esatta dei segnaposto con il manifest. Solo dopo risolvere i valori dal profilo privato e consegnare i corpi all'esecutore privilegiato di `ouf-deploy`.
