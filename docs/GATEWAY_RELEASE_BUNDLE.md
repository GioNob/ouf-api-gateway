# Pacchetto di rilascio Gateway

Il pacchetto sprint-03 aggiorna un Gateway già installato con dodici risorse Admin API di tipo `routes`. Alla base sprint-02 di sette route aggiunge `mcp-onboarding-schema-notices-read` e distribuisce le quattro route esistenti `mcp-managed-file-{profile,preview,create,review-prepare}` con gli schemi del profilo di unità. Nella base cambia solo lo schema `Arguments` di `mcp-source-revision-prepare`, nelle proprietà `properties.unitProfileRef`, `if`, `then` ed `else`.

Il generatore compila `ouf-config/`, applica la proiezione D-058 con valori simbolici e costruisce i prerequisiti execute e HUMAN con i materializzatori del repository. L'applicazione in esercizio deve verificare la corrispondenza delle rotte preesistenti e del backend Onboarding con l'installazione autorizzata.

### Contratto Gateway → Onboarding per gli avvisi

Il Gateway verifica il workload, la delega HUMAN, lo scope e la corrispondenza con l'envelope. Emette un GET senza corpo verso il nodo Onboarding configurato. Il target firmato comprende il percorso e la query nell'ordine `state=OPEN&limit=n[&after=…]`, con il valore del cursore percent-encoded. La lettura ha una scadenza complessiva di tre secondi e il Gateway restituisce la pagina completa entro il limite `MaxResultBytes` di 65.536 byte.

L'header `X-OUF-Schema-Notices-Receipt` contiene `base64url(payload).base64url(mac)` senza padding. Il MAC è HMAC-SHA256 sulla concatenazione di `ouf-schema-notices-owner-v1.` e della prima componente, con la chiave Onboarding già usata per le revisioni. Il payload JSON contiene `v=1`, `purpose=schema-notices-owner`, `method=GET`, `path` comprensivo della query, capability, issuer, audience, workload, subject, tenant, acr, roles, scope, iat ed exp. La scadenza è al massimo 30 secondi e rientra nella validità della delega.

Per qualificare il percorso completo, il GET dell'owner deve verificare firma, target, capability, contesto e scadenza della ricevuta prima di costruire il principal HUMAN e rivalutare i grant sulle singole sorgenti. Le prove Gateway usano un owner di test. Per una revisione sostitutiva con il solo `unitProfileRef` il chiamante deve fornire `If-Match: W/"ov:<expectedVersion>"`, come richiesto dal task-01.

## Generazione e formato

Da un checkout con le dipendenze di `requirements-dev.txt`, indicare una directory dedicata e i valori di provenienza. L'ID del run nell'esempio è fittizio.

```sh
python -m tools.gateway_release_bundle --output generated/gateway-release-bundle --workflow-path .github/workflows/ci.yml --run-id 123456789
python -m pytest -q tests/test_gateway_release_bundle.py
```

| File | Contenuto |
| --- | --- |
| `bundle.json` | `schema` uguale a `ouf.gateway-release-bundle.v1`, `sourceRepository` uguale a `GioNob/ouf-api-gateway`, `sourceCommit` uguale allo SHA completo di `HEAD`, `resources`, `resourcesSha256` e `placeholders` come elenco di oggetti `{name, type}` ordinato per nome. |
| `manifest.json` | `schema` uguale a `ouf.gateway-release-manifest.v1`, `sourceRepository` e `sourceCommit` uguali al bundle, `workflowPath`, `runId` come stringa di cifre, `bundleSha256`, `resourcesSha256` e `placeholders` come elenco ordinato dei soli nomi. |
| `SHA256SUMS` | Due righe in ordine di nome, prima `bundle.json` e poi `manifest.json`. Ogni riga contiene il digest, due spazi, il nome del file e LF. |

Ogni risorsa ha esattamente `kind`, `id` e `body`. L'ID è la chiave della risorsa in `/apisix/admin/{kind}/{id}`, rispetta `^[A-Za-z0-9._-]{1,64}$` ed è univoco per collezione. Il corpo PUT esclude `id`, `create_time` e `update_time`. L'ordine di applicazione delle collezioni è `upstreams`, `services`, `plugin_configs`, `plugin_metadata`, `global_rules`, `routes`. All'interno di ogni collezione le risorse sono ordinate per ID. Il generatore di questo delta gestisce le rotte e interrompe la generazione se la materializzazione introduce altre collezioni.

I due JSON sono UTF-8 senza BOM, con soli caratteri ASCII, chiavi ordinate, separatori senza spazi, valori numerici finiti e nessun LF finale. La serializzazione di riferimento è `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`. Gli hash sono SHA-256 esadecimali minuscoli. `bundleSha256` copre i byte di `bundle.json` e `resourcesSha256` quelli del solo array canonico `resources` prima della sostituzione.

## Profilo di installazione

Un segnaposto occupa un intero valore JSON, per esempio `{"$installation":"services.ports.ouf-onboarding"}`. Ogni nome rispetta `^[A-Za-z][A-Za-z0-9_.-]{0,127}$`, identifica una voce del registro D-065 e compare sia nella configurazione da risolvere sia negli elenchi del bundle e del manifest. L'esecutore risolve il nome esatto nel profilo privato e sostituisce l'intero oggetto. La CI usa un profilo sintetico in memoria.

Il contratto rev. 2 classifica `services.ports.*` come `integer`. L'esecutore e il loader del gate CI richiedono un intero JSON ed escludono stringhe, booleani e valori in virgola mobile. I nomi con `Secret` o `Key` sono classificati `secret`, compresi i riferimenti ai segreti e i nomi delle variabili che espongono le chiavi. Issuer e discovery sono `url`. Gli altri nomi sono classificati `string`. I tipi `string`, `url` e `secret` richiedono una stringa JSON.

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

1. Su `pull_request` il job `config-contract` verifica il checkout del commit di testa della PR e genera il pacchetto da quel commit. Il workflow passa al generatore `workflowPath` e `runId`.
2. Il gate **Real APISIX OIDC and delegation** verifica formato, hash, provenienza attesa ed elenco dei segnaposto. Risolve le rotte in memoria verificando i tipi dichiarati e le carica nel provider YAML dell'immagine APISIX 3.18.0 con le porte dei nodi upstream come interi. Verifica il rifiuto delle richieste anonime su ogni rotta, attraversa entrambe le rotte di revisione e prova adozione e lettura contro gli owner di test.
3. Dopo il successo del gate, Actions carica esattamente i tre file alla radice dell'artefatto `gateway-release-bundle-<runId>`. Questo caricamento è riservato all'evento `pull_request`. Una riesecuzione può produrre un nuovo ID e digest dell'artefatto.
4. Per il rilascio, verificare tramite GitHub repository, workflow, run riuscito, evento, PR, SHA di testa e appartenenza dell'artefatto al run. Confrontare il digest ZIP con quello restituito da Actions, poi verificare i tre file alla radice, `SHA256SUMS`, lo schema esatto, i campi incrociati, il digest canonico delle risorse e la corrispondenza dei segnaposto. Dopo questi controlli l'esecutore di `ouf-deploy` può risolvere i valori dal profilo privato.
