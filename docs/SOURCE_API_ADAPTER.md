# Adattatore southbound `fetch` per `ouf.vertical-source.v1` (task-61f-a)

> Implementato da Claude, Codex non disponibile (DN-0). Prima parte del 61f: il modulo autonomo.
> La famiglia di rotte `source_api` nel bundle governato, la ricevuta mintata da APISIX e la rotta
> degli esiti UDP sono del **61f-b**.

Contratti: `ouf.source-api.v1` rev. 2, §2 (binding e `fetch`) e §7 (autorizzazione); fonte
`ouf.vertical-mock.v1` §2–§4. Disegno: `parere-61f.md` (ricognizione della linea V).

## Ruolo e confini
`POST /internal/sources/v1/fetch` è il solo punto d'uscita verso i verticali. Il percorso è:

```
Ingestion / Onboarding --OIDC--> APISIX --ricevuta--> source_api_adapter --TLS, IP verificato--> verticale
```

- **APISIX** verifica il JWT (issuer, audience, scope tecnico, attore `SERVICE`, client del workload
  dalla proiezione d'installazione) e conia una ricevuta breve. Questa parte è del 61f-b.
- **L'adattatore** (`tools/source_api_adapter.py`) ricontrolla la ricevuta sui byte esatti ricevuti,
  poi applica grammatica, binding, limiti, segreto e trasporto. Non si fida di nessuna intestazione
  d'identità del chiamante e rifiuta una richiesta che porta ancora `Authorization`.
- Il processo si avvia con `python -B -m tools.source_api_adapter --configuration <file>`, come
  utente non root. È un server TLS con un processo figlio per richiesta (`ForkingMixIn`), così la
  scadenza `SIGALRM` resta nel thread principale e un guasto non contamina le altre richieste.

## Ricevuta di ammissione
Intestazione `X-OUF-Source-Fetch-Receipt`: `base64url(claims).hmac-sha256`, con scopo separato
`ouf-source-api-fetch-v1`. Una ricevuta del provider semantico non vale qui.

| Claim | Controllo |
|---|---|
| `purpose`, `installation`, `issuer`, `audience`, `scope` | uguali alla configurazione |
| `actor` | `SERVICE` |
| `workload` | uno dei due client configurati: `INGESTION` oppure `ONBOARDING` |
| `tenant` | formato chiuso, poi confrontato con `tenants` del binding |
| `requestHash` | SHA-256 di metodo, target e corpo esatti |
| `iat`, `exp` | durata massima 30 secondi |

La chiave HMAC è un file privato (`receiptKeyFile`), come per il provider semantico. La ricevuta è
riutilizzabile solo fino alla scadenza: il trasporto è in sola lettura.

## Registro dei binding
È configurazione privata d'installazione (D-058): nel repository ci sono solo lo schema
`schemas/source-api-binding-registry-v1.json` e l'esempio fittizio
`tests/fixtures/source-api-binding-registry-example.json`.

```json
{"schema": "ouf.source-api-binding-registry.v1", "revision": 1, "bindings": [{
  "bindingRef": "gateway://sources/<id>", "title": "…", "contract": "ouf.vertical-source.v1",
  "origin": "https://<host>[:<porta>]", "allowedNetworks": ["<cidr>"],
  "credentialRef": "secret://<nome>", "trustRef": "trust://<nome>",
  "tenants": ["<tenant>"], "collections": ["*"],
  "limits": {"maxPageBytes": 5000000, "timeout": "PT20S", "maxRequestsPerMinute": 60, "maxConcurrency": 4},
  "status": "ACTIVE"}]}
```

- Forma chiusa, controllata anche nel codice (l'adattatore usa solo la libreria standard). Il codice è
  più severo dello schema dove JSON Schema non arriva: CIDR valido, `bindingRef` unico, numeri interi
  veri, nessun `workload://`.
- `secret://<nome>` si risolve in `<secretsDirectory>/<nome>`: file regolare, un solo link, dello stesso
  utente del processo, senza permessi di gruppo o altri, senza link simbolici. Il nome non diventa mai
  un percorso libero.
- `workload://` è rifiutato all'avvio (`CREDENTIAL_PROVIDER_UNAVAILABLE`) finché non c'è un fornitore
  d'identità configurato.
- `trustRef` (aggiunta di questo task, facoltativa) indica l'ancora di fiducia della CA privata del
  verticale, in `<trustDirectory>/<nome>`. Senza `trustRef` vale il trust store di sistema.
- Il registro e il segreto si rileggono **a ogni richiesta**: revoca (`status: INACTIVE`) e rotazione
  del token valgono dalla richiesta successiva, senza riavvio. Un registro non valido ferma l'avvio;
  a processo avviato dà `SOURCE_UNAVAILABLE` finché non è corretto.

## Grammatica chiusa
| `resource` | Chiamata al verticale | Workload |
|---|---|---|
| `COLLECTIONS` | `GET /collections` | Ingestion, Onboarding |
| `SCHEMA` | `GET /collections/{c}/schema` | Ingestion, Onboarding |
| `ITEMS` | `GET /collections/{c}/items` | solo Ingestion |

- `collection` segue il pattern del contratto (`^[a-z][a-z0-9_-]{0,62}$`).
- `ITEMS` ammette `mode` (`CURSOR`, `WATERMARK`, `SNAPSHOT`) e `limit` (1–1000). `CURSOR`: `cursor`.
  `WATERMARK`: prima pagina con `changedSince` (RFC 3339) ed eventuale `afterId`, poi solo `cursor`.
  `SNAPSHOT`: `page`. Senza `mode` vale solo `limit`.
- I token (`cursor`, `page`) sono opachi, nell'alfabeto `[A-Za-z0-9._~+/=-]`, fino a 4096 caratteri.
  Ogni valore è codificato in query senza caratteri sicuri, quindi un token non cambia mai percorso
  né host. Ogni altro campo, intestazione o percorso del chiamante è rifiutato con
  `SOURCE_REQUEST_INVALID` **prima** di DNS e connessione.

## Trasporto
- DNS risolto e **ogni** indirizzo verificato con `tools/southbound_security.validate_destination`:
  host e porta registrati, classi vietate (loopback, link-local, multicast, riservati), CIDR del binding.
- Connessione all'indirizzo verificato (`PinnedHTTPSConnection` del relay semantico), con SNI e verifica
  TLS del nome; TLS 1.2 o superiore. Nessun secondo lookup DNS.
- Solo intestazioni tecniche: `Accept`, `Accept-Encoding: identity`, `Authorization: Bearer <segreto>`,
  `User-Agent`. Il bearer va solo all'origine del binding.
- Una scadenza unica (`limits.timeout`) per DNS, TLS, intestazioni e corpo. Un solo tentativo.
- Nessun redirect: un `3xx` è `SOURCE_RESPONSE_INVALID`.
- Byte contati anche con `chunked`; oltre `maxPageBytes` la risposta è `SOURCE_RESPONSE_TOO_LARGE`
  senza corpo parziale. Una risposta più corta del `Content-Length`, o un `chunked` interrotto, è
  `SOURCE_UNAVAILABLE`. Un corpo d'errore oltre 64 KiB non si interpreta, ma lo stato della fonte si
  mappa comunque secondo la tabella degli errori.

## Risposta
- `200` con i byte del verticale **invariati**, più `X-Ouf-Source-Schema-Version` e, se la busta la
  dichiara, `X-Ouf-Source-Epoch`.
- La versione viene da `X-Schema-Version` o dal campo `schemaVersion` del corpo: almeno uno deve
  esserci e, se ci sono entrambi, devono coincidere (D-076). Per `SCHEMA` e `ITEMS` il campo
  `collection` del corpo deve essere quello chiesto.
- **Unica eccezione:** `COLLECTIONS` con un binding a `collections` ristretto. Il catalogo è filtrato
  alle collezioni ammesse, il digest è ricalcolato (`ouf.vertical-mock.v1` §3) e la risposta porta
  `X-Ouf-Catalog-Filtered: true`.

## Errori
Corpo chiuso `{"code","reason"?,"schemaVersion"?,"epoch"?,"retryAfter"?}`.

| Causa | `code` | HTTP |
|---|---|---|
| Fonte `410` | `SOURCE_CURSOR_EXPIRED`, `reason` `RETENTION` o `EPOCH_CHANGED`, `epoch` nuova | 410 |
| Fonte `429` | `SOURCE_RATE_LIMITED`, `retryAfter` da `Retry-After` in secondi interi | 429 |
| Fonte `503`, scadenza, rete, TLS, DNS fuori dai CIDR | `SOURCE_UNAVAILABLE`, `retryAfter` se c'è | 503 |
| Fonte `401` o `403` | `SOURCE_CREDENTIAL_REJECTED` | 502 |
| Pagina oltre il limite | `SOURCE_RESPONSE_TOO_LARGE` | 502 |
| Redirect, tipo, codifica o JSON non validi, versione assente o discordante | `SOURCE_RESPONSE_INVALID` (aggiunta) | 502 |
| Fonte `400`, `404`, `409` autenticati | `SOURCE_REQUEST_REJECTED` (aggiunta), `reason` = codice della fonte | 422 |
| Binding sconosciuto, inattivo, di altro tenant, collezione o risorsa fuori perimetro | `SOURCE_BINDING_NOT_ALLOWED`, risposta identica | 403 |
| Ricevuta assente, non valida, scaduta o `Authorization` del chiamante | `SOURCE_ADMISSION_DENIED` (aggiunta) | 403 |
| Grammatica | `SOURCE_REQUEST_INVALID` (aggiunta) | 400 |
| Limite locale di frequenza | `SOURCE_RATE_LIMITED`, `retryAfter` | 429 |
| Limite locale di concorrenza | `SOURCE_UNAVAILABLE`, `retryAfter: 1` | 503 |

Il client dell'Ingestion (task-61g) tratta come transitori i codici tipizzati `429 SOURCE_RATE_LIMITED`
e `503 SOURCE_UNAVAILABLE`. Un codice che non conosce vale come risposta non tipizzata: è permanente con
`400`, `403` e `422`, ma **transitorio** con `502`. Finché il 61g non aggiunge le quattro aggiunte al suo
elenco, `SOURCE_RESPONSE_INVALID` (`502`) viene quindi ritentato invece di bloccare (correzione della
review 61f-a). Non passa alcun dato: il chiamante non riceve corpo. Un input malformato, anche con tipi
JSON errati, annidamento eccessivo o surrogati, è sempre `400 SOURCE_REQUEST_INVALID`, mai un `503`.

## Limiti
- Corpo in ingresso fino a 16 KiB, `Content-Length` obbligatorio, niente `Transfer-Encoding`.
- `maxRequestsPerMinute` (finestra scorrevole) e `maxConcurrency` per binding, condivisi fra i
  processi figli con file `flock` in `stateDirectory` (privata). Il kernel rilascia i lock alla fine
  del processo, quindi un crash non perde uno slot.
- `maxWorkers` limita i processi figli in totale.

## Segreti e log
- Il bearer non compare in log, errori o eccezioni: le eccezioni di trasporto sono sostituite da codici
  fissi (`from None`). Un token sentinella lo prova nei test.
- Una riga per richiesta su `stderr`:
  `SOURCE_API_FETCH code=<codice> durationMs=<n> bytes=<n> correlationId=<id validato o ->`.
  Mai bearer, URL, query, cursori, corpi o `bindingRef`.

## Configurazione del processo
Chiavi chiuse: `listenAddress`, `listenPort`, `maxWorkers`, `requestTimeoutSeconds`, `fetchPath`,
`admission` (`installation`, `issuer`, `audience`, `scope`, `workloads.INGESTION`,
`workloads.ONBOARDING`), `receiptKeyFile`, `registryFile`, `secretsDirectory`, `trustDirectory`,
`stateDirectory`, `tlsCertificateFile`, `tlsPrivateKeyFile`. Sono tutti parametri d'installazione
(D-056): nessun host, porta, rete, client IAM o percorso è cablato.

## Prove (D-082)
`tests/test_source_api_adapter.py`, con un verticale fittizio TLS (`tests/source_api_vertical_fixture.py`,
CA effimera generata nel test):

| Prova | Test |
|---|---|
| GW-A14 (SSRF): vettori nel percorso, nei token e nel riferimento, zero connessioni | `test_grammar_vectors_are_refused_before_any_connection`, `test_binding_reference_vectors_are_refused`, `test_tokens_are_opaque_query_values_that_never_change_path_or_host` |
| GW-A14: DNS fuori CIDR, rebinding, loopback, metadata, IPv6 e IPv4-mapped | `test_dns_answers_outside_the_binding_networks_never_connect`, `test_ipv4_mapped_answer_of_an_allowed_address_never_connects` |
| TLS con SNI e nome verificato | `test_tls_name_verification_and_trust_anchor_are_enforced`, `test_tls_name_is_verified_even_with_the_trusted_ca` |
| Ammissione e risposta identica senza enumerazione, segreto non letto | `test_not_allowed_is_identical_for_unknown_inactive_foreign_and_out_of_scope`, `test_receipt_failures_stop_before_grammar_and_transport` |
| GW-01 (PULL `fetch`), tabella errori riga per riga, un solo tentativo | `test_source_errors_map_to_the_typed_table`, `test_items_cursor_reaches_registered_origin_with_bearer_and_bytes_unchanged` |
| Limiti: scadenza, pagina al limite e oltre (anche chunked), risposta incompleta | `test_deadline_bounds_a_slow_source`, `test_page_at_the_limit_passes_and_limit_plus_one_fails_without_partial_body`, `test_incomplete_response_is_unavailable` |
| Frequenza e concorrenza per binding | `test_rate_limit_per_binding_with_retry_after`, `test_concurrency_limit_is_shared_across_workers` |
| Rotazione e revoca | `test_registry_rotation_and_revocation_apply_to_the_next_request` |
| Segreti e log | `test_forked_server_serves_and_logs_only_code_duration_bytes_and_correlation`, `test_sentinel_bearer_never_appears_in_errors` |

Restano aperti, per il 61f-b e per l'installazione: la ricevuta coniata da APISIX con la prova di
parità in CI, la prova sul percorso reale con APISIX e IAM di prova, GW-A13 e GW-A16 (egress di rete
effettivo) e la custodia dei segreti in esercizio.
