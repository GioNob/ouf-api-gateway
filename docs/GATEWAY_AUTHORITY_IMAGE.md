# Immagine Gateway per autorità del mandato e adattatore Keycloak

Avviare due container della stessa immagine qualificata, uno con l’argomento `authority` e uno con `iam-adapter`. Ogni container espone un solo listener TCP privato. Gunicorn termina TLS 1.3 e carica la factory WSGI nel worker `gthread`. Un comando assente, sconosciuto o seguito da altri argomenti termina con codice 2.

## Listener e profilo di hosting

| Variabile | Valore da materializzare nel container |
|---|---|
| `OUF_HOST_ADDRESS` | IP locale di bind (IPv6 senza parentesi) o nome DNS del listener privato. |
| `OUF_HOST_PORT` | Porta TCP, da 1 a 65535. Per l’autorità usare host e porta coerenti con `services.bindings/ports.ouf-gateway-analysis-mandates` del bundle e con il certificato verificato da APISIX. Per l’adattatore allineare entrambi gli URL privati del profilo IAM. |
| `OUF_HOST_CERT_FILE`, `OUF_HOST_KEY_FILE` | File PEM della catena server e della relativa chiave privata, leggibili dall’UID del servizio. Il certificato deve coprire il nome del servizio e l’uso server TLS. |
| `OUF_HOST_CLIENT_CA_FILE` | Bundle PEM delle CA autorizzate a emettere certificati client. Obbligatorio per l’adattatore. Per l’autorità la sua presenza attiva mTLS obbligatorio anche per APISIX e per lo scraper. |
| `OUF_HOST_IDENTITY_FIELD` | `subject-cn` (default) oppure `san-uri`. Seleziona rispettivamente un solo commonName nel soggetto o una sola URI nei SAN. |
| `OUF_HOST_PROBE_PRINCIPAL` | Identità esatta del certificato di sonda per la readiness su un listener mTLS. Usare un’identità dedicata, distinta dal client Gateway dell’adattatore. |
| `OUF_HOST_PROCESSES` | Numero di worker, da 1 a 64. |
| `OUF_HOST_THREADS` | Thread per worker, da 1 a 512. |
| `OUF_HOST_CONNECTIONS` | Totale connessioni accettabili nell’istanza, da 1 a 32768. Gunicorn assegna lo stesso limite a ogni worker, quindi il totale deve essere divisibile per il numero di processi. |
| `OUF_ANALYSIS_CONFIG` | Per `authority`, percorso del JSON privato `ouf.analysis.installation.v1`. Include `store`, `manifestFile`, endpoint con trust e credenziali di ruolo e uno tra `delegationKeyFile` e `delegationKeyEnv`. |
| `OUF_KEYCLOAK_DECISIONS_CONFIG` | Per `iam-adapter`, percorso del JSON privato con `store`, `profileFile`, `gatewayTlsPrincipal`, configurazione del resource server e uno tra `secretFile` e `secretEnv`. |

Indirizzo, porta e dimensionamento sono espliciti. Per l’autorità i tre limiti devono coincidere con i valori effettivi di `capacity.processes`, `capacity.threadsPerProcess` e `capacity.instanceConnections`, inclusi i default 55g per i campi omessi. Il processo termina con `AUTHORITY_HOSTING_MISMATCH` se i limiti differiscono o se manca la riserva per controllo, relay e osservazione.

Al client dell’adattatore occorre un certificato con uso client TLS emesso nel dominio di fiducia configurato. Il valore scelto dal certificato del Gateway deve coincidere esattamente con `gatewayTlsPrincipal` e rispettare la grammatica del contratto 55h. Il middleware imposta `SSL_CLIENT_VERIFY` e `REMOTE_USER` a partire dal socket TLS verificato. Scarta i campi di identità forniti via HTTP. Un’identità assente o ambigua lascia entrambe le variabili WSGI assenti. Gli access log sono disabilitati. [Contratto del mandato](../contracts/analysis-mandate-v1.md) · [Contratto dell’adattatore](../contracts/keycloak-analysis-verifier.md)

## Volumi e registro D-065

Eseguire con rootfs in sola lettura e UID/GID **65532:65532**. Il profilo di `module-install` deve montare `/tmp` come tmpfs scrivibile (`--tmpfs /tmp:rw,nosuid,nodev,noexec`). Gunicorn usa `worker_tmp_dir=/tmp`. Il tmpfs copre il `VOLUME ["/tmp"]` dell’immagine ed evita il volume anonimo che bloccherebbe il rilascio successivo (`IMAGE_VOLUME_UNCOVERED` al plan). Il percorso di ciascuno store è il campo `store` del JSON del ruolo. Montare in lettura/scrittura l’intera directory persistente, con supporto ai lock SQLite e ai file journal, WAL e SHM.

| Ruolo | Stato da predisporre e preservare |
|---|---|
| Autorità | Database operativo Gateway esistente con la tabella `gateway_operational_incident`. La factory apre il file in modalità `rw` e inizializza le tabelle mandato. Ripristinare insieme mandati, comandi, tentativi, fence ed evidenze. |
| Adattatore | File SQLite privato già esistente, accessibile a tutti i worker della stessa installazione. La factory inizializza le tabelle di quota e di evidenza monouso. Preservare le finestre di quota e lo stato di consumo. |

Montare configurazioni, manifest, profilo IAM, CA, catene e chiavi in sola lettura per la generazione del processo. Per l’installazione governata usare bind RO distinti per ruolo e indicare nel JSON il percorso interno, per esempio `"delegationKeyFile": "/credential/delegation"` e `"secretFile": "/credential/resource-server"`. Ogni worker legge la credenziale una volta all’avvio. Il file contiene una sola riga UTF-8 con terminatore facoltativo LF o CRLF. La delega usa i 64 caratteri esadecimali già previsti. L’adattatore accetta anche una mappa indicizzata dal `secretRef` del profilo approvato. Le configurazioni precedenti possono usare i riferimenti ENV. Alla rotazione sostituire i processi con una generazione configurata e verificata. Prima del ripristino di uno store escludere i worker precedenti.

Il catalogo del Gateway censisce i due store, i due JSON, il manifest, il profilo IAM e i riferimenti TLS per ruolo. Nel registro privato associare alla revisione i volumi e le procedure di backup/ripristino, i binding e la capacità, il digest del manifest, il campo identità e il principal atteso, le versioni delle CA, delle catene e dei riferimenti custoditi alle chiavi. Includere i riferimenti mTLS in uscita degli endpoint configurati. [Catalogo runtime](../config/runtime-catalog-v1.yaml)

Per D-065 registrare anche il profilo di installazione per modulo, il digest dei JSON, il riferimento custodito e la versione dei due file credenziale, il principal e i riferimenti TLS della sonda, la ricevuta del primo CID e il journal. Conservare la cattura dello store operativo condiviso prima del primo avvio dell’autorità.

## Readiness

Eseguire `GET /health/ready` senza query sul listener HTTPS privato del ruolo. Con mTLS presentare il certificato corrispondente a `OUF_HOST_PROBE_PRINCIPAL`. Un altro principal verificato riceve 403. L’assenza del certificato impedisce l’handshake.

Il 204 a corpo vuoto attesta l’avvio della factory con il profilo di hosting validato e l’accesso in scrittura allo store del ruolo. La sonda apre il file esistente in modalità `rw`, acquisisce `BEGIN IMMEDIATE`, verifica i permessi di scrittura senza cambiare righe e chiude con `ROLLBACK`. Funziona anche con `dispatchEnabled=false` e non chiama i peer. Un writer concorrente, uno store indisponibile o una configurazione applicativa invalida producono 503. Al rilascio del lock la sonda può tornare subito a 204. Se l’inizializzazione della factory fallisce, correggere la causa e avviare una nuova generazione. Gli errori del listener, del materiale TLS o del dimensionamento restano errori di avvio.

## Lettura delle metriche

Eseguire `GET /metrics` senza query sul listener privato dell’autorità. Ad esempio, con `AUTHORITY_URL` impostata all’origine HTTPS e `SERVER_CA` al trust del chiamante:

```sh
curl --fail --silent --show-error --tlsv1.3 --cacert "$SERVER_CA" "$AUTHORITY_URL/metrics"
```

Con mTLS aggiungere `--cert "$SCRAPER_CERT" --key "$SCRAPER_KEY"`. La risposta in formato Prometheus distingue `data`, `control` e `relay`. Confrontare `gateway_inflight_requests` con `gateway_analysis_slot_limit` per classe e leggere il tasso di crescita di `gateway_analysis_pressure_refusals_total`. Le metriche sono locali al worker che ha risposto. Con più worker lo scrape ripetuto sul bind condiviso non identifica stabilmente i processi. Per osservare ciascun processo, predisporre target distinti, ad esempio istanze con un solo worker e dimensionamento coerente. Il limite d’istanza si legge una sola volta. Il servizio espone le metriche anche con `dispatchEnabled: false`.

## Artefatto e rilascio

Il job `authority-image` esegue i test offline, costruisce la revisione del checkout e prova entrambi i comandi con rootfs in sola lettura. Lo smoke GW-58D-06 genera una CA effimera, verifica il rifiuto di TLS 1.2 e dell’hosting incoerente, poi distingue il Gateway autenticato da un altro client della stessa CA e da una connessione senza certificato. Per il Gateway, il corpo di prova `{}` raggiunge la validazione e produce HTTP 400. Per l’altro principal, la stessa richiesta produce HTTP 403.

| Prova D-082 | Risultato atteso |
|---|---|
| GW-58I-01 | Layout del pacchetto, provenienza, lunghezza e SHA-256 dell’archivio concordano con il contratto del consumatore. |
| GW-58I-02 | Ogni ruolo seleziona una sola fonte per la credenziale. File vuoti, illeggibili o su più righe bloccano l’avvio della factory. |
| GW-58I-03/04 | I due worker rispondono 204 con lo store disponibile, 503 per contesa, sola lettura o configurazione invalida. Sul listener mTLS il principal errato riceve 403. |
| GW-58I-05 | Lo smoke Docker prova TLS, identità della sonda, bind RO dei segreti, copertura tmpfs e assenza dei valori in `Config.Env`. Togliendo e ripristinando il permesso di scrittura sul DB, osserva 503 e poi 204. |

Dopo lo smoke il job carica un solo `gateway-authority-image-<run_id>` per `gateway-authority` e `gateway-iam-adapter`. Entrambi i profili usano il prefisso `gateway-authority-image-`, `imageName=gateway-authority` e `manifestSchema=ouf.gateway-authority-tested-image.v1`. Lo ZIP contiene esattamente `image.tar.gz`, `manifest.json` e `SHA256SUMS` alla radice. Il manifest lega repository, commit revisionato e testato, albero Git, run e tentativo, tag, ID Docker e revisione OCI al nome, dimensione e SHA-256 dell’archivio compresso. `sha256sum -c SHA256SUMS` verifica i byte dell’archivio. Il consumatore verifica anche il digest dello ZIP, la provenienza e l’identità dell’immagine. Il primo avvio usa `module-install` con l’argomento del ruolo. Gli aggiornamenti usano `module-release` con l’ID installato come predecessore.

Al task di rilascio in `ouf-deploy` competono selezione della run qualificata, trasporto dell’artefatto, verifica di digest e provenienza, materializzazione dei volumi e dei segreti, binding privati e avvio della revisione approvata. La qualifica d’installazione comprende APISIX, identità effettive, policy del realm, raccolta metriche e ripristino dei due store.
