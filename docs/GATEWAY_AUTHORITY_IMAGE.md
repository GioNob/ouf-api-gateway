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
| `OUF_HOST_PROCESSES` | Numero di worker, da 1 a 64. |
| `OUF_HOST_THREADS` | Thread per worker, da 1 a 512. |
| `OUF_HOST_CONNECTIONS` | Totale connessioni accettabili nell’istanza, da 1 a 32768. Gunicorn assegna lo stesso limite a ogni worker, quindi il totale deve essere divisibile per il numero di processi. |
| `OUF_ANALYSIS_CONFIG` | Per `authority`, percorso del JSON privato `ouf.analysis.installation.v1`. Include `store`, `manifestFile`, endpoint con trust e credenziali di ruolo e il nome della variabile `delegationKeyEnv`. |
| `OUF_KEYCLOAK_DECISIONS_CONFIG` | Per `iam-adapter`, percorso del JSON privato con `store`, `profileFile`, `gatewayTlsPrincipal`, configurazione del resource server e riferimento `secretEnv`. |

Indirizzo, porta e dimensionamento sono espliciti. Per l’autorità i tre limiti devono coincidere con i valori effettivi di `capacity.processes`, `capacity.threadsPerProcess` e `capacity.instanceConnections`, inclusi i default 55g per i campi omessi. Il processo termina con `AUTHORITY_HOSTING_MISMATCH` se i limiti differiscono o se manca la riserva per controllo, relay e osservazione.

Al client dell’adattatore occorre un certificato con uso client TLS emesso nel dominio di fiducia configurato. Il valore scelto dal certificato del Gateway deve coincidere esattamente con `gatewayTlsPrincipal` e rispettare la grammatica del contratto 55h. Il middleware imposta `SSL_CLIENT_VERIFY` e `REMOTE_USER` a partire dal socket TLS verificato. Scarta i campi di identità forniti via HTTP. Un’identità assente o ambigua lascia entrambe le variabili WSGI assenti. Gli access log sono disabilitati. [Contratto del mandato](../contracts/analysis-mandate-v1.md) · [Contratto dell’adattatore](../contracts/keycloak-analysis-verifier.md)

## Volumi e registro D-065

Eseguire con rootfs in sola lettura, UID/GID **65532:65532** e `/tmp` scrivibile (tmpfs per i file temporanei del worker). Il percorso di ciascuno store è il campo `store` del JSON del ruolo. Montare in lettura/scrittura l’intera directory persistente, con supporto ai lock SQLite e ai file journal, WAL e SHM.

| Ruolo | Stato da predisporre e preservare |
|---|---|
| Autorità | Database operativo Gateway esistente con la tabella `gateway_operational_incident`. La factory apre il file in modalità `rw` e inizializza le tabelle mandato. Ripristinare insieme mandati, comandi, tentativi, fence ed evidenze. |
| Adattatore | File SQLite privato già esistente, accessibile a tutti i worker della stessa installazione. La factory inizializza le tabelle di quota e di evidenza monouso. Preservare le finestre di quota e lo stato di consumo. |

Montare configurazioni, manifest, profilo IAM, CA, catene e chiavi in sola lettura per la generazione del processo. Iniettare i valori effettivi di `delegationKeyEnv` e `secretEnv` attraverso la custodia del rispettivo ruolo. Alla rotazione sostituire i processi con una generazione configurata e verificata. Prima del ripristino di uno store escludere i worker precedenti.

Il catalogo del Gateway censisce i due store, i due JSON, il manifest, il profilo IAM e i riferimenti TLS per ruolo. Nel registro privato associare alla revisione i volumi e le procedure di backup/ripristino, i binding e la capacità, il digest del manifest, il campo identità e il principal atteso, le versioni delle CA, delle catene e dei riferimenti custoditi alle chiavi. Includere i riferimenti mTLS in uscita degli endpoint configurati. [Catalogo runtime](../config/runtime-catalog-v1.yaml)

## Lettura delle metriche

Eseguire `GET /metrics` senza query sul listener privato dell’autorità. Ad esempio, con `AUTHORITY_URL` impostata all’origine HTTPS e `SERVER_CA` al trust del chiamante:

```sh
curl --fail --silent --show-error --tlsv1.3 --cacert "$SERVER_CA" "$AUTHORITY_URL/metrics"
```

Con mTLS aggiungere `--cert "$SCRAPER_CERT" --key "$SCRAPER_KEY"`. La risposta in formato Prometheus distingue `data`, `control` e `relay`. Confrontare `gateway_inflight_requests` con `gateway_analysis_slot_limit` per classe e leggere il tasso di crescita di `gateway_analysis_pressure_refusals_total`. Le metriche sono locali al worker che ha risposto. Con più worker lo scrape ripetuto sul bind condiviso non identifica stabilmente i processi. Per osservare ciascun processo, predisporre target distinti, ad esempio istanze con un solo worker e dimensionamento coerente. Il limite d’istanza si legge una sola volta. Il servizio espone le metriche anche con `dispatchEnabled: false`.

## Artefatto e rilascio

Il job `authority-image` esegue i test offline, costruisce la revisione del checkout e prova entrambi i comandi con rootfs in sola lettura. Lo smoke GW-58D-06 genera una CA effimera, verifica il rifiuto di TLS 1.2 e dell’hosting incoerente, poi distingue il Gateway autenticato da un altro client della stessa CA e da una connessione senza certificato. Per il Gateway, il corpo di prova `{}` raggiunge la validazione e produce HTTP 400. Per l’altro principal, la stessa richiesta produce HTTP 403.

Dopo lo smoke il job carica `gateway-authority-image-<run_id>` con `image.tar.gz`, `image-id.txt` (ID Docker `sha256` della configurazione immagine), `source-commit.txt` e `SHA256SUMS`. Verificare con `sha256sum -c SHA256SUMS`, caricare con `docker load -i image.tar.gz` e confrontare l’ID e la label OCI di revisione con i due file. Il digest di un manifest di registry si rileva alla pubblicazione.

Al task di rilascio in `ouf-deploy` competono selezione della run qualificata, trasporto dell’artefatto, verifica di digest e provenienza, materializzazione dei volumi e dei segreti, binding privati e avvio della revisione approvata. La qualifica d’installazione comprende APISIX, identità effettive, policy del realm, raccolta metriche e ripristino dei due store.
