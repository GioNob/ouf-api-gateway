# Report sprint-03 / task-58i-c — Correzioni della review Gateway 58i-b

## Esito

`PARTIAL` — Entrambi i difetti di avvio sono corretti e verificati nel working tree. Restano aperte la qualifica CI della nuova revisione e la registrazione nella matrice D-082 dell’handoff.

## Sintesi

Autorità e adattatore condividono il budget di avvio tra i processi che aprono lo stesso store per lo stesso ruolo. Un lettore può mantenere aperta la propria transazione durante l’avvio su schema completo. Le prove riproducono entrambi i difetti sulla base della PR.

| Difetto chiuso | Correzione (file:riga) | Prova di regressione (file:riga) |
|---|---|---|
| Un riavvio concedeva altri quattro tentativi sullo stesso incidente. | `tools/analysis_schema.py:59` recupera il budget e `tools/analysis_schema.py:85` addebita il tentativo prima di aprire lo store. | GW-58IC-01 — `tests/test_authority_installable.py:220` verifica crash, due processi concorrenti e zero aperture dopo l’esaurimento. `tests/test_authority_installable.py:266` verifica la scadenza originale dopo un’ora simulata. |
| Un lettore in rollback journal impediva l’avvio sullo schema già inizializzato. | `tools/analysis_schema.py:39` termina la verifica in lettura sullo schema completo. Entrambi i ruoli usano questo percorso in `tools/analysis_store.py:35` e `tools/iam_keycloak_decisions.py:59`. | GW-58IC-02 — `tests/test_authority_installable.py:285` verifica 204 durante e dopo la lettura. `tests/test_authority_installable.py:304` verifica la creazione di un indice mancante e il rifiuto di un oggetto incompatibile. |

## Branch e commit

- Branch `sprint-03/task-58i-authority-installable`, PR #127.
- HEAD `4e0a6b91b4a02f26ca27b2e1935dc5964e8fc2dc`. Modifiche non committate come richiesto da D-001.

## File modificati

| File | Tipo (A/M/D) | Descrizione |
|---|---|---|
| `tools/analysis_schema.py` | A | Budget persistente, coordinamento dei worker, verifica dello schema e DDL atomico. |
| `tools/analysis_store.py` | M | Inizializzazione dello store mandato con verifica della tabella operativa preesistente. |
| `tools/iam_keycloak_decisions.py` | M | Applicazione dello stesso profilo allo schema privato dell’adattatore. |
| `tests/test_authority_installable.py` | M | Regressioni GW-58IC e adeguamento della prova GW-58IB-02 alle scadenze persistenti. |
| `docs/GATEWAY_AUTHORITY_IMAGE.md` | M | Inventario, backup, diagnosi dei 503 e prove per i due ruoli. |
| `config/runtime-catalog-v1.yaml` | M | Censimento del database ausiliario associato ai due store. |
| `report-58i-c.md` | A | Esiti locali e ricevute per la matrice. |

## Comandi eseguiti

| Comando | Esito |
|---|---|
| `git archive --format=zip HEAD tools contracts deploy/authority tests` e `python -m unittest -q` sui tre casi di riavvio, scadenza e lettore attivo | Copia temporanea di `4e0a6b9` con i test nuovi. Sei fallimenti attesi, tre per ruolo. Il riavvio ripartiva, la scadenza veniva rinnovata e il lettore causava 503. |
| `python -m unittest -q tests.test_authority_host tests.test_authority_installable tests.test_analysis_mandate tests.test_analysis_capacity tests.test_iam_keycloak_decisions` | Python 3.12.14 su Windows. 56 test, 55 superati e una prova FIFO POSIX saltata. |
| `python -m compileall -q tools/analysis_schema.py tools/analysis_store.py tools/iam_keycloak_decisions.py tests/test_authority_installable.py`, `bash -n deploy/authority/smoke.sh`, `git diff --check` | Superati. |
| `python -m pytest --version`, `docker version`, `wsl -l -q` | Nel runtime locale manca pytest. Accesso negato al motore Docker e a WSL. Suite completa su `python:3.13-slim` e smoke della nuova revisione da qualificare in CI. |

## Criteri di accettazione

- [x] GW-58IC-01. Contatore, prossimo tentativo e scadenza sono condivisi per store e ruolo. Dopo l’esaurimento, il riavvio resta in 503 anche a lock rilasciato.
- [x] GW-58IC-02. Entrambe le factory si avviano con un lettore in modalità `DELETE`, preservando la scrittura reversibile della readiness.
- [x] D-058 e D-065. Solo dati sintetici nelle prove. Il percorso del database ausiliario deriva dallo store. Inventario e ripristino sono descritti in `config/runtime-catalog-v1.yaml:51` e `docs/GATEWAY_AUTHORITY_IMAGE.md:34`.
- [ ] D-082, GW-58IB. La review attesta la CI sul commit precedente. Le quattro righe sotto sono pronte per la matrice ufficiale in `_handoff/sprint-03/pet-matrix/`, esterna al repository autorizzato.
- [ ] D-082, GW-58IC. Manca la ricevuta del job `authority-image` sulla revisione che conterrà queste modifiche.

## Decisioni prese

Il budget risiede in `<store>.schema-boot.sqlite` perché un lock esclusivo può impedire anche la lettura del database principale. Il lock SQLite sul file ausiliario serializza gli avvii e resta acquisito durante la registrazione durevole del tentativo e la verifica dello schema. Entrambe le connessioni si chiudono prima del backoff. Il profilo v2 conserva i limiti numerici della 58i-b.

## Domande aperte

Nessuna.

## Note per il reviewer

Il budget esaurito richiede intervento HUMAN governato. Conservare la coppia di database anche durante il ripristino. Il rinnovo operativo del budget richiede una procedura autorizzata esterna alla factory.

Righe D-082 per la matrice ufficiale. Data, revisione ed esito provengono dalla review 58i-b.

| Prova | Data | Release | Esito e ricevuta |
|---|---|---|---|
| GW-58IB-01 | 2026-11-25 | `4e0a6b9` | Readiness reversibile e perdita/ripristino dei permessi della directory. [Job CI][job] · [Artefatto][artifact] |
| GW-58IB-02 | 2026-11-25 | `4e0a6b9` | Contesa e budget del singolo avvio. La persistenza tra processi è coperta da GW-58IC-01. [Job CI][job] · [Artefatto][artifact] |
| GW-58IB-03 | 2026-11-25 | `4e0a6b9` | Rifiuto dei principal coincidenti prima del bind. [Job CI][job] · [Artefatto][artifact] |
| GW-58IB-04 | 2026-11-25 | `4e0a6b9` | File regolari, limite di 4096 byte e FIFO senza writer. [Job CI][job] · [Artefatto][artifact] |

[job]: https://github.com/GioNob/ouf-api-gateway/actions/runs/45610073005/job/139190989139
[artifact]: https://github.com/GioNob/ouf-api-gateway/actions/runs/45610073005/artifacts/15019996330
