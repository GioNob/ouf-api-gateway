# Collector: provider R3 e finestre di fiducia

Sprint-01 task-47, D-039, R-008 e R-009. Le nuove sonde copiano nello store
operativo del gateway gli stati prodotti dai job di `ouf-deploy`. Gli incidenti
sono disponibili attraverso MCP esistente; questo incremento non installa i job.

```sh
python3 -m tools.gateway_operational_collector semantic-provider \
  --status /var/lib/ouf-semantic-provider-health/status.json \
  --store /var/lib/ouf-gateway-operations/gateway-operations.sqlite
python3 -m tools.gateway_operational_collector trust-windows \
  --status /var/lib/ouf-trust-windows/status.json \
  --store /var/lib/ouf-gateway-operations/gateway-operations.sqlite
```

Entrambe restituiscono 0 senza incidenti attivi della propria modalità, 2 se ce
ne sono. Non modificano gli heartbeat APISIX/ETCD. Riassunti di apertura e chiusura
sono frasi inglesi fisse; negli `error_code` entrano solo codici pubblici validati.
Gli incidenti aperti hanno `TENANT_OPERATIONAL` e `action_required=true`.

## Contratto dei produttori

File regolare root:root `0600`, un solo link, massimo 16384 byte; percorso assoluto
senza `..`, antenati directory senza symlink, root e non scrivibili da gruppo/altri.
Apertura con `O_NOFOLLOW|O_NONBLOCK`. JSON ASCII, senza duplicati, NaN o Infinity;
campi esatti a ogni livello. La custodia POSIX richiede Linux.
`bool` non è accettato come intero. `CODE` è `[A-Z0-9_]{1,80}`.

Schema `ouf.semantic-provider-r3-health.v1`, campi obbligatori:

```text
schema, checkedAt: int,
head: {decision: OPERATE|STOP|UNPROVEN, sequence: int|null},
supervisor: {unitActive: bool, state: WAITING|ACTIVE|PARKED_RATE_LIMITED|STOPPED|FAILED|null,
             reason: CODE|null, updatedAt: int|null, activationsLastHour: int|null},
lease: {state: CODE|null, leaseAuthorized: bool|null},
roles: {adapter: ROLE, southbound: ROLE}, readError: CODE|null
ROLE = {epoch: int|null, state: CODE|null, failure: CODE|null, live: bool,
        previousState: CODE|null, dockerRunning: bool|null,
        denials: [{mode, reason: CODE, at: int}, ...]}  # massimo 4
```

`mode` ammette esclusivamente `authorize-create`, `record-created`, `cohort-ready`,
`prepare`, `cleanup`. Ogni lista `denials` descrive l'epoca corrente del ruolo;
se `epoch` è null non esiste un'epoca corrente e la lista non alimenta le regole.
Per «primo diniego» si usa l'ordine dei produttori nella lista, con `adapter`
prima di `southbound`. `previousState` non prova lo stato terminale corrente.

Schema `ouf.trust-window-status.v1`:

```text
schema, checkedAt: int,
windows: [{ref: slug, policySha256: hex64, expiresAt: int, liveConsumers: [slug, ...]}, ...]
```

Massimo 16 finestre con `ref` unici e 16 consumatori per finestra. Slug
`[a-z0-9-]{1,64}`, hash `[0-9a-fA-F]{64}`; tutti i campi sono obbligatori.

## Provider R3

Chiavi `semantic:r3:<regola>`, endpoint `semantic://provider/r3`.

| Regola | Apertura | Severità |
|---|---|---|
| stopped | Entrambi i ruoli con epoca corrente DELETED, dockerRunning false e nessun diniego corrente | WARNING |
| down | Non stopped; lease diverso da LEASE_READY, supervisore diverso da ACTIVE o ruolo non live | WARNING; CRITICAL dopo oltre 900 s di episodio |
| denial | Diniego corrente o supervisore PARKED_RATE_LIMITED | CRITICAL |
| supervisor | Unità inattiva, FAILED/STOPPED oppure updatedAt non nullo più vecchio di 600 s | CRITICAL |
| integrity | Testa UNPROVEN oppure reason AUTHORITY_REVOKED, CONFIGURATION_DRIFT o INTEGRITY_UNPROVEN | CRITICAL |
| status-unavailable | Stato non verificabile, readError non nullo o checkedAt oltre 300 s nel futuro | ERROR |
| silent | checkedAt più vecchio di 1200 s | CRITICAL |

Le prime quattro regole si valutano in OPERATE; STOP le chiude, UNPROVEN conserva
il loro stato precedente. `integrity` si valuta con qualunque testa. Un campo
`updatedAt` nullo non è una prova di anzianità. Gli eventi sono rispettivamente
`SEMANTIC_PROVIDER_R3_STOPPED`, `SEMANTIC_PROVIDER_R3_DOWN`,
`SEMANTIC_PROVIDER_R3_DENIAL_PERSISTENT`, `SEMANTIC_PROVIDER_R3_SUPERVISOR_DOWN`,
`SEMANTIC_PROVIDER_R3_INTEGRITY_UNPROVEN`, `SEMANTIC_PROVIDER_R3_STATUS_UNAVAILABLE`,
`SEMANTIC_PROVIDER_R3_SILENT`.

`down.error_code`: primo diniego corrente, prima failure non nulla dei ruoli,
supervisor.reason, infine R3_NOT_READY. L'escalation legge `first_seen_at` dal
risultato pubblico di `open_incident` e aggiorna lo stesso episodio tramite
la stessa API; dopo una chiusura il nuovo episodio riparte da WARNING.

## Finestre di fiducia

Chiavi `trust:window:<ref>`, endpoint `authority://trust-policy/<ref>`. Solo le
finestre con consumatori attivi aprono incidenti: meno di 45 giorni WARNING,
meno di 21 ERROR, meno di 7 CRITICAL (`TRUST_POLICY_NEAR_EXPIRY`); alla scadenza
compresa CRITICAL (`TRUST_POLICY_EXPIRED`). Le soglie sono strettamente inferiori.
La severità e il tipo cambiano nello stesso episodio. Rinnovo oltre soglia,
consumatori vuoti o finestra rimossa chiudono l'incidente.

`trust:windows:status-unavailable` (ERROR, `TRUST_WINDOWS_STATUS_UNAVAILABLE`) e
`trust:windows:silent` (oltre 48 h, CRITICAL, `TRUST_WINDOWS_SILENT`) usano endpoint
`authority://trust-policy/windows`. Anche qui oltre 300 s nel futuro lo stato
non è verificabile. In entrambe le modalità lo stato non verificabile conserva
**tutti gli altri incidenti**, inclusi quelli di finestre apparentemente rimosse.
Uno stato vecchio ma valido resta valutabile e apre anche `silent`.

## Mandati e unità di esempio

In `authority-mandates` si aggiunge `authority:mandates:overdue`, evento
`AUTHORITY_MANDATE_RENEWAL_OVERDUE`, ERROR, quando la scadenza più vicina dista
meno di 28 giorni (2419200 s) e outcome non è BLOCKED. Può coesistere con
`near-expiry`; BLOCKED chiude overdue. Le regole precedenti restano invariate.

Le unità `ops/systemd/ouf-gateway-semantic-provider-probe.{service,timer}` e
`ouf-gateway-trust-windows-probe.{service,timer}` eseguono le sonde ogni 5 minuti
e ogni ora. Con `ProtectSystem=strict` lo stato è in sola lettura e la scrittura
persistente è limitata alla directory dello store, inclusi WAL/SHM SQLite.
Il percorso di stato opzionale consente di registrare anche lo stato mancante.
`SuccessExitStatus=2` considera la presenza di incidenti un esito operativo
previsto, senza segnare come fallita l'unità. Deploy e verifica sul VPS restano
fuori da questo task.
