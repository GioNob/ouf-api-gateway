# Incidenti del rinnovo dei mandati nel collector del gateway (sprint-01, task-31)

Riferimenti: D-018, D-030 (`_handoff/decisions.md`), contratto dello stato in `_handoff/sprint-01/task-28.md` §E.

## Cosa fa
Il job di rinnovo automatico dei mandati (`ouf-deploy`, task-28) pubblica sul VPS uno stato a schema chiuso, `/var/lib/ouf-authority-mandate-renewal/status.json`. La modalità `authority-mandates` del collector legge lo stato e lo trasforma in incidenti nello store operativo esistente del gateway, gli stessi esposti da `ouf.gateway.operations.incidents`. Non ci sono route, schemi o moduli nuovi.

```
python3 -m tools.gateway_operational_collector authority-mandates \
  --store /var/lib/ouf-gateway-operations/gateway-operations.sqlite \
  --status /var/lib/ouf-authority-mandate-renewal/status.json
```

Exit code: 0 se nessun incidente `authority:mandates:*` è aperto, 2 altrimenti (come la sonda etcd).

## Lettura dello stato
- Path assoluto. Gli antenati sono di root e non scrivibili da gruppo e altri.
- File regolare root:root `0600`, un solo link, al massimo 16 KiB, aperto con `O_NOFOLLOW`.
- JSON ASCII, chiavi duplicate e `NaN` rifiutati, campi esatti `ouf.semantic-mandate-renewal-status.v1`. `reasonCode` è presente se e solo se `outcome` è `BLOCKED`.
- Un `checkedAt` più di 5 minuti nel futuro rende lo stato illeggibile.
- Il contenuto dello stato non entra mai negli incidenti né nell'output: entra solo il `reasonCode`, che è un codice pubblico `[A-Z0-9_]`.

## Regole
`endpoint_ref` vale sempre `authority://mandates/renewal`, `visibility_class` vale `TENANT_OPERATIONAL` (visibile all'attore HUMAN, come etcd) e `action_required` vale `true`.

| dedup_key | Condizione | event_type | severity | error_code |
|---|---|---|---|---|
| `authority:mandates:blocked` | `outcome == BLOCKED` | `AUTHORITY_MANDATE_RENEWAL_BLOCKED` | CRITICAL | `reasonCode` |
| `authority:mandates:silent` | `now − checkedAt > 2 giorni` | `AUTHORITY_MANDATE_RENEWAL_SILENT` | CRITICAL | `STATUS_STALE` |
| `authority:mandates:near-expiry` | min(`earliestExpiresAt`) − now < 15 giorni | `AUTHORITY_MANDATE_NEAR_EXPIRY` | CRITICAL | `MANDATE_NEAR_EXPIRY` |
| `authority:mandates:status-unavailable` | stato assente o illeggibile | `AUTHORITY_MANDATE_STATUS_UNAVAILABLE` | ERROR | `AUTHORITY_MANDATE_STATUS_MISSING` / `…_UNREADABLE` |

Una regola che non vale più risolve il proprio incidente. Se lo stato non è verificabile, le altre tre regole conservano lo stato precedente, perché non sono valutabili.

## Unità
`ops/systemd/ouf-gateway-authority-mandates-probe.{service,timer}`:
- sono costruite sul modello della sonda etcd, con un timer ogni 15 minuti;
- la directory di stato del job è montata in sola lettura e marcata `-`, cioè opzionale.

Finché il job non è installato, lo stato manca e l'incidente `STATUS_UNAVAILABLE` (`AUTHORITY_MANDATE_STATUS_MISSING`) resta aperto. È voluto: il rinnovo automatico non è ancora operativo.

## Non incluso
- **Heartbeat della fonte:** `mark_collector_observed` non è usato. Lo store accetta solo `APISIX`/`ETCD` e la freshness è esposta solo per le fonti richieste. Il silenzio del job è coperto dalla regola `silent`.
- **Deploy sul VPS:** si pianifica con l'umano, dopo la review.
