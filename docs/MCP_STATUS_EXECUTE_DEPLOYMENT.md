# MCP system status: deploy del profilo execute con delega

## Problema verificato e perimetro

Il 19 settembre 2026 il server MCP aggiornato a `8c4046a` e la policy v6
pubblicata hanno raggiunto il dispatch. La risposta `STATUS_UNAVAILABLE` 404
corrispondeva all'assenza in APISIX di POST
`/internal/capabilities/v1/execute`, l'endpoint configurato nel client MCP.
La presenza delle rotte legacy `/execute/urban.object.related_search` non
copriva quel percorso.

Questo incremento materializza **solo `ouf.system.status`**, READ, HUMAN,
argomenti `{}`. Il backend è
`http://ouf-mcp-server:8080/api/internal/v1/mcp/operations/status`.
Non inoltra a `/mcp` e non apre un proxy generico per il resto del catalogo.
La proiezione dei sei campi PUBLIC_OPERATIONAL appartiene all'owner MCP.

Companion obbligatorio: [MCP PR29](https://github.com/GioNob/ouf-mcp-server/pull/29).
Non installare separatamente. Il nuovo MCP nega invocazioni senza prova di delega.

## Contratto e riferimenti PET

PET MCP §37 e §83: token umano non persistito, identità workload distinta,
delega verificabile con audience e rivalutazione fine-grained nell'owner.
PET Gateway T29.1: controlli coarse e routing, senza mascheramento dei dati owner.

1. `/mcp` verifica OIDC (firma/JWKS, TLS, audience, scope), elimina gli header
   esterni di identità e produce `X-OUF-Delegation` firmato HMAC-SHA256.
2. La prova contiene issuer, audience Gateway, workload destinatario, soggetto,
   tenant, attore, client iniziatore, scope, ACR, iat/exp e purpose/versione.
   Scade dopo al massimo 60 secondi, mai oltre il JWT originale.
3. MCP la mantiene nella singola richiesta, esclusa da JSON/audit/ammissione,
   e la inoltra come header con il bearer **workload**. Non riceve la chiave.
4. Execute verifica OIDC del workload, issuer/azp/attore SERVICE, tenant,
   firma/scadenza della prova, scope `operations.status.read`, identità
   nell'envelope e coerenza degli identificativi di governance negli header.
5. Header owner ricostruiti; nessun bearer, cookie o prova inoltrato. Owner
   rivaluta la policy e confronta decisionRef, tenant, resourceType e dettaglio
   pubblico prima della lettura.

La prova è riutilizzabile dal workload autorizzato entro la breve durata:
attesta un'identità, non è una prova monouso dell'ammissione né un grant.
MCP mantiene ammissione/budget/idempotenza e l'owner controlla i grant correnti.
Nell'envelope il campo storico `ServicePrincipalID` identifica il client
iniziatore; negli header owner identifica il workload verificato.

Il trust degli header owner richiede che l'API interna sia raggiungibile
soltanto dal Gateway secondo l'isolamento di rete del deployment. Non esporre
la porta MCP 8080 sull'host e non aggiungere una rotta pubblica diretta owner.

## Preparazione sul server SSH

Prima di modificare: conservare inspect dei container, immagini precedenti,
configurazione APISIX e snapshot delle rotte; i file con segreti devono restare
root-only. Interrompere le nuove invocazioni durante il cambio coordinato.
Le tre scritture Admin API **non sono una transazione atomica**: lo script
ripristina le rotte già toccate se una scrittura/readback/verifica fallisce.

Usare il checkout Gateway che contiene questa modifica e una proiezione di
installazione **corrente e verificata**, non `tests/fixtures`. Non riutilizzare
il vecchio runtime compilato: serve anche la policy con attore canonico HUMAN.
Esempio, impostando `OUF_INSTALLATION_PROJECTION` sul file reale:

```bash
cd /opt/ouf/gateway
python3 tools/compile_config.py --output generated/apisix-routes.json
sudo python3 tools/apply_installation_projection.py \
  --compiled generated/apisix-routes.json \
  --projection "$OUF_INSTALLATION_PROJECTION" \
  --output /run/ouf-status-runtime.json
sudo python3 -m tools.materialize_apisix_execute_runtime \
  --runtime /run/ouf-status-runtime.json \
  --oidc-client-secret-ref '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET' \
  --delegation-key-env OUF_GATEWAY_DELEGATION_KEY \
  --output /run/ouf-status-routes.json
```

La materializzazione non contiene credenziali; non sostituisce l'attivazione
InstallationConfiguration e non modifica la policy Authorization.

## Chiave dedicata solo Gateway

Generare una volta una chiave casuale di 32 byte rappresentata da 64 cifre hex.
Non usare il secret OIDC o la fingerprint key MCP. Il seguente comando crea
un file env nuovo con modo 0600 e rifiuta di sovrascriverlo:

```bash
sudo python3 - <<'PY'
import os, secrets
path='/opt/ouf/secrets/gateway-delegation.env'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:
    f.write('OUF_GATEWAY_DELEGATION_KEY='+secrets.token_hex(32)+'\n')
print('GATEWAY_DELEGATION_ENV_CREATED')
PY
```

Integrare quel file nella definizione di avvio **esistente** di `ouf-apisix`
(`--env-file /opt/ouf/secrets/gateway-delegation.env` se gestito con Docker run).
Preservare tutte le reti, mount, env, restrizioni, restart e immagine correnti.
`docker restart` da solo non aggiunge una nuova variabile: serve ricreare il
container dalla definizione verificata. Non stampare `docker inspect` completo
né il contenuto del file env nella chat.

Nella configurazione APISIX aggiungere il nome alla lista esistente, senza
sostituire altre impostazioni:

```yaml
nginx_config:
  envs:
    - OUF_GATEWAY_DELEGATION_KEY
```

La variabile deve essere disponibile anche ai worker Nginx. Lo script di
deploy verifica sia l'env del container sia la direttiva `env` nel nginx.conf
generato. Chiave assente o formato errato causa diniego 503. Niente fallback.
Tutte le repliche Gateway devono condividere questa chiave; una rotazione
coordinata invalida le prove in corso per al massimo 60 secondi.

## Installazione e rollback rotte

Dopo aver predisposto Gateway e immagine MCP companion durante la finestra
coordinata, eseguire:

```bash
sudo python3 ops/apisix/deploy_status_execute.py \
  --materialization /run/ouf-status-routes.json \
  --admin-key /opt/ouf/secrets/apisix-admin-key \
  --container ouf-apisix
```

Admin API resta su localhost nel network namespace APISIX. Il secret passa
tramite file privato, mai argv. Lo script salva prima tutte e tre le rotte,
aggiorna e rilegge il contenuto, controlla metadata 200 e accessi senza bearer
401 a `/mcp` e `/execute`. Stampa `BACKUP=/run/ouf-status-routes-.../previous.json`.
La cartella contiene il rollback e risposte Admin: custodirla; `/run` non
sopravvive al reboot. L'header con la chiave admin viene rimosso all'uscita.

Rollback esplicito, usando **il percorso stampato dal deploy**:

```bash
sudo python3 ops/apisix/deploy_status_execute.py \
  --restore "$OUF_ROUTES_BACKUP" \
  --admin-key /opt/ouf/secrets/apisix-admin-key \
  --container ouf-apisix
```

Ripristinare anche l'immagine MCP precedente se si abbandona il nuovo
contratto di delega. Il rollback delle rotte non annulla policy pubblicate.

## Verifiche e diagnosi

- Confermare bundle v6 caricato senza errore `blank or invalid grant constraint`.
- Grant di prova `giovanni-chatgpt`: scadenza **2026-09-20 05:27:26 UTC**.
- Keycloak: client `ouf-chatgpt`, scope `mcp.connect` e `operations.status.read`
  presenti nel token; tenant `ouf-lab`, attore `HUMAN`, audience Gateway.
- Riconnettere ChatGPT come `giovanni-chatgpt`, chiamare `ouf_system_status`
  senza argomenti. Conservare il risultato reale: i controlli senza token
  provano il diniego, non il successo della capability.
- 404: rotta assente o backend non aggiornato; 401: OIDC; 403: delega,
  scope/identità/policy; 409: riferimenti di governance incoerenti; 503:
  chiave assente o bundle/provider non disponibile. Non cancellare i controlli
  per trasformare questi errori in un risultato fittizio.

Test: `bash scripts/verify.sh`; gate CI obbligatorio
`OUF_APISIX_LIVE_TEST=1 python3 -m pytest -q tests/test_execute_apisix_live.py`.
Quest'ultimo avvia APISIX 3.18.0 con JWT/JWKS sintetici e backend locale CI:
verifica firma OIDC, prova emessa, dispatch, sanitizzazione header e dinieghi.
La fixture usa HTTP soltanto in CI; la materializzazione produzione conserva
HTTPS discovery e `ssl_verify: true`. Le regex dello schema sono compatibili
anche col validatore effettivo APISIX, non solo con jsonschema Python.

## Collaudo del 19 settembre: permessi, virgolette e ripristino

### File montato leggibile dall'utente reale

L'immagine in esercizio avvia APISIX come `apisix`, UID/GID **636:636**.
Una nuova configurazione YAML creata con `umask 077` risultava root:root
0600: il container si avviava e terminava con `Permission denied` sul mount
`/usr/local/apisix/conf/config.yaml`. Questo errore non riguarda la chiave
OIDC o il nuovo secret di delega.

Distinguere i file: `gateway-delegation.env` resta root-only perché viene
letto dal processo di provisioning; il YAML montato deve essere leggibile
dall'utente del processo APISIX. Prima dello switch, copiare owner e modo
dalla configurazione funzionante e provare una lettura con l'utente reale,
senza mostrare il contenuto e senza avviare il servizio:

```bash
sudo chown --reference=/opt/ouf/secrets/apisix-config.yaml /opt/ouf/secrets/apisix-config-delegation.yaml
sudo chmod --reference=/opt/ouf/secrets/apisix-config.yaml /opt/ouf/secrets/apisix-config-delegation.yaml
sudo docker exec ouf-apisix id
sudo docker run --rm --pull=never --network none \
  --user apisix \
  --mount type=bind,src=/opt/ouf/secrets/apisix-config-delegation.yaml,dst=/tmp/config.yaml,readonly \
  --entrypoint /bin/sh apache/apisix:3.18.0-debian \
  -c 'if cat /tmp/config.yaml >/dev/null; then echo CONFIG_READ_OK; else exit 1; fi'
```

Il nome utente è quello verificato in questa installazione: su un'altra
installazione ricavarlo dall'inspect ed eseguire la prova con quell'utente.
Non usare `chmod 777`, non eseguire il servizio come root per aggirare il
problema e non estendere i permessi del file env contenente la chiave.

### La direttiva generata contiene virgolette

Nginx è stato generato con:

```nginx
env "OUF_GATEWAY_DELEGATION_KEY";
```

È una direttiva valida. Il primo controllo cercava soltanto il nome senza
virgolette e ha causato un secondo rollback benché APISIX rispondesse già
200 alla lettura del bundle. Lo script ora accetta entrambi i formati, con
o senza virgolette bilanciate, e ha test di regressione. Non serve cambiare
la configurazione o rigenerare la chiave.

Un `EXIT_CODE=0` dopo lo switch fallito può essere lo stop ordinato del
rollback. Non prova che APISIX non sia mai partito. Registrare separatamente
la fase fallita, l'esito della lettura nginx.conf, il codice di uscita curl e
il codice HTTP. In caso di errore, leggere log recenti con i valori delle
variabili sensibili oscurati; mai stampare inspect completo o configurazioni.

### Sequenza osservata e checkpoint operativo

- Backup precedente APISIX: `/run/ouf-apisix-backup-izejp444/inspect.json` e
  `config.yaml`; file privati e temporanei, persi al reboot.
- Reti da conservare: `ouf-backend` e `ouf-gateway-control`; NetworkMode
  `ouf-gateway-control`, restart `unless-stopped`, nessuna porta pubblicata.
- Nuovo mount: `/opt/ouf/secrets/apisix-config-delegation.yaml` sullo stesso
  percorso interno, read-only. Credenziali preesistenti conservate.
- Sostitutivo creato inizialmente fermo, ID breve `52383313eccf`.
- Primo rollback per permessi YAML; secondo per controllo env non compatibile
  con virgolette. Entrambi hanno riavviato il container precedente.
- Dopo la correzione, output osservato `APISIX_STARTED_WITH_DELEGATION_KEY`,
  `MCP_UNAUTHENTICATED_HTTP=401`; precedente conservato fermo come
  `ouf-apisix-rollback-before-delegation`.
- Immagine MCP `ouf-mcp:340cbc0` costruita con successo, runtime derivato da
  `ouf-mcp:8c4046a` e binario compilato con Go 1.25.13. Il build riuscito
  **non** implica sostituzione del container MCP: in questo checkpoint
  nuove rotte e sostituzione MCP restano da eseguire.

Non ripetere creazione della chiave o del container dopo un rollback:
verificare gli ID conservati e correggere la causa prima del nuovo switch.
Non ripetere indefinitamente lo switch sulla base di un generico
`SWITCH_FAILED`: conservare il motivo del fallimento senza esporre segreti.
Il 401 senza bearer verifica soltanto il diniego; la chiamata autenticata
`ouf_system_status` rimane il collaudo finale da eseguire dopo il deploy completo.

### Collaudo autenticato completato — 19 settembre 2026

Il checkpoint precedente è stato completato: rotte installate e container MCP
sostituito, poi chiamata reale dello strumento `ouf_system_status` riuscita.

- Gateway aggiornato a `9101c16`; materializzazione in
  `/run/ouf-status-deploy-aGbAjk/routes.json`.
- Deploy rotte: `APISIX_STATUS_ROUTES_INSTALLED`; backup precedente in
  `/run/ouf-status-routes-l2jni47b/previous.json`.
- Backup della sostituzione MCP: `/run/ouf-mcp-delegation-qy_pi9og`.
- Container corrente `ouf-mcp`, immagine `ouf-mcp:340cbc0`;
  `MCP_READY_HTTP=204`. Precedente conservato fermo come
  `ouf-mcp-rollback-8c4046a`.
- APISIX precedente conservato come `ouf-apisix-rollback-before-delegation`.

La readiness 204 è stata seguita dal collaudo autenticato effettivo, con
`ouf_system_status({})`, che ha restituito `isError: false` e questo contenuto:

```json
{
  "module": "MCP",
  "status": "HEALTHY",
  "actionRequired": false,
  "partial": false,
  "visibilityClass": "PUBLIC_OPERATIONAL",
  "redacted": true
}
```

Questo verifica il percorso ChatGPT → MCP → Gateway → owner per lo stato
pubblico del modulo MCP. Non certifica lo stato di tutti gli altri moduli
né abilita le altre capability del catalogo. La chiamata è una lettura di
stato; i normali meccanismi interni di audit restano attivi.

Il grant di prova `grant-system-status-giovanni-chatgpt-v6` nel bundle
pubblicato versione 6 scade il **20 settembre 2026 alle 05:27:26 UTC**.
Un successivo rinnovo deve seguire il flusso amministrativo previsto;
il collaudo non ne modifica la durata. I backup sotto `/run` sono temporanei
e non sopravvivono al riavvio della macchina.

### Ruoli IAM per l'accesso ordinario

L'abilitazione ordinaria associa ruoli IAM a capability OUF, non rinnova grant
personali al login. Il profilo di delega trasporta il claim canonico
`externalRoleRefs` soltanto dopo verifica OIDC. I ruoli vengono validati,
ordinati e inclusi nella firma, poi ricostruiti nell'header privato
`X-OUF-External-Role-Refs` per MCP e owner. Header del client e body del tool
non costituiscono autorità. Claim assente significa zero ruoli.

Richiede il consumer MCP che legge questo contesto e una policy di ruolo
esplicita. Limiti: 32 riferimenti distinti di 1–128 caratteri ASCII
`A-Z a-z 0-9 _ : . / -`. La delega mantiene TTL massimo 60 secondi e scadenza
entro il JWT originario. La rimozione IAM del ruolo è effettiva sui nuovi
token; la revoca policy segue il refresh e la max-staleness del consumer.

La configurazione, l'ordine di deploy, i test di revoca e il perimetro
dell'amministrazione conversazionale sono nella
[guida MCP per ruoli](https://github.com/GioNob/ouf-mcp-server/blob/main/docs/ACCESSO_PER_RUOLI_E_AMMINISTRAZIONE.md).
Il nuovo codice non pubblica grant, non gestisce utenti IAM e non apre
l'execute a capability ulteriori rispetto a `ouf.system.status`.
