# R4a — urban.object.search, prima tranche

Il contratto candidate collega `POST /internal/capabilities/v1/execute/urban.object.search` a `POST /api/udp/v1/objects/search` sul servizio UDP. Il payload è `{ "type": "<tipo canonico esatto>", "pageSize": 1..100, "cursor": "<opzionale>" }`. UDP riusa il serving con tenant, decisioni per oggetto/proprietà, proiezione minimizzata e cursore opaco. Nessun parametro seleziona un backend o una query arbitraria.

**Stato: candidato installabile, tool MCP ancora `INACTIVE`.** `tools.materialize_object_search` aggiunge una sola rotta POST al profilo di incidenti esistente. Riutilizza OIDC workload, delega umana firmata e scope `urban.object.search`; verifica envelope e argomenti, cancella le credenziali in ingresso e invia a UDP solo `{type,pageSize?,cursor?}` insieme a un receipt HMAC di 30 secondi legato ai byte esatti. UDP verifica receipt, tenant e scope, installa il `TrustedPrincipal` e richiede la policy locale prima del serving. La configurazione mancante risponde 503; firma, body o policy non validi rispondono 403.

Prima di renderlo `ACTIVE`:

1. installare lo stesso nuovo secret esadecimale di 32 byte, distinto dalle altre chiavi, in APISIX (`OUF_UDP_SEARCH_OWNER_KEY`, ereditato dai worker tramite `nginx_config.envs`) e nel solo UDP come file leggibile dal processo (`OUF_UDP_SEARCH_OWNER_KEY_FILE`); fissare `OUF_UDP_SEARCH_TENANT_ID`, `OUF_UDP_SEARCH_ISSUER`, `OUF_UDP_SEARCH_AUDIENCE`, `OUF_UDP_SEARCH_WORKLOAD` ai valori effettivi del bundle/Keycloak;
2. compilare il catalogo e proiettarvi l'installazione come per il profilo incidenti; generare il candidato con `python3 -m tools.materialize_object_search --runtime <runtime.json> --oidc-client-secret-ref '$ENV://<OIDC_SECRET_ENV>' --delegation-key-env <DELEGATION_KEY_ENV> --owner-key-env <AUTHORIZATION_OWNER_KEY_ENV> --udp-key-env OUF_UDP_SEARCH_OWNER_KEY --output <candidate.json>`; verificare che i tre parametri di chiave siano distinti;
3. applicare solo la nuova rotta con `python3 -m ops.apisix.deploy_object_search --materialization <candidate.json> --admin-key <admin-key-file>`: lo script stampa `BACKUP=<previous.json>` e verifica readback. In caso di rollback usare `--restore <previous.json> --admin-key <admin-key-file>`;
4. eseguire su stack rappresentativo test permessi e negati APISIX→UDP: token e scope mancanti, tenant errato, receipt falsificato, body alterato, tipo wildcard, `pageSize` fuori limite, assenza del bundle, proprietà minimizzate, `nextCursor` e `partial`. Bloccare l'attivazione MCP finché questa evidenza non esiste e la release coordinata non è fissata.

Il percorso THS per configurazioni e decisioni umane resta nel browser Onboarding; i log protetti non entrano nel manifest MCP. R-INSTALL resta OPEN.
