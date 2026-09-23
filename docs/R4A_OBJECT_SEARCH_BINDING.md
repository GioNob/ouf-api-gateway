# R4a — urban.object.search, prima tranche

Il contratto candidate collega `POST /internal/capabilities/v1/execute/urban.object.search` a `POST /api/udp/v1/objects/search` sul servizio UDP. Il payload è `{ "type": "<tipo canonico esatto>", "pageSize": 1..100, "cursor": "<opzionale>" }`. UDP riusa il serving con tenant, decisioni per oggetto/proprietà, proiezione minimizzata e cursore opaco. Nessun parametro seleziona un backend o una query arbitraria.

**Stato: non attivabile.** Il profilo APISIX installato materializza `/internal/capabilities/v1/execute` per lo status e per le capability operative espressamente elencate. La sola RouteBinding compilata non installa una nuova route APISIX protetta. Il manifest MCP mantiene perciò `urban.object.search` `INACTIVE`. Il dispatcher Python verifica il contratto statico e usa un upstream fittizio; non dimostra il passaggio autenticato fino a UDP.

Prima di renderlo `ACTIVE`:

1. aggiungere una materializzazione APISIX chiusa per questa singola capability con verifica del token workload, delega umana firmata, scope `urban.object.search`, identità dell'envelope, limiti di richiesta, retry Gateway zero e destinazione fissa;
2. attestare su UDP un `TrustedPrincipal` installato da un filtro di autenticazione indipendente dai soli header `X-OUF-*`, con stesso tenant e scope, e rigetto dei tentativi di spoofing; non creare il principal usando header non autenticati;
3. testare nel runtime APISIX→UDP casi permessi, senza scope, tenant errato, filtri invalidi e minimizzazione, compresi `nextCursor` e `partial`;
4. aggiornare il profilo e gli script R-INSTALL, incluse versione di release, rollback e test negativo, quindi abilitare il tool MCP soltanto dopo l'evidenza.

Il percorso THS per configurazioni e decisioni umane resta nel browser Onboarding; i log protetti non entrano nel manifest MCP. R-INSTALL resta OPEN.
