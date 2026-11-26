# R-050 / D-087 · Protocollo MCP pubblico

Il bundle adotta `public-mcp-endpoint` e `public-mcp-oauth-protected-resource`. Il binding di origine è `ouf-config/protocol/mcp-endpoint.yaml`. La POST usa la catena execute esistente, comprese le due funzioni di rewrite e le due di access, nell’ordine installato. Il Gateway firma la delega, rimuove il bearer e inoltra la richiesta al backend. La GET serve il documento RFC 9728 con `mocking`.

## Valori da registrare nel profilo dell’esecutore

| Nome | Tipo nel bundle v2 | Origine |
|---|---|---|
| `services.bindings.ouf-mcp-server` | `string` | Host del backend MCP raggiungibile da APISIX |
| `services.ports.ouf-mcp-server` | `integer` | Porta HTTP dello stesso backend |
| `gateway.rateLimits.publicMcp.count`, `gateway.rateLimits.publicMcp.timeWindowSeconds` | `integer` | Conteggio e finestra della POST, da `limit-count.count` e `limit-count.time_window` |
| `gateway.rateLimits.publicMcpMetadata.count`, `gateway.rateLimits.publicMcpMetadata.timeWindowSeconds` | `integer` | Conteggio e finestra della GET, dagli stessi campi della sua quota |
| `gateway.publicMcpChallenge` | `string` | Valore completo dell’header `WWW-Authenticate` prodotto dal materializzatore |
| `gateway.publicMcpMetadataJson` | `string` | Stringa JSON compatta prodotta per `mocking.response_example` |

Per l’adozione, ricavare le quote dalle rispettive rotte installate. Il bundle v2 sostituisce ciascun valore JSON per intero. Generare insieme le due stringhe OAuth a ogni proiezione con `tools.release_family_public_mcp.oauth_profile_values`. Gli argomenti sono `runtime["x-ouf-installation"]` e `binding["x-ouf-policy"]` del binding pubblico. La funzione convalida gli URL proiettati da `gateway.publicApiBaseUrl` e `gateway.issuerUrl` e legge `requiredScope` dalla policy. Restituisce le due voci del profilo con il documento OAuth serializzato. Inserire quest’ultimo nel profilo come stringa, conservandone i byte.

Il validatore OIDC e la firma usano lo stesso issuer. Audience, workload e nome della variabile della chiave di delega arrivano dalle label del rilascio. Il segreto OIDC usa `gateway.oidcClientSecretRef`. Il deployer status continua a gestire la sola rotta execute anche con uno snapshot precedente di tre rotte.

## Evidenze PET

| ID | Verifica |
|---|---|
| `GW-60e-01` | Digest canonico del sottoinsieme esplicito dei 31 ID di `3d69cb4` |
| `GW-60e-02` | Confronto ricorsivo dei campi e delle funzioni Lua, parità oggetto/array e limite corpo. La prova Lua esegue rewrite e access e verifica la firma al consumatore |
| `GW-60e-03` | Parità byte per byte della stringa del documento OAuth e confronto del challenge |
| `GW-60e-04` | Adozione degli ID installati, controllo dei selettori, secondo plan e ritorno esatto delle immagini iniziali |
| `GW-60e-05` | Blocco degli installatori e dei ripristini legacy sulle due rotte |
| `GW-60e-06` | Prova HTTP nel gate APISIX 3.18 esistente con bundle risolto, issuer e backend di test |

I test offline sono in `tests/test_release_family_public_mcp.py`. La fixture CI sostituisce i valori privati dell’export con dati sintetici. Se disponibile nella worktree, lo stesso test usa anche l’export sanificato del 23/11 e controlla i conflitti sull’inventario storico completo fornito. I timestamp Admin restano fuori dal corpo del PUT.
