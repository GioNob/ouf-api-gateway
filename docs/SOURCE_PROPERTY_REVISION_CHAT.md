# Mediazione delle revisioni di sorgente via MCP

**Stato previsto per il rilascio: candidato su `main`, non ancora installato.**

Il Gateway espone a MCP due POST esatti sotto `/internal/capabilities/v1/execute/source.revision/`. Ogni operazione richiede il proprio scope, il workload MCP autenticato e una delega HUMAN valida per lo stesso tenant. Il Gateway verifica identità, capability, owner, classe di operazione, correlazione, tentativo e chiave nell'envelope. Il corpo completo ha un limite di 65.536 byte.

## Preparazione

`prepare` richiede lo scope `ouf.onboarding.revision.prepare`, la sorgente, la versione padre, `expectedVersion`, `configurationHash`, una `commandKey` uguale a `IdempotencyKey` e l'accettazione esplicita di `NEW_PUBLICATION_MAY_START_ACQUISITION`. Si sceglie uno solo dei due intenti.

- `changes` propone regole di riconciliazione per coppie esistenti di `propertyIri` e `sourceField`.
- `assetRef` indica il nuovo CSV e il suo profilo immutabile tramite gli UUID `assetId` e `profileId`. Solo questo ramo ammette `newColumns`, con al massimo 1.024 decisioni. Per ogni colonna nuova, `EXCLUDE` richiede il solo nome e la decisione. `MAP` richiede anche `mapping` con `propertyIri`, `transform` e `reconciliation`. Onboarding verifica custodia, compatibilità con il padre e completezza delle decisioni.

Con `assetRef` il Gateway imposta `If-Match: W/"ov:<expectedVersion>"` usando il valore intero del corpo che firma. L'header sostituisce qualsiasi valore inviato dal chiamante. Nel ramo `changes` resta il comportamento originario. Onboarding verifica la precondizione sulla versione padre.

## Ricevuta, lettura e approvazione

Il Gateway elimina bearer, delega e header owner del chiamante. Una ricevuta HMAC con dominio `ouf-source-revision-owner-v1.` lega metodo, path owner, capability, identità e hash dei byte JSON originali. Nel cambio file anche l'ordine di `newColumns` e la distinzione tra array vuoto e omesso sono parte dell'intento.

`read` richiede lo scope `ouf.onboarding.revision.read`. Si legge una versione con `sourceId` e `onboardingVersionId`. Dopo una risposta incerta si riconcilia il comando con `sourceId`, `parentVersionId` e la `commandKey` originale. Entrambe le rotte hanno zero retry HTTP automatici. La decisione di approvazione e la successiva attivazione restano sul percorso HUMAN nativo.

Il materializzatore aggiunge le due rotte al profilo esistente. Verifica il template execute autenticato, i binding runtime e la corrispondenza con il backend della revisione HUMAN. L'host proviene dalla proiezione del servizio logico e la porta dal binding di ciascuna rotta. Una collisione o una deriva interrompe la materializzazione prima della consegna del risultato.
