# Adozione di un candidato della discovery tramite MCP

Il Gateway espone `POST /internal/capabilities/v1/execute/semantic/discovery/adopt` al workload MCP configurato. Il binding inoltra l’envelope a `POST /api/semantic/v1/proposal-commands/adopt`. Il materializzatore delle proposte usa host e porta del backend proiettato. Per estendere un canale proposte già materializzato, usare `--adoption-only` con la configurazione esistente e gli stessi riferimenti alle chiavi.

## Richiesta e prova

Gli `Arguments` ammettono soltanto `requestId` e `candidateId` (UUID) e `commandKey` (da 1 a 128 caratteri del set `A-Za-z0-9_:.-`). Tutti e tre sono obbligatori. La chiave deve coincidere con `IdempotencyKey` dell’envelope e con l’header HTTP. Il limite di 65.536 byte si applica all’intero corpo.

OIDC autentica il workload MCP. Il Gateway verifica la firma e la validità temporale della delega, l’attore HUMAN, il tenant, l’identità dell’envelope e lo scope `ouf.semantic.discovery`. Rimuove bearer, cookie e header di identità del chiamante. La prova `X-OUF-Semantic-Proposal-Receipt` firma la capability `ouf.semantic.discovery.adopt`, il metodo e il path owner, il digest SHA-256 dei byte originali e il contesto delegato. Usa il dominio HMAC `ouf-semantic-proposal-owner-v1.` e scade entro 30 secondi o alla scadenza della delega.

## Ricevuta e riconciliazione

Il proxy conserva status e corpo dell’owner, inclusi la ricevuta DRAFT con provenienza e gli errori. In caso di esito incerto, usare `ouf.semantic.proposal.read` su `POST /internal/capabilities/v1/execute/semantic/read` con la `Arguments.commandKey` originaria e una delega HUMAN fresca con gli scope `ouf.semantic.proposal.read` e `ouf.semantic.discovery`. L’owner verifica i grant correnti per lettura e adozione e restituisce lo snapshot storico del comando `ADOPT`. I retry HTTP automatici del Gateway sono disabilitati.

Il test di compatibilità confronta lo schema materializzato con gli argomenti della PR owner #49 al commit `8c0b1a23228d6ad0d99f16283f69d448c36b2560`, espandendo il riferimento locale alla definizione UUID. Il vettore fissato e l’esempio di ricevuta dell’owner sono in `tests/fixtures/`.
