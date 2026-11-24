# Rilascio Gateway D-081

| ID rotta | Metodo e percorso | Capability | Backend logico |
| --- | --- | --- | --- |
| `semantic-human-terms` | `GET /api/trusted-human/v1/semantic-published-terms` | `ouf.semantic.review@1.0.0` | `ouf-semantic-registry:8080`, stesso percorso |
| `trusted-human-resolution-review` | `GET`, `POST /trusted-human/resolution/*` | `resolution.issue.read` (label della pagina con sessione Onboarding) | `ouf-onboarding:8080`, stesso percorso |
| `ths-resolution-package-read` | `GET /api/udp/v1/governance/resolution/issues/package` | `resolution.issue.read` | `ouf-udp-object-resolution:8080`, stesso percorso |
| `ths-resolution-package-confirm` | `POST /api/udp/v1/governance/resolution/issues/package/confirm` | `resolution.match.approve` | `ouf-udp-object-resolution:8080`, stesso percorso |

La rotta dei termini semantici richiede un bearer OIDC con attore `HUMAN` e scope
`ouf.semantic.review`. APISIX confronta il solo percorso con il selettore
`uri` e inoltra la query `revisionIds` al registro semantico. Il limite del
corpo è 65.536 byte e il timeout upstream è 10 secondi.

Per le tre rotte di risoluzione il limite del corpo è 1.048.576 byte.
I timeout di connessione e invio sono 3 secondi. Il timeout di lettura è
30 secondi per la pagina e 20 secondi per le API UDP. La conferma conserva
la validazione del corpo. [Schema della conferma](../schemas/ths-resolution-package-confirm-v1.json)

Il bundle incrementale contiene le quattro risorse APISIX in tabella.
Il contratto `ouf.gateway-release-bundle.v1` usa i segnaposto D-058 per host,
porta intera, discovery OIDC, audience, riferimento al segreto client e label
d’installazione. Il manifest riporta commit, workflow, ID del run e digest.

Su pull request il job `config-contract` genera il bundle dal commit di testa,
ne risolve i segnaposto con un profilo di test e carica le rotte in APISIX.
Per i termini semantici il gate verifica l’inoltro della query, i dinieghi di autorizzazione e i
mancati match per metodo o percorso. Dopo il gate, l’artefatto
`gateway-release-bundle-<runId>` contiene `bundle.json`, `manifest.json` e
`SHA256SUMS`. I comandi seguenti riproducono il formato in locale con un ID di prova.

```sh
python -m tools.gateway_release_bundle --output generated/gateway-release-bundle --workflow-path .github/workflows/ci.yml --run-id 33
python -m pytest -q tests/test_gateway_release_bundle.py tests/test_semantic_human_routes.py tests/test_resolution_ths.py
```
