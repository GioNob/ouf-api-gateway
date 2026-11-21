# Rilascio Gateway D-081

| ID rotta | Metodo e percorso | Capability | Backend logico |
| --- | --- | --- | --- |
| `semantic-human-terms` | `GET /api/trusted-human/v1/semantic-published-terms` | `ouf.semantic.review@1.0.0` | `ouf-semantic-registry:8080`, stesso percorso |

La rotta THS pubblica richiede un bearer OIDC con attore `HUMAN` e scope
`ouf.semantic.review`. APISIX confronta il solo percorso con il selettore
`uri` e inoltra la query `revisionIds` al registro semantico. Il limite del
corpo è 65.536 byte e il timeout upstream è 10 secondi.

Il bundle incrementale contiene la sola risorsa APISIX `routes/semantic-human-terms`.
Il contratto `ouf.gateway-release-bundle.v1` usa i segnaposto D-058 per host,
porta intera, discovery OIDC, audience, riferimento al segreto client e label
d’installazione. Il manifest riporta commit, workflow, ID del run e digest.

Su pull request il job `config-contract` genera il bundle dal commit di testa,
ne risolve i segnaposto con un profilo di test e carica la rotta in APISIX.
Il gate verifica l’inoltro della query, i dinieghi di autorizzazione e i
mancati match per metodo o percorso. Dopo il gate, l’artefatto
`gateway-release-bundle-<runId>` contiene `bundle.json`, `manifest.json` e
`SHA256SUMS`. I comandi seguenti riproducono il formato in locale con un ID di prova.

```sh
python -m tools.gateway_release_bundle --output generated/gateway-release-bundle --workflow-path .github/workflows/ci.yml --run-id 33
python -m pytest -q tests/test_gateway_release_bundle.py tests/test_semantic_human_routes.py
```
