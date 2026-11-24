# Contratto delle rotte browser THS

Il contratto elenca le richieste che il browser deve poter inviare al Gateway per aprire ciascuna pagina, caricare gli asset, leggere una scheda ed eseguire le azioni disponibili. Login e callback OIDC sono condivisi dalle sei superfici. Il riferimento sorgente è il commit di `ouf-source-onboarding` indicato in `onboardingRevision`. [Contratto v1](../config/ths-page-route-contract-v1.json)

## Aggiornare una pagina

1. Nella revisione candidata di Onboarding, aprire l'HTML in `src/main/resources/ths/`. Verificare l'URL pubblico della pagina nel controller Java, compresa la barra finale. Riportare in `scripts` e `stylesheets` gli URL caricati dall'HTML, nell'ordine dichiarato. Ad esempio, `managed-file-picker.html` carica `picker.js`.
2. Seguire le chiamate dello script, inclusi gli helper condivisi e le azioni condizionali. Aggiungere in `api` una voce per ciascun metodo e percorso effettivo. Per esempio, l'ownership del recupero usa lo stesso percorso in GET per la scheda e in POST per la decisione. Usare `{nome}` per un identificatore variabile. Un'azione con suffisso fisso ha una propria voce.
3. Registrare i percorsi come li risolve il browser dalla pagina. Per il routing basta il pathname. Parametri come `challenge`, `handoff` e `__ths_login` usano la stessa rotta. Se cambia il flusso OIDC, verificare anche l'avvio del login e il callback in `oidc`. Aggiornare `onboardingRevision` insieme all'inventario. Un cambio incompatibile del formato richiede una nuova versione del contratto e del suo lettore.
4. Aggiornare i casi in `ouf-source-onboarding/tests/browser/` che aprono la pagina o intercettano le API. Verificare il caricamento reale dello script di pagina e confrontare metodo e pathname osservati con il JSON, anche per le azioni di recupero e rifiuto. Eseguire il controllo Gateway sulla stessa revisione.

## Verifica offline

Dalla radice del Gateway, con le dipendenze di sviluppo già disponibili, eseguire:

```powershell
$env:OUF_ONBOARDING_CHECKOUT = 'C:\dev\ouf\ouf-source-onboarding'
python -m pytest -q tests/test_ths_page_route_contract.py
```

Impostare il percorso sulla checkout di Onboarding da confrontare. Il test legge i sei HTML e confronta gli script e i fogli di stile con il contratto. Senza la variabile, il controllo di routing si esegue comunque per ogni voce del JSON.

Il test compila `ouf-config` con la proiezione di laboratorio, esegue i materializzatori di permission proposals, onboarding review, managed-file THS e resolution THS e usa i selettori APISIX del picker e del login. Per ciascuna richiesta controlla il metodo e gli indirizzi generati in `uri` o `uris`. Un indirizzo esatto copre solo quel percorso. Un jolly finale copre il prefisso anche su più segmenti. Se una futura rotta richiede condizioni aggiuntive (per esempio `vars`), occorre verificarle prima di considerarla coperta. Ogni voce scoperta produce un fallimento con superficie, metodo e percorso. [Test del contratto](../tests/test_ths_page_route_contract.py)

## Superficie di risoluzione

Il Gateway materializza e distribuisce le tre rotte di risoluzione. `trusted-human-resolution-review` inoltra a Onboarding le cinque richieste browser sotto `/trusted-human/resolution/`, preservando il percorso e la sessione della pagina. Per le chiamate da Onboarding a UDP, `ths-resolution-package-read` richiede lo scope `resolution.issue.read` e `ths-resolution-package-confirm` richiede `resolution.match.approve`. Entrambe verificano il bearer OIDC dell’attore HUMAN. [Inventario del bundle](GATEWAY_RELEASE_BUNDLE.md)

Il piano `ouf-deploy/tools/resolution_ths_update` resta come storico dell’installazione originale. Il test applica una copia di `compile_routes` alle rotte Gateway di onboarding e preflight UDP e confronta ogni campo con la materializzazione corrente e con il bundle risolto. Con una checkout locale di Deploy confronta anche la funzione e le costanti della copia con il sorgente originale ed esegue il verificatore del bundle. [Test di equivalenza](../tests/test_resolution_ths.py)

```powershell
$env:OUF_DEPLOY_CHECKOUT = 'C:\dev\ouf\ouf-deploy'
python -m pytest -q tests/test_resolution_ths.py
```

## Regressione del 21 novembre

L'HTML precedente al task 31 caricava `/trusted-human/authorization/session.js`. La lista di indirizzi esatti di authorization escludeva quello script. Dal commit Onboarding `4e3dd7a`, l'owner incorpora i byte di `session.js` nello script di ciascuna pagina. Il fixture browser `tests/browser/ths-asset.cjs` riproduce questa composizione. Se un HTML torna a richiedere lo script separatamente, il confronto con la checkout segnala il nuovo asset. Inserirlo nel JSON rende verificabile la sua copertura anche nella CI del solo Gateway.
