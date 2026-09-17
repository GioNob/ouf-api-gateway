# R2f — routing della revisione geometrica

Due binding distinti preservano il namespace UDP `/api/udp/v1/governance/geometry/issues/*`: GET richiede `resolution.issue.read`; POST richiede `authority.override`, dichiara HUMAN_USER e non è un tool MCP. L’owner UDP rivalida identità umana, tenant, capability e accesso ad entrambe le geometrie prima di registrare la decisione. Nessuna priorità globale viene dedotta dalla scelta del singolo caso.

Il profilo Gateway iniziale ammette soltanto OPEN/ANONYMOUS, come previsto dal PET (§§1, 4, 20 e T29.1). Il relativo test negativo rimane invariato. L’API UDP di revisione mantiene questo limite anche se un principal possiede privilegi più ampi. Le prove owner su label RESTRICTED non autorizzano la loro esposizione nel profilo iniziale.

I test verificano la compilazione dei binding, la separazione read/command e la conservazione dell’URI. La pubblicazione APISIX, il browser THS con IAM reale e il collaudo del percorso umano rimangono gate di ambiente: il file di routing non li certifica. Nessun servizio è stato distribuito tramite questa modifica.
