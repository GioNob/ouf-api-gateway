# R2f — routing della revisione geometrica

Due binding distinti preservano il namespace UDP `/api/udp/v1/governance/geometry/issues/*`: GET richiede `resolution.issue.read`; POST richiede `authority.override`, dichiara HUMAN_USER e non è un tool MCP. L’owner UDP rivalida identità umana, tenant, capability e accesso ad entrambe le geometrie prima di registrare la decisione. Nessuna priorità globale viene dedotta dalla scelta del singolo caso.

Il manifest delle capability accetta anche le label dati PERSONAL, SENSITIVE e RESTRICTED già previste dalla baseline. Questa classificazione non autorizza la divulgazione: le decisioni resource/label restano server-side nell’owner.

I test verificano la compilazione dei binding, la separazione read/command e la conservazione dell’URI. La pubblicazione APISIX, il browser THS con IAM reale e il collaudo del percorso umano rimangono gate di ambiente: il file di routing non li certifica. Nessun servizio è stato distribuito tramite questa modifica.
