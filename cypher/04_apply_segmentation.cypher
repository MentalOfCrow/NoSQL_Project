// Simulation de securisation reseau.
// Objectif : supprimer les chemins directs depuis SRV-DB vers DC-01 et NAS-BACKUP.

MATCH (web:Machine {name: "SRV-WEB"})-[webDb:CONNECTED_TO]->(db:Machine {name: "SRV-DB"})
SET webDb.status = "restricted",
    webDb.allowedPorts = [27017],
    webDb.note = "Flux applicatif strictement controle";

MATCH (:Machine {name: "SRV-DB"})-[r:CONNECTED_TO]->(:Machine {name: "DC-01"})
DELETE r;

MATCH (:Machine {name: "SRV-DB"})-[r:CONNECTED_TO]->(:Machine {name: "NAS-BACKUP"})
DELETE r;

MATCH (pc:Machine {name: "PC-ALICE"})-[r:CONNECTED_TO]->(web:Machine {name: "SRV-WEB"})
SET r.status = "filtered",
    r.note = "Acces utilisateur limite au frontal web";

// Verification apres segmentation
MATCH path = (:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
WHERE target.criticality = "critical"
RETURN target.name AS cible, [node IN nodes(path) | node.name] AS chemin;
