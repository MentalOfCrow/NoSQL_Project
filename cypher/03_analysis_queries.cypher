// Afficher tout le graphe
MATCH (n)
RETURN n;

// Afficher les utilisateurs et leurs machines
MATCH (u:User)-[:USES]->(m:Machine)
RETURN u.name AS utilisateur, m.name AS machine
ORDER BY utilisateur;

// Afficher les machines critiques
MATCH (m:Machine)
WHERE m.criticality = "critical"
RETURN m.name AS machine, m.type AS type, m.riskScore AS score_risque
ORDER BY score_risque DESC;

// Afficher les machines vulnerables
MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score
ORDER BY v.score DESC;

// Afficher les services exposes
MATCH (m:Machine)-[:EXPOSES]->(s:Service)
RETURN m.name AS machine, s.name AS service, s.port AS port
ORDER BY m.name, s.port;

// Trouver un chemin vers le controleur de domaine
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine {name: "DC-01"})
RETURN path;

// Trouver tous les chemins vers des machines critiques
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
WHERE target.criticality = "critical"
RETURN path;

// Trouver les machines vulnerables accessibles depuis PC-ALICE
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score, path
ORDER BY v.score DESC;

// Trouver les ressources accessibles depuis PC-ALICE
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
RETURN r.name AS ressource, r.sensitivity AS sensibilite, m.name AS machine, path
ORDER BY r.sensitivity DESC;

// Trouver les utilisateurs ayant des droits admin
MATCH (u:User)-[:ADMIN_OF]->(m:Machine)
RETURN u.name AS utilisateur, m.name AS machine_administree
ORDER BY utilisateur;

// Trouver les utilisateurs pouvant acceder a des machines critiques via un groupe
MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high", "critical"]
RETURN u.name AS utilisateur, g.name AS groupe, m.name AS machine, m.criticality AS criticite
ORDER BY criticite DESC, utilisateur;

// Bonus : chemin le plus court vers chaque machine critique
MATCH (start:Machine {name: "PC-ALICE"}), (target:Machine)
WHERE target.criticality = "critical"
MATCH path = shortestPath((start)-[:CONNECTED_TO*1..5]->(target))
RETURN target.name AS cible, [n IN nodes(path) | n.name] AS chemin, length(path) AS sauts
ORDER BY sauts ASC;
