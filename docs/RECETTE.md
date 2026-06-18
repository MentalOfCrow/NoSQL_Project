# Recette fonctionnelle

## Verification du lancement

Commande :

```powershell
docker compose up --build
```

Resultat attendu :

- Neo4j demarre sur `http://localhost:7474`.
- L'application demarre sur `http://localhost:8000`.

## Verification du chargement

Action :

1. ouvrir `http://localhost:8000` ;
2. cliquer sur **Charger le graphe**.

Resultat attendu :

- les compteurs affichent les noeuds et relations ;
- le graphe s'affiche ;
- les chemins d'attaque apparaissent.

## Verification Neo4j Browser

Connexion :

```text
URL: bolt://localhost:7687
Database: neo4j
Username: neo4j
Password: cybercorp123
```

Requete :

```cypher
MATCH (n)
RETURN n;
```

Resultat attendu : tous les noeuds CyberCorp sont affiches.

## Verification des chemins d'attaque

Requete :

```cypher
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
WHERE target.criticality = "critical"
RETURN path;
```

Resultat attendu :

- chemin vers `DC-01` ;
- chemin vers `NAS-BACKUP`.

## Verification de l'export

Action : cliquer sur **Exporter JSON**.

Resultat attendu : un fichier `cybercorp-analysis-export.json` est telecharge.
