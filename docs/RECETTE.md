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
2. attendre l'auto-chargement ou cliquer sur **Recharger le graphe**.

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

## Verification avant / apres segmentation

Action :

1. dans l'application, cliquer sur **Appliquer segmentation** ;
2. verifier que le nombre de chemins critiques restants passe a `0` ;
3. cliquer sur **Restaurer initial** pour revenir au graphe de depart.

Resultat attendu :

- avant segmentation : chemins vers `DC-01` et `NAS-BACKUP` ;
- apres segmentation : plus aucun chemin critique depuis `PC-ALICE`.

## Verification automatisee

Commande :

```powershell
python scripts/smoke_test.py
```

Resultat attendu :

```text
OK: 31 noeuds, 41 relations
```

## Verification du bonus CSV/Python

Commande :

```powershell
python scripts/load_from_csv.py --clear
```

Resultat attendu :

```text
Import CSV termine.
Noeuds lus depuis CSV: 31
Relations lues depuis CSV: 41
Graphe Neo4j: 31 noeuds, 41 relations
```
