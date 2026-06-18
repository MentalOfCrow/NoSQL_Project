# Import automatique CSV avec Python

Ce projet propose deux methodes de creation du graphe :

1. `cypher/02_seed_graph.cypher` pour montrer la creation Cypher manuelle demandee dans l'enonce ;
2. `scripts/load_from_csv.py` pour obtenir le bonus import CSV + Python.

## Fichiers CSV

- `data/nodes.csv` : utilisateurs, machines, services, vulnerabilites, groupes, ressources.
- `data/relationships.csv` : relations `USES`, `MEMBER_OF`, `ADMIN_OF`, `CONNECTED_TO`, `EXPOSES`, `HAS_VULNERABILITY`, `HAS_ACCESS_TO`, `HOSTS`.

## Lancement

Neo4j doit etre demarre :

```powershell
docker compose up --build
```

Dans un autre terminal :

```powershell
pip install -r requirements.txt
python scripts/load_from_csv.py --clear
```

Resultat attendu :

```text
Import CSV termine.
Noeuds lus depuis CSV: 31
Relations lues depuis CSV: 41
Graphe Neo4j: 31 noeuds, 41 relations
```

## Interet pour le bonus

L'import CSV rend le projet plus professionnel parce que les donnees ne sont plus codees uniquement dans un script Cypher. On peut modifier l'infrastructure dans les fichiers CSV, puis relancer le script Python pour reconstruire le graphe.

Le script cree les contraintes d'unicite Neo4j, valide les labels et les relations autorises, insere les noeuds, cree les relations et affiche un bilan d'import.
