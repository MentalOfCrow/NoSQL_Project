# Utilisation de l'application

## Prerequis

- Docker Desktop lance
- Git
- Un navigateur web

## Lancer le projet

Depuis le dossier du projet :

```powershell
docker compose up --build
```

Ouvrir ensuite :

- Application : http://localhost:8000
- Neo4j Browser : http://localhost:7474

Identifiants Neo4j :

```text
neo4j / cybercorp123
```

## Charger le graphe

Dans l'application, cliquer sur **Charger le graphe**.

Le bouton execute automatiquement :

1. `cypher/01_constraints.cypher`
2. `cypher/02_seed_graph.cypher`

## Charger le graphe avec Python

Si Neo4j tourne deja :

```powershell
pip install -r requirements.txt
python scripts/load_data.py
```

## Ce que montre l'application

- cartographie visuelle du graphe ;
- nombre de noeuds et relations ;
- chemins d'attaque depuis `PC-ALICE` ;
- plus courts chemins vers les machines sensibles ;
- ressources critiques accessibles ;
- machines vulnerables ;
- services exposes ;
- utilisateurs et groupes a risque ;
- recommandations de securisation.

## Commandes Git utiles

Apres modification :

```powershell
git add .
git commit -m "Complete functional Neo4j application"
git push origin main
```
