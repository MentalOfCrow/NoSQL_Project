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

Au demarrage, l'application charge automatiquement le graphe si la base Neo4j est vide.

Il est aussi possible de cliquer sur **Recharger le graphe** pour supprimer puis recreer toutes les donnees.

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

- synthese executive pour la presentation ;
- cartographie visuelle du graphe ;
- filtres par type de noeud ;
- nombre de noeuds et relations ;
- matrice de risque par machine ;
- chemins d'attaque depuis `PC-ALICE` ;
- plus courts chemins vers les machines sensibles ;
- ressources critiques accessibles ;
- machines vulnerables ;
- services exposes ;
- utilisateurs et groupes a risque ;
- requetes Cypher avec commentaires ;
- resultats exploitables ;
- comparaison avant/apres segmentation ;
- checklist des livrables ;
- recommandations de securisation.

## Exporter les resultats

Dans l'application, cliquer sur **Exporter JSON**.

Le fichier telecharge contient :

- statistiques du graphe ;
- chemins d'attaque ;
- vulnerabilites ;
- ressources accessibles ;
- services exposes ;
- risques utilisateurs/groupes ;
- recommandations ;
- plan de segmentation.

## Import CSV bonus

Les donnees CSV sont dans :

- `data/nodes.csv`
- `data/relationships.csv`

Pour charger Neo4j depuis les CSV :

```powershell
pip install -r requirements.txt
python scripts/load_from_csv.py
```

## Fichiers de rendu

- `reports/analyse_cyber.md` : rapport d'analyse cyber.
- `reports/resultats_requetes.md` : resultats attendus des requetes.
- `reports/presentation_orale.md` : trame pour la presentation.
- `docs/RECETTE.md` : checklist de verification.

## Test rapide

Quand Docker est lance :

```powershell
python scripts/smoke_test.py
```

Resultat attendu :

```text
OK: 31 noeuds, 41 relations
```

## Commandes Git utiles

Apres modification :

```powershell
git add .
git commit -m "Complete functional Neo4j application"
git push origin main
```
