# Presentation orale - CyberCorp Neo4j

## 1. Introduction

Le projet modelise le systeme d'information de CyberCorp dans Neo4j afin d'analyser les chemins d'attaque possibles depuis une machine compromise.

Machine compromise : `PC-ALICE`.

Problematique : a partir de `PC-ALICE`, quels chemins permettent d'atteindre les ressources critiques ?

## 2. Modele de graphe

Noeuds utilises :

- `User`
- `Machine`
- `Group`
- `Service`
- `Vulnerability`
- `Resource`

Relations principales :

- `USES`
- `MEMBER_OF`
- `ADMIN_OF`
- `HAS_ACCESS_TO`
- `CONNECTED_TO`
- `EXPOSES`
- `HAS_VULNERABILITY`
- `HOSTS`

## 3. Scenario d'attaque

Un utilisateur RH est victime d'un phishing. Le poste `PC-ALICE` est compromis.

Chemin principal :

```text
PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01
```

Chemin vers les sauvegardes :

```text
PC-ALICE -> SRV-WEB -> SRV-DB -> NAS-BACKUP
```

## 4. Vulnérabilités principales

- `Log4Shell` sur `SRV-WEB`
- `Spring4Shell` sur `SRV-WEB`
- `Zerologon` sur `DC-01`
- `BlueKeep` sur `PC-BOB`
- mauvaise configuration SMB sur `NAS-BACKUP`

## 5. Ressources critiques exposees

- `Active Directory` sur `DC-01`
- `Sauvegardes` sur `NAS-BACKUP`
- `Secrets applicatifs` sur `SRV-DB`
- `Base clients` sur `SRV-DB`
- `Donnees RH` sur `SRV-DB`

## 6. Risques utilisateurs et groupes

Le groupe `DEV` a acces a `SRV-DB`, ce qui est trop permissif.

Le groupe `ADMINS` a acces a `DC-01` et `NAS-BACKUP`. Une compromission d'un compte admin aurait donc un impact critique.

## 7. Recommandations

- segmenter le reseau ;
- isoler les postes utilisateurs ;
- limiter les flux vers `SRV-DB`, `DC-01` et `NAS-BACKUP` ;
- corriger les vulnerabilites critiques ;
- appliquer le moindre privilege ;
- activer MFA pour les comptes administrateurs ;
- surveiller les connexions laterales ;
- desactiver les services inutiles.

## 8. Demonstration

1. Lancer `docker compose up --build`.
2. Ouvrir `http://localhost:8000`.
3. Cliquer sur **Charger le graphe**.
4. Montrer le graphe.
5. Montrer les chemins depuis `PC-ALICE`.
6. Ouvrir Neo4j Browser et executer les requetes Cypher.

## 9. Conclusion

Neo4j permet de visualiser les dependances entre machines, utilisateurs, groupes, services, vulnerabilites et ressources critiques. Cette representation facilite l'identification des chemins d'attaque et aide a prioriser les mesures de securisation.
