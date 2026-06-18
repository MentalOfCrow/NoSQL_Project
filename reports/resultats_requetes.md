# Resultats des requetes Cypher

## 1. Utilisateurs et machines

Requete :

```cypher
MATCH (u:User)-[:USES]->(m:Machine)
RETURN u.name AS utilisateur, m.name AS machine;
```

Resultat attendu :

| utilisateur | machine |
|---|---|
| alice | PC-ALICE |
| bob | PC-BOB |
| charlie | DC-01 |
| diana | PC-BOB |
| eve | PC-ALICE |

Commentaire : les comptes utilisateurs sont associes aux machines qu'ils utilisent dans le systeme d'information.

## 2. Machines critiques

Requete :

```cypher
MATCH (m:Machine)
WHERE m.criticality = "critical"
RETURN m.name AS machine, m.type AS type;
```

Resultat attendu :

| machine | type |
|---|---|
| DC-01 | domain_controller |
| NAS-BACKUP | backup_server |

Commentaire : `DC-01` et `NAS-BACKUP` sont les actifs les plus sensibles.

## 3. Machines vulnerables

Requete :

```cypher
MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score
ORDER BY v.score DESC;
```

Resultat attendu :

| machine | cve | vulnerabilite | score |
|---|---|---|---:|
| SRV-WEB | CVE-2021-44228 | Log4Shell | 10 |
| DC-01 | CVE-2020-1472 | Zerologon | 10 |
| SRV-WEB | CVE-2022-22965 | Spring4Shell | 9.8 |
| PC-BOB | CVE-2019-0708 | BlueKeep | 9.8 |
| NAS-BACKUP | CVE-2023-0001 | SMB Misconfiguration | 7.5 |

Commentaire : `SRV-WEB` et `DC-01` doivent etre corriges en priorite.

## 4. Chemins vers les machines critiques

Requete :

```cypher
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
WHERE target.criticality = "critical"
RETURN path;
```

Resultat attendu :

```text
PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01
PC-ALICE -> SRV-WEB -> SRV-DB -> NAS-BACKUP
PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01 -> NAS-BACKUP
```

Commentaire : un poste utilisateur compromis peut atteindre les machines critiques par rebond reseau.

## 5. Ressources accessibles depuis PC-ALICE

Requete :

```cypher
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
RETURN r.name AS ressource, r.sensitivity AS sensibilite, m.name AS machine, path
ORDER BY r.sensitivity DESC;
```

Resultat attendu :

| ressource | sensibilite | machine |
|---|---|---|
| Active Directory | critical | DC-01 |
| Sauvegardes | critical | NAS-BACKUP |
| Secrets applicatifs | critical | SRV-DB |
| Base clients | high | SRV-DB |
| Donnees RH | high | SRV-DB |

Commentaire : les ressources critiques sont atteignables depuis `PC-ALICE`, ce qui montre un probleme de segmentation.

## 6. Utilisateurs et groupes a risque

Requete :

```cypher
MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high", "critical"]
RETURN u.name AS utilisateur, g.name AS groupe, m.name AS machine, m.criticality AS criticite;
```

Resultat attendu :

| utilisateur | groupe | machine | criticite |
|---|---|---|---|
| bob | DEV | SRV-DB | high |
| charlie | ADMINS | DC-01 | critical |
| charlie | ADMINS | NAS-BACKUP | critical |

Commentaire : les groupes `DEV` et `ADMINS` doivent etre controles avec le principe du moindre privilege.
