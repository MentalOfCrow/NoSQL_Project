# Rapport d'analyse cyber - CyberCorp

## 1. Presentation du systeme d'information modelise

Le systeme d'information CyberCorp est represente sous forme de graphe Neo4j. Le modele contient six types de noeuds : `User`, `Machine`, `Group`, `Service`, `Vulnerability` et `Resource`.

Les relations principales sont `USES`, `MEMBER_OF`, `ADMIN_OF`, `HAS_ACCESS_TO`, `CONNECTED_TO`, `EXPOSES`, `HAS_VULNERABILITY` et `HOSTS`.

## 2. Schema ou capture du graphe

La capture du graphe peut etre realisee depuis l'application web ou depuis Neo4j Browser apres execution des scripts Cypher.

## 3. Hypothese d'attaque

Le poste compromis au depart est `PC-ALICE`. L'hypothese retenue est une compromission par phishing d'un poste utilisateur RH.

## 4. Chemins d'attaque identifies

Depuis `PC-ALICE`, un attaquant peut suivre le chemin suivant :

```text
PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01
```

Ce chemin permet d'atteindre le controleur de domaine `DC-01`, qui heberge la ressource critique `Active Directory`.

Un autre chemin important est :

```text
PC-ALICE -> SRV-WEB -> SRV-DB -> NAS-BACKUP
```

Ce chemin permet d'atteindre `NAS-BACKUP`, qui heberge les sauvegardes critiques de l'entreprise.

## 5. Machines vulnerables

Les machines les plus dangereuses dans le graphe sont :

- `SRV-WEB`, car il est accessible depuis `PC-ALICE` et possede `Log4Shell` et `Spring4Shell` ;
- `SRV-DB`, car il heberge la base clients, les donnees RH et les secrets applicatifs ;
- `DC-01`, car il est critique et possede la vulnerabilite `Zerologon` ;
- `NAS-BACKUP`, car il heberge les sauvegardes et expose SMB avec une mauvaise configuration.

## 6. Services exposes

Les services qui augmentent la surface d'attaque sont :

- `HTTP` et `HTTPS` sur `SRV-WEB` ;
- `SSH` sur `SRV-WEB` ;
- `MongoDB` sur `SRV-DB` ;
- `SMB` sur `DC-01` et `NAS-BACKUP` ;
- `RDP` sur `PC-BOB`.

## 7. Utilisateurs et groupes a risque

Le groupe `DEV` possede un acces a `SRV-DB`. Cet acces est risque car `SRV-DB` heberge des donnees sensibles.

Le groupe `ADMINS` possede un acces a `DC-01` et `NAS-BACKUP`. La compromission d'un compte administrateur peut donc mener a une compromission complete du systeme d'information.

L'utilisateur `charlie` est particulierement sensible car il possede des droits administrateur sur `DC-01` et `NAS-BACKUP`.

## 8. Recommandations de securite

- Isoler les postes utilisateurs des serveurs critiques.
- Limiter ou supprimer la connexion `SRV-DB -> DC-01`.
- Limiter ou supprimer la connexion `SRV-DB -> NAS-BACKUP`.
- Corriger `Log4Shell` et `Spring4Shell` sur `SRV-WEB`.
- Corriger `Zerologon` sur `DC-01`.
- Restreindre l'acces du groupe `DEV` a `SRV-DB`.
- Appliquer le principe du moindre privilege.
- Segmenter le reseau avec des VLAN et des regles firewall.
- Surveiller les connexions anormales depuis les postes utilisateurs.
- Desactiver les services inutiles comme RDP, SMB ou SSH quand ils ne sont pas necessaires.
- Renforcer l'authentification des comptes administrateurs avec MFA.
- Mettre en place une politique de patch management priorisee par criticite.

## 9. Conclusion

Neo4j permet de representer clairement les dependances entre utilisateurs, machines, services, vulnerabilites et ressources critiques. Dans ce scenario, le graphe montre qu'un poste utilisateur compromis peut devenir un point d'entree vers des actifs critiques si les connexions reseau et les droits d'acces sont trop permissifs.

La priorite defensive est de reduire les chemins entre `PC-ALICE`, `SRV-WEB`, `SRV-DB`, `DC-01` et `NAS-BACKUP`, puis de corriger les vulnerabilites critiques exposees.
