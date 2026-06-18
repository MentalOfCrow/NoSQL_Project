NoSQL_Project

Projet B3 Cyber / Infra

Cartographie d’un système d’information et analyse des chemins d’attaque avec Neo4j

Objectif général

L’objectif du projet est de modéliser un système d’information dans une base de données orientée graphe Neo4j, puis d’analyser les relations entre les machines, les utilisateurs, les groupes, les services, les vulnérabilités et les ressources critiques.

Les étudiants devront se placer dans un contexte cyber défensif et répondre à la problématique suivante :

À partir d’une machine compromise, quels sont les chemins possibles vers les ressources critiques de l’entreprise ?

Ce projet permet de comprendre comment un attaquant peut se déplacer latéralement dans un système d’information et comment une mauvaise configuration réseau ou des droits trop permissifs peuvent augmenter le risque de compromission.

Contexte du projet

L’entreprise fictive CyberCorp possède une infrastructure interne composée de :

postes utilisateurs ;
serveurs internes ;
comptes utilisateurs ;
groupes d’utilisateurs ;
services exposés ;
vulnérabilités connues ;
ressources sensibles.

Une alerte de sécurité indique qu’un poste utilisateur a été compromis à la suite d’une attaque par phishing.

La machine compromise est :

PC-ALICE

Les étudiants doivent utiliser Neo4j pour identifier les chemins possibles depuis cette machine vers les ressources critiques de l’entreprise.

Technologies utilisées

Obligatoire

Neo4j Community Edition ou Neo4j AuraDB Free
Cypher Query Language

Optionnel

Docker
Python
CSV
Graph Data Science Library

Compétences travaillées

À la fin du projet, les étudiants doivent être capables de :

comprendre le principe d’une base de données orientée graphe ;
modéliser un système d’information sous forme de nœuds et de relations ;
créer des données dans Neo4j avec Cypher ;
écrire des requêtes Cypher simples et intermédiaires ;
identifier des chemins d’attaque potentiels ;
repérer les machines vulnérables ;
analyser les droits utilisateurs et les groupes à risque ;
produire une analyse cyber exploitable ;
proposer des recommandations de sécurisation.

Données de départ

Utilisateurs

Nom	Rôle
alice	employée RH
bob	développeur
charlie	administrateur système
diana	RSSI
eve	stagiaire

Machines

Machine	Type	Criticité
PC-ALICE	poste utilisateur	faible
PC-BOB	poste développeur	moyenne
SRV-WEB	serveur web	moyenne
SRV-DB	serveur base de données	élevée
DC-01	contrôleur de domaine	critique
NAS-BACKUP	serveur de sauvegarde	critique

Services

Service	Port
SSH	22
HTTP	80
HTTPS	443
RDP	3389
SMB	445
MongoDB	27017

Vulnérabilités

CVE	Description	Score
CVE-2021-44228	Log4Shell	10
CVE-2020-1472	Zerologon	10
CVE-2019-0708	BlueKeep	9.8
CVE-2022-22965	Spring4Shell	9.8
CVE-2023-0001	Mauvaise configuration SMB	7.5

Groupes

Groupe	Description
RH	utilisateurs du service RH
DEV	équipe de développement
ADMINS	administrateurs système
SECURITY	équipe sécurité

Ressources sensibles

Ressource	Sensibilité
Base clients	élevée
Données RH	élevée
Active Directory	critique
Sauvegardes	critique
Secrets applicatifs	critique

Modèle de graphe attendu

Types de nœuds

Les étudiants doivent créer les types de nœuds suivants :

(:User)
(:Machine)
(:Service)
(:Vulnerability)
(:Group)
(:Resource)

Types de relations

Les étudiants doivent utiliser les relations suivantes :

(:User)-[:USES]->(:Machine)
(:User)-[:MEMBER_OF]->(:Group)
(:User)-[:ADMIN_OF]->(:Machine)

(:Group)-[:HAS_ACCESS_TO]->(:Machine)

(:Machine)-[:CONNECTED_TO]->(:Machine)
(:Machine)-[:EXPOSES]->(:Service)
(:Machine)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Machine)-[:HOSTS]->(:Resource)

Exemple de graphe simplifié

alice ──USES──> PC-ALICE

PC-ALICE ──CONNECTED_TO──> SRV-WEB
SRV-WEB ──CONNECTED_TO──> SRV-DB
SRV-DB ──CONNECTED_TO──> DC-01

DC-01 ──HOSTS──> Active Directory
SRV-DB ──HOSTS──> Base clients
NAS-BACKUP ──HOSTS──> Sauvegardes

Travail demandé

Les étudiants doivent construire un graphe Neo4j représentant le système d’information de CyberCorp.

Le graphe doit contenir au minimum :

5 utilisateurs ;
6 machines ;
4 groupes ;
5 services ;
5 vulnérabilités ;
3 ressources sensibles ;
20 relations minimum.

Les étudiants sont libres d’enrichir le scénario avec :

de nouvelles machines ;
de nouveaux utilisateurs ;
de nouvelles vulnérabilités ;
de nouveaux services ;
de nouvelles ressources ;
de nouvelles connexions réseau.

Étape 1 — Création des nœuds

Les étudiants doivent créer les utilisateurs, les machines, les groupes, les services, les vulnérabilités et les ressources.

Exemple de création d’utilisateurs

CREATE (:User {name: "alice", role: "RH"});
CREATE (:User {name: "bob", role: "Développeur"});
CREATE (:User {name: "charlie", role: "Admin Système"});
CREATE (:User {name: "diana", role: "RSSI"});
CREATE (:User {name: "eve", role: "Stagiaire"});

Exemple de création de machines

CREATE (:Machine {name: "PC-ALICE", type: "workstation", criticality: "low"});
CREATE (:Machine {name: "PC-BOB", type: "workstation", criticality: "medium"});
CREATE (:Machine {name: "SRV-WEB", type: "server", criticality: "medium"});
CREATE (:Machine {name: "SRV-DB", type: "database", criticality: "high"});
CREATE (:Machine {name: "DC-01", type: "domain_controller", criticality: "critical"});
CREATE (:Machine {name: "NAS-BACKUP", type: "backup_server", criticality: "critical"});

Exemple de création de services

CREATE (:Service {name: "SSH", port: 22});
CREATE (:Service {name: "HTTP", port: 80});
CREATE (:Service {name: "HTTPS", port: 443});
CREATE (:Service {name: "RDP", port: 3389});
CREATE (:Service {name: "SMB", port: 445});
CREATE (:Service {name: "MongoDB", port: 27017});

Exemple de création de vulnérabilités

CREATE (:Vulnerability {
  cve: "CVE-2021-44228",
  name: "Log4Shell",
  score: 10,
  description: "Exécution de code à distance via Log4j"
});

CREATE (:Vulnerability {
  cve: "CVE-2020-1472",
  name: "Zerologon",
  score: 10,
  description: "Élévation de privilèges sur contrôleur de domaine"
});

CREATE (:Vulnerability {
  cve: "CVE-2019-0708",
  name: "BlueKeep",
  score: 9.8,
  description: "Exécution de code à distance via RDP"
});

CREATE (:Vulnerability {
  cve: "CVE-2022-22965",
  name: "Spring4Shell",
  score: 9.8,
  description: "Exécution de code à distance sur application Spring"
});

CREATE (:Vulnerability {
  cve: "CVE-2023-0001",
  name: "SMB Misconfiguration",
  score: 7.5,
  description: "Mauvaise configuration du partage SMB"
});

Exemple de création de groupes

CREATE (:Group {name: "RH"});
CREATE (:Group {name: "DEV"});
CREATE (:Group {name: "ADMINS"});
CREATE (:Group {name: "SECURITY"});

Exemple de création de ressources

CREATE (:Resource {name: "Base clients", sensitivity: "high"});
CREATE (:Resource {name: "Données RH", sensitivity: "high"});
CREATE (:Resource {name: "Active Directory", sensitivity: "critical"});
CREATE (:Resource {name: "Sauvegardes", sensitivity: "critical"});
CREATE (:Resource {name: "Secrets applicatifs", sensitivity: "critical"});

Étape 2 — Création des relations

Les étudiants doivent ensuite connecter les nœuds entre eux afin de représenter le fonctionnement du système d’information.

Associer les utilisateurs à leurs machines

MATCH (u:User {name: "alice"}), (m:Machine {name: "PC-ALICE"})
CREATE (u)-[:USES]->(m);

MATCH (u:User {name: "bob"}), (m:Machine {name: "PC-BOB"})
CREATE (u)-[:USES]->(m);

Associer les utilisateurs à des groupes

MATCH (u:User {name: "alice"}), (g:Group {name: "RH"})
CREATE (u)-[:MEMBER_OF]->(g);

MATCH (u:User {name: "bob"}), (g:Group {name: "DEV"})
CREATE (u)-[:MEMBER_OF]->(g);

MATCH (u:User {name: "charlie"}), (g:Group {name: "ADMINS"})
CREATE (u)-[:MEMBER_OF]->(g);

MATCH (u:User {name: "diana"}), (g:Group {name: "SECURITY"})
CREATE (u)-[:MEMBER_OF]->(g);

Créer les connexions réseau

MATCH (a:Machine {name: "PC-ALICE"}), (b:Machine {name: "SRV-WEB"})
CREATE (a)-[:CONNECTED_TO]->(b);

MATCH (a:Machine {name: "PC-BOB"}), (b:Machine {name: "SRV-WEB"})
CREATE (a)-[:CONNECTED_TO]->(b);

MATCH (a:Machine {name: "SRV-WEB"}), (b:Machine {name: "SRV-DB"})
CREATE (a)-[:CONNECTED_TO]->(b);

MATCH (a:Machine {name: "SRV-DB"}), (b:Machine {name: "DC-01"})
CREATE (a)-[:CONNECTED_TO]->(b);

MATCH (a:Machine {name: "SRV-DB"}), (b:Machine {name: "NAS-BACKUP"})
CREATE (a)-[:CONNECTED_TO]->(b);

Associer les machines aux services exposés

MATCH (m:Machine {name: "SRV-WEB"}), (s:Service {name: "HTTP"})
CREATE (m)-[:EXPOSES]->(s);

MATCH (m:Machine {name: "SRV-WEB"}), (s:Service {name: "HTTPS"})
CREATE (m)-[:EXPOSES]->(s);

MATCH (m:Machine {name: "SRV-DB"}), (s:Service {name: "MongoDB"})
CREATE (m)-[:EXPOSES]->(s);

MATCH (m:Machine {name: "DC-01"}), (s:Service {name: "SMB"})
CREATE (m)-[:EXPOSES]->(s);

MATCH (m:Machine {name: "PC-BOB"}), (s:Service {name: "RDP"})
CREATE (m)-[:EXPOSES]->(s);

Associer les machines aux vulnérabilités

MATCH (m:Machine {name: "SRV-WEB"}), (v:Vulnerability {cve: "CVE-2021-44228"})
CREATE (m)-[:HAS_VULNERABILITY]->(v);

MATCH (m:Machine {name: "SRV-WEB"}), (v:Vulnerability {cve: "CVE-2022-22965"})
CREATE (m)-[:HAS_VULNERABILITY]->(v);

MATCH (m:Machine {name: "PC-BOB"}), (v:Vulnerability {cve: "CVE-2019-0708"})
CREATE (m)-[:HAS_VULNERABILITY]->(v);

MATCH (m:Machine {name: "DC-01"}), (v:Vulnerability {cve: "CVE-2020-1472"})
CREATE (m)-[:HAS_VULNERABILITY]->(v);

MATCH (m:Machine {name: "NAS-BACKUP"}), (v:Vulnerability {cve: "CVE-2023-0001"})
CREATE (m)-[:HAS_VULNERABILITY]->(v);

Associer les groupes aux machines

MATCH (g:Group {name: "RH"}), (m:Machine {name: "SRV-WEB"})
CREATE (g)-[:HAS_ACCESS_TO]->(m);

MATCH (g:Group {name: "DEV"}), (m:Machine {name: "SRV-DB"})
CREATE (g)-[:HAS_ACCESS_TO]->(m);

MATCH (g:Group {name: "ADMINS"}), (m:Machine {name: "DC-01"})
CREATE (g)-[:HAS_ACCESS_TO]->(m);

MATCH (g:Group {name: "ADMINS"}), (m:Machine {name: "NAS-BACKUP"})
CREATE (g)-[:HAS_ACCESS_TO]->(m);

Associer les machines aux ressources hébergées

MATCH (m:Machine {name: "SRV-DB"}), (r:Resource {name: "Base clients"})
CREATE (m)-[:HOSTS]->(r);

MATCH (m:Machine {name: "SRV-DB"}), (r:Resource {name: "Secrets applicatifs"})
CREATE (m)-[:HOSTS]->(r);

MATCH (m:Machine {name: "DC-01"}), (r:Resource {name: "Active Directory"})
CREATE (m)-[:HOSTS]->(r);

MATCH (m:Machine {name: "NAS-BACKUP"}), (r:Resource {name: "Sauvegardes"})
CREATE (m)-[:HOSTS]->(r);

Étape 3 — Requêtes d’exploration

Les étudiants doivent écrire des requêtes Cypher pour explorer le graphe.

Afficher tout le graphe

MATCH (n)
RETURN n;

Afficher les utilisateurs et leurs machines

MATCH (u:User)-[:USES]->(m:Machine)
RETURN u.name AS utilisateur, m.name AS machine;

Afficher les machines critiques

MATCH (m:Machine)
WHERE m.criticality = "critical"
RETURN m.name AS machine, m.type AS type;

Afficher les machines vulnérables

MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN 
  m.name AS machine,
  v.cve AS cve,
  v.name AS vulnerabilite,
  v.score AS score
ORDER BY v.score DESC;

Afficher les services exposés

MATCH (m:Machine)-[:EXPOSES]->(s:Service)
RETURN 
  m.name AS machine,
  s.name AS service,
  s.port AS port
ORDER BY m.name;

Étape 4 — Analyse des chemins d’attaque

Le poste compromis est :

PC-ALICE

Les étudiants doivent rechercher les chemins possibles vers :

SRV-DB
DC-01
NAS-BACKUP
les ressources critiques ;
les machines avec des vulnérabilités critiques.

Trouver un chemin vers le contrôleur de domaine

MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine {name: "DC-01"})
RETURN path;

Trouver tous les chemins vers des machines critiques

MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
WHERE target.criticality = "critical"
RETURN path;

Trouver les machines vulnérables accessibles depuis PC-ALICE

MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN 
  m.name AS machine,
  v.cve AS cve,
  v.name AS vulnerabilite,
  v.score AS score,
  path
ORDER BY v.score DESC;

Trouver les ressources accessibles depuis PC-ALICE

MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
RETURN 
  r.name AS ressource,
  r.sensitivity AS sensibilite,
  m.name AS machine,
  path
ORDER BY r.sensitivity DESC;

Trouver les utilisateurs ayant des droits admin

MATCH (u:User)-[:ADMIN_OF]->(m:Machine)
RETURN 
  u.name AS utilisateur,
  m.name AS machine_administree;

Trouver les utilisateurs pouvant accéder à des machines critiques via un groupe

MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high", "critical"]
RETURN 
  u.name AS utilisateur,
  g.name AS groupe,
  m.name AS machine,
  m.criticality AS criticite;

Étape 5 — Analyse cyber

Les étudiants doivent rédiger une analyse courte à partir de leurs résultats.

Leur analyse doit répondre aux questions suivantes :

Quelle machine est compromise au départ ?
Quels chemins permettent d’atteindre les ressources critiques ?
Quelles machines sont les plus dangereuses dans le graphe ?
Quelles vulnérabilités facilitent l’attaque ?
Quels utilisateurs ou groupes représentent un risque ?
Quels services exposés augmentent la surface d’attaque ?
Quelles connexions réseau devraient être supprimées ou limitées ?
Quelles mesures de sécurité recommandez-vous ?

Exemple d’analyse attendue

Le poste PC-ALICE est compromis à la suite d’un phishing.

Depuis PC-ALICE, un attaquant peut atteindre SRV-WEB, puis SRV-DB, puis DC-01.
Le serveur SRV-WEB expose HTTP et HTTPS et possède une vulnérabilité critique Log4Shell.
Le serveur SRV-DB héberge la base clients et les secrets applicatifs.
SRV-DB est connecté au contrôleur de domaine DC-01, ce qui représente un risque très élevé.

Le groupe DEV possède un accès à SRV-DB alors que cet accès devrait être limité.
Le groupe ADMINS possède des droits sur DC-01 et NAS-BACKUP. Une compromission d’un compte admin pourrait donc mener à une compromission complète du système d’information.

Recommandations :
- isoler les postes utilisateurs des serveurs critiques ;
- limiter les connexions directes vers SRV-DB ;
- corriger Log4Shell sur SRV-WEB ;
- corriger Zerologon sur DC-01 ;
- revoir les droits du groupe DEV ;
- appliquer le principe du moindre privilège ;
- segmenter le réseau ;
- surveiller les connexions anormales ;
- désactiver les services non nécessaires ;
- renforcer l’authentification des comptes administrateurs.

Livrables attendus

Livrable 1 — Graphe Neo4j

Les étudiants doivent fournir :

une capture d’écran du graphe Neo4j ;
le script Cypher de création des nœuds ;
le script Cypher de création des relations ;
une courte description du modèle de données.

Livrable 2 — Requêtes Cypher

Les étudiants doivent fournir :

au moins 3 requêtes de création ;
au moins 5 requêtes d’analyse ;
les résultats obtenus ;
un commentaire expliquant chaque résultat.

Livrable 3 — Rapport d’analyse cyber

Le rapport peut être rendu au format Markdown, PDF ou document texte.

Structure recommandée :

1. Présentation du système d’information modélisé
2. Schéma ou capture du graphe
3. Hypothèse d’attaque
4. Chemins d’attaque identifiés
5. Machines vulnérables
6. Services exposés
7. Utilisateurs et groupes à risque
8. Recommandations de sécurité
9. Conclusion

Livrable 4 — Présentation orale

Chaque groupe doit présenter :

le graphe construit ;
le scénario d’attaque choisi ;
un chemin d’attaque identifié ;
les requêtes Cypher utilisées ;
les vulnérabilités principales ;
les recommandations de sécurité proposées.

Critères d’évaluation

Critère	Points
Modélisation correcte du système d’information	4
Utilisation pertinente des nœuds et relations	3
Qualité des requêtes Cypher	4
Analyse des chemins d’attaque	4
Pertinence des recommandations cyber	5
Total	20

Contraintes techniques

Les étudiants doivent respecter les contraintes suivantes :

utiliser Neo4j ;
utiliser le langage Cypher ;
créer un graphe cohérent ;
utiliser au minimum 6 types de nœuds ;
utiliser au minimum 6 types de relations ;
produire des requêtes permettant d’analyser les chemins d’attaque ;
justifier les recommandations de sécurité.

Bonus possibles

Les étudiants peuvent obtenir des points bonus s’ils ajoutent :

un import de données depuis un fichier CSV ;
un script Python pour insérer les données dans Neo4j ;
une visualisation claire du graphe ;
un scoring de risque par machine ;
une classification des vulnérabilités par criticité ;
une analyse des chemins les plus courts ;
une proposition de segmentation réseau ;
une comparaison avant/après sécurisation du graphe.

Exemples de pistes d’amélioration du graphe

Les étudiants peuvent enrichir le projet avec :

des pare-feux ;
des VLAN ;
des comptes de service ;
des droits Active Directory ;
des accès VPN ;
des machines exposées à Internet ;
des logs de connexion ;
des tentatives d’authentification échouées ;
des relations de dépendance applicative ;
des niveaux de privilèges ;
des dates de dernier patch ;
des statuts de correction des vulnérabilités.

Objectif final

À la fin du projet, les étudiants doivent être capables d’expliquer comment une base de données graphe peut aider à représenter un système d’information et à analyser des risques cyber.

Ils doivent démontrer qu’ils savent :

créer un modèle de données orienté graphe ;
manipuler Neo4j ;
écrire des requêtes Cypher ;
identifier des chemins d’attaque ;
produire une analyse de risque ;
proposer des mesures concrètes de sécurisation.
