MATCH (n) DETACH DELETE n;

CREATE (:User {name: "alice", role: "Employee RH"});
CREATE (:User {name: "bob", role: "Developpeur"});
CREATE (:User {name: "charlie", role: "Administrateur systeme"});
CREATE (:User {name: "diana", role: "RSSI"});
CREATE (:User {name: "eve", role: "Stagiaire"});

CREATE (:Machine {name: "PC-ALICE", type: "workstation", criticality: "low", riskScore: 30});
CREATE (:Machine {name: "PC-BOB", type: "developer_workstation", criticality: "medium", riskScore: 60});
CREATE (:Machine {name: "SRV-WEB", type: "web_server", criticality: "medium", riskScore: 85});
CREATE (:Machine {name: "SRV-DB", type: "database", criticality: "high", riskScore: 90});
CREATE (:Machine {name: "DC-01", type: "domain_controller", criticality: "critical", riskScore: 100});
CREATE (:Machine {name: "NAS-BACKUP", type: "backup_server", criticality: "critical", riskScore: 95});

CREATE (:Service {name: "SSH", port: 22});
CREATE (:Service {name: "HTTP", port: 80});
CREATE (:Service {name: "HTTPS", port: 443});
CREATE (:Service {name: "RDP", port: 3389});
CREATE (:Service {name: "SMB", port: 445});
CREATE (:Service {name: "MongoDB", port: 27017});

CREATE (:Vulnerability {cve: "CVE-2021-44228", name: "Log4Shell", score: 10, severity: "critical", description: "Execution de code a distance via Log4j"});
CREATE (:Vulnerability {cve: "CVE-2020-1472", name: "Zerologon", score: 10, severity: "critical", description: "Elevation de privileges sur controleur de domaine"});
CREATE (:Vulnerability {cve: "CVE-2019-0708", name: "BlueKeep", score: 9.8, severity: "critical", description: "Execution de code a distance via RDP"});
CREATE (:Vulnerability {cve: "CVE-2022-22965", name: "Spring4Shell", score: 9.8, severity: "critical", description: "Execution de code a distance sur application Spring"});
CREATE (:Vulnerability {cve: "CVE-2023-0001", name: "SMB Misconfiguration", score: 7.5, severity: "high", description: "Mauvaise configuration du partage SMB"});

CREATE (:Group {name: "RH", description: "Utilisateurs du service RH"});
CREATE (:Group {name: "DEV", description: "Equipe de developpement"});
CREATE (:Group {name: "ADMINS", description: "Administrateurs systeme"});
CREATE (:Group {name: "SECURITY", description: "Equipe securite"});

CREATE (:Resource {name: "Base clients", sensitivity: "high"});
CREATE (:Resource {name: "Donnees RH", sensitivity: "high"});
CREATE (:Resource {name: "Active Directory", sensitivity: "critical"});
CREATE (:Resource {name: "Sauvegardes", sensitivity: "critical"});
CREATE (:Resource {name: "Secrets applicatifs", sensitivity: "critical"});

MATCH (u:User {name: "alice"}), (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "bob"}), (m:Machine {name: "PC-BOB"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "DC-01"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "diana"}), (m:Machine {name: "PC-BOB"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "eve"}), (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);

MATCH (u:User {name: "alice"}), (g:Group {name: "RH"}) CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "bob"}), (g:Group {name: "DEV"}) CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "charlie"}), (g:Group {name: "ADMINS"}) CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "diana"}), (g:Group {name: "SECURITY"}) CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "eve"}), (g:Group {name: "RH"}) CREATE (u)-[:MEMBER_OF]->(g);

MATCH (u:User {name: "charlie"}), (m:Machine {name: "DC-01"}) CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "NAS-BACKUP"}) CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name: "diana"}), (m:Machine {name: "SRV-WEB"}) CREATE (u)-[:ADMIN_OF]->(m);

MATCH (a:Machine {name: "PC-ALICE"}), (b:Machine {name: "SRV-WEB"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "PC-BOB"}), (b:Machine {name: "SRV-WEB"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-WEB"}), (b:Machine {name: "SRV-DB"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-DB"}), (b:Machine {name: "DC-01"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-DB"}), (b:Machine {name: "NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "DC-01"}), (b:Machine {name: "NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);

MATCH (m:Machine {name: "SRV-WEB"}), (s:Service {name: "HTTP"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-WEB"}), (s:Service {name: "HTTPS"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-WEB"}), (s:Service {name: "SSH"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-DB"}), (s:Service {name: "MongoDB"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "DC-01"}), (s:Service {name: "SMB"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "PC-BOB"}), (s:Service {name: "RDP"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "NAS-BACKUP"}), (s:Service {name: "SMB"}) CREATE (m)-[:EXPOSES]->(s);

MATCH (m:Machine {name: "SRV-WEB"}), (v:Vulnerability {cve: "CVE-2021-44228"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "SRV-WEB"}), (v:Vulnerability {cve: "CVE-2022-22965"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "PC-BOB"}), (v:Vulnerability {cve: "CVE-2019-0708"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "DC-01"}), (v:Vulnerability {cve: "CVE-2020-1472"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "NAS-BACKUP"}), (v:Vulnerability {cve: "CVE-2023-0001"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);

MATCH (g:Group {name: "RH"}), (m:Machine {name: "SRV-WEB"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "DEV"}), (m:Machine {name: "SRV-DB"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}), (m:Machine {name: "DC-01"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}), (m:Machine {name: "NAS-BACKUP"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "SECURITY"}), (m:Machine {name: "SRV-WEB"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);

MATCH (m:Machine {name: "SRV-DB"}), (r:Resource {name: "Base clients"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "SRV-DB"}), (r:Resource {name: "Secrets applicatifs"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "SRV-DB"}), (r:Resource {name: "Donnees RH"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "DC-01"}), (r:Resource {name: "Active Directory"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "NAS-BACKUP"}), (r:Resource {name: "Sauvegardes"}) CREATE (m)-[:HOSTS]->(r);
