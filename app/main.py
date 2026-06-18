import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "app" / "static"
CYPHER_DIR = BASE_DIR / "cypher"

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "cybercorp123")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

ANALYSIS_QUERIES = [
    {
        "id": "all_graph",
        "title": "Afficher tout le graphe",
        "query": "MATCH (n) RETURN n;",
        "comment": "Permet de verifier que tous les noeuds du systeme d'information sont presents dans Neo4j.",
    },
    {
        "id": "critical_machines",
        "title": "Machines critiques",
        "query": 'MATCH (m:Machine) WHERE m.criticality = "critical" RETURN m.name AS machine, m.type AS type;',
        "comment": "Identifie les actifs les plus sensibles : le controleur de domaine et les sauvegardes.",
    },
    {
        "id": "vulnerable_machines",
        "title": "Machines vulnerables",
        "query": "MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score ORDER BY v.score DESC;",
        "comment": "Classe les faiblesses techniques par score CVSS afin de prioriser les corrections.",
    },
    {
        "id": "attack_paths",
        "title": "Chemins vers les machines critiques",
        "query": 'MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine) WHERE target.criticality = "critical" RETURN path;',
        "comment": "Montre les chemins de deplacement lateral possibles depuis le poste compromis.",
    },
    {
        "id": "reachable_resources",
        "title": "Ressources accessibles depuis PC-ALICE",
        "query": 'MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource) RETURN r.name AS ressource, r.sensitivity AS sensibilite, m.name AS machine, path ORDER BY r.sensitivity DESC;',
        "comment": "Liste les donnees sensibles qui deviennent atteignables depuis le poste compromis.",
    },
    {
        "id": "risky_groups",
        "title": "Utilisateurs et groupes a risque",
        "query": 'MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine) WHERE m.criticality IN ["high", "critical"] RETURN u.name AS utilisateur, g.name AS groupe, m.name AS machine, m.criticality AS criticite;',
        "comment": "Met en evidence les droits de groupe trop permissifs sur les serveurs sensibles.",
    },
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    wait_for_neo4j()
    yield
    driver.close()


app = FastAPI(title="CyberCorp Neo4j Attack Path Analysis", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def wait_for_neo4j(max_attempts: int = 30, delay: float = 2.0) -> None:
    for _ in range(max_attempts):
        try:
            driver.verify_connectivity()
            return
        except ServiceUnavailable:
            time.sleep(delay)
    raise RuntimeError("Neo4j est indisponible apres plusieurs tentatives")


def run_query(query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        with driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]
    except ServiceUnavailable as exc:
        raise HTTPException(status_code=503, detail="Neo4j est indisponible") from exc
    except Neo4jError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def run_cypher_file(path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    statements = [part.strip() for part in content.split(";") if part.strip()]
    with driver.session() as session:
        for statement in statements:
            session.run(statement)


def collect_dashboard_data() -> dict[str, Any]:
    return {
        "stats": stats(),
        "graph": graph(),
        "attackPaths": attack_paths(),
        "shortestPaths": shortest_paths(),
        "vulnerableMachines": vulnerable_machines(),
        "resources": reachable_resources(),
        "exposedServices": exposed_services(),
        "identityRisks": identity_risks(),
        "recommendations": recommendations(),
        "segmentation": segmentation_plan(),
        "queryCatalog": query_catalog(),
    }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    run_query("RETURN 1 AS ok")
    return {"status": "ok"}


@app.post("/api/seed")
def seed_graph() -> dict[str, str]:
    try:
        run_cypher_file(CYPHER_DIR / "01_constraints.cypher")
        run_cypher_file(CYPHER_DIR / "02_seed_graph.cypher")
        return {"status": "loaded"}
    except Neo4jError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    rows = run_query(
        """
        MATCH (n)
        WITH labels(n)[0] AS label, count(n) AS total
        ORDER BY label
        RETURN collect({label: label, total: total}) AS nodes
        """
    )
    rels = run_query(
        """
        MATCH ()-[r]->()
        WITH type(r) AS type, count(r) AS total
        ORDER BY type
        RETURN collect({type: type, total: total}) AS relationships
        """
    )
    node_counts = rows[0]["nodes"] if rows else []
    rel_counts = rels[0]["relationships"] if rels else []
    return {
        "nodes": node_counts,
        "relationships": rel_counts,
        "totalNodes": sum(row["total"] for row in node_counts),
        "totalRelationships": sum(row["total"] for row in rel_counts),
    }


@app.get("/api/graph")
def graph() -> dict[str, list[dict[str, Any]]]:
    nodes = run_query(
        """
        MATCH (n)
        RETURN id(n) AS id, labels(n) AS labels, properties(n) AS properties
        ORDER BY coalesce(n.name, n.cve)
        """
    )
    relationships = run_query(
        """
        MATCH (a)-[r]->(b)
        RETURN id(r) AS id, id(a) AS source, id(b) AS target, type(r) AS type
        ORDER BY type(r)
        """
    )
    return {"nodes": nodes, "relationships": relationships}


@app.get("/api/attack-paths")
def attack_paths() -> dict[str, list[dict[str, Any]]]:
    rows = run_query(
        """
        MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
        WHERE target.criticality IN ["high", "critical"]
        RETURN
          target.name AS target,
          target.criticality AS criticality,
          [node IN nodes(path) | node.name] AS nodes,
          length(path) AS hops
        ORDER BY target.criticality DESC, hops ASC
        """
    )
    return {"paths": rows}


@app.get("/api/shortest-paths")
def shortest_paths() -> dict[str, list[dict[str, Any]]]:
    rows = run_query(
        """
        MATCH (start:Machine {name: "PC-ALICE"}), (target:Machine)
        WHERE target.criticality IN ["high", "critical"]
        MATCH path = shortestPath((start)-[:CONNECTED_TO*1..5]->(target))
        RETURN
          target.name AS target,
          target.criticality AS criticality,
          [node IN nodes(path) | node.name] AS nodes,
          length(path) AS hops
        ORDER BY hops ASC, target.name
        """
    )
    return {"paths": rows}


@app.get("/api/vulnerable-machines")
def vulnerable_machines() -> dict[str, list[dict[str, Any]]]:
    rows = run_query(
        """
        MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN
          m.name AS machine,
          m.criticality AS criticality,
          v.cve AS cve,
          v.name AS vulnerability,
          v.score AS score,
          [node IN nodes(path) | coalesce(node.name, node.cve)] AS path
        ORDER BY v.score DESC
        """
    )
    return {"machines": rows}


@app.get("/api/resources")
def reachable_resources() -> dict[str, list[dict[str, Any]]]:
    rows = run_query(
        """
        MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
        RETURN
          r.name AS resource,
          r.sensitivity AS sensitivity,
          m.name AS machine,
          [node IN nodes(path) | coalesce(node.name, node.cve)] AS path
        ORDER BY r.sensitivity DESC, r.name
        """
    )
    return {"resources": rows}


@app.get("/api/exposed-services")
def exposed_services() -> dict[str, list[dict[str, Any]]]:
    rows = run_query(
        """
        MATCH (m:Machine)-[:EXPOSES]->(s:Service)
        OPTIONAL MATCH (m)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN
          m.name AS machine,
          m.criticality AS criticality,
          s.name AS service,
          s.port AS port,
          collect(v.cve) AS cves
        ORDER BY m.name, s.port
        """
    )
    return {"services": rows}


@app.get("/api/identity-risks")
def identity_risks() -> dict[str, list[dict[str, Any]]]:
    rows = run_query(
        """
        MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
        WHERE m.criticality IN ["high", "critical"]
        RETURN
          u.name AS user,
          u.role AS role,
          g.name AS group,
          m.name AS machine,
          m.criticality AS criticality
        ORDER BY m.criticality DESC, user
        """
    )
    admins = run_query(
        """
        MATCH (u:User)-[:ADMIN_OF]->(m:Machine)
        RETURN u.name AS user, u.role AS role, m.name AS machine, m.criticality AS criticality
        ORDER BY m.criticality DESC, user
        """
    )
    return {"groupRisks": rows, "adminRights": admins}


@app.get("/api/recommendations")
def recommendations() -> dict[str, list[str]]:
    return {
        "recommendations": [
            "Isoler les postes utilisateurs des serveurs critiques.",
            "Limiter les connexions PC-ALICE -> SRV-WEB et SRV-WEB -> SRV-DB aux flux strictement necessaires.",
            "Supprimer ou filtrer les connexions SRV-DB -> DC-01 et SRV-DB -> NAS-BACKUP.",
            "Corriger Log4Shell et Spring4Shell sur SRV-WEB.",
            "Corriger Zerologon sur DC-01.",
            "Restreindre l'acces du groupe DEV a SRV-DB.",
            "Appliquer le principe du moindre privilege aux groupes ADMINS, DEV et RH.",
            "Desactiver les services inutiles et surveiller RDP, SMB, SSH, MongoDB, HTTP et HTTPS.",
            "Activer MFA sur les comptes administrateurs.",
            "Mettre en place une supervision des chemins d'attaque et des connexions laterales.",
        ]
    }


@app.get("/api/query-catalog")
def query_catalog() -> dict[str, list[dict[str, str]]]:
    return {"queries": ANALYSIS_QUERIES}


@app.get("/api/query-results")
def query_results() -> dict[str, list[dict[str, Any]]]:
    return {
        "results": [
            {
                "title": "Utilisateurs et machines",
                "comment": "Chaque utilisateur est rattache a une machine de travail.",
                "rows": run_query(
                    """
                    MATCH (u:User)-[:USES]->(m:Machine)
                    RETURN u.name AS utilisateur, m.name AS machine
                    ORDER BY utilisateur
                    """
                ),
            },
            {
                "title": "Machines critiques",
                "comment": "DC-01 et NAS-BACKUP sont les machines dont la compromission aurait le plus d'impact.",
                "rows": run_query(
                    """
                    MATCH (m:Machine)
                    WHERE m.criticality = "critical"
                    RETURN m.name AS machine, m.type AS type, m.riskScore AS score_risque
                    ORDER BY score_risque DESC
                    """
                ),
            },
            {
                "title": "Vulnerabilites prioritaires",
                "comment": "Les scores les plus eleves doivent etre corriges en premier.",
                "rows": run_query(
                    """
                    MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score
                    ORDER BY v.score DESC
                    """
                ),
            },
            {
                "title": "Services exposes",
                "comment": "Les services exposes augmentent la surface d'attaque.",
                "rows": run_query(
                    """
                    MATCH (m:Machine)-[:EXPOSES]->(s:Service)
                    RETURN m.name AS machine, s.name AS service, s.port AS port
                    ORDER BY machine, port
                    """
                ),
            },
        ]
    }


@app.get("/api/segmentation-plan")
def segmentation_plan() -> dict[str, Any]:
    return {
        "before": [
            "PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01",
            "PC-ALICE -> SRV-WEB -> SRV-DB -> NAS-BACKUP",
            "PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01 -> NAS-BACKUP",
        ],
        "actions": [
            "Bloquer les flux directs des postes utilisateurs vers les serveurs internes hors proxy applicatif.",
            "Limiter SRV-WEB -> SRV-DB au seul port applicatif necessaire.",
            "Interdire SRV-DB -> DC-01 sauf flux Active Directory strictement justifies.",
            "Isoler NAS-BACKUP dans un VLAN de sauvegarde non joignable depuis les serveurs applicatifs.",
            "Restreindre DEV sur SRV-DB et separer les privileges d'administration.",
        ],
        "after": [
            "PC-ALICE ne peut plus atteindre directement SRV-DB, DC-01 ou NAS-BACKUP.",
            "SRV-WEB reste expose uniquement sur HTTP/HTTPS controles.",
            "Les ressources critiques sont protegees par segmentation et moindre privilege.",
        ],
    }


@app.get("/api/export")
def export() -> dict[str, Any]:
    return collect_dashboard_data()
