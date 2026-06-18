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
