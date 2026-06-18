import os
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
app = FastAPI(title="CyberCorp Neo4j Attack Path Analysis")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


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


@app.on_event("shutdown")
def close_driver() -> None:
    driver.close()


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
