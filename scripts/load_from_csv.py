import argparse
import csv
import os
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "cybercorp123")

ALLOWED_LABELS = {"User", "Machine", "Service", "Vulnerability", "Group", "Resource"}
ALLOWED_KEYS = {"name", "cve"}
ALLOWED_RELATIONSHIPS = {
    "USES",
    "MEMBER_OF",
    "ADMIN_OF",
    "HAS_ACCESS_TO",
    "CONNECTED_TO",
    "EXPOSES",
    "HAS_VULNERABILITY",
    "HOSTS",
}


def validate_identifier(value: str, allowed: set[str], kind: str) -> str:
    if value not in allowed:
        raise ValueError(f"{kind} non autorise dans le CSV: {value}")
    return value


def clean_properties(row: dict[str, str]) -> dict[str, Any]:
    reserved = {"label", "key"}
    properties: dict[str, Any] = {}
    for key, value in row.items():
        if key in reserved or value == "":
            continue
        if key in {"port", "riskScore"}:
            properties[key] = int(value)
        elif key == "score":
            properties[key] = float(value)
        else:
            properties[key] = value
    return properties


def create_constraints(session) -> None:
    constraints = [
        "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
        "CREATE CONSTRAINT machine_name IF NOT EXISTS FOR (m:Machine) REQUIRE m.name IS UNIQUE",
        "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE",
        "CREATE CONSTRAINT group_name IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE",
        "CREATE CONSTRAINT resource_name IF NOT EXISTS FOR (r:Resource) REQUIRE r.name IS UNIQUE",
    ]
    for query in constraints:
        session.run(query)


def load_nodes(session) -> int:
    count = 0
    with (DATA_DIR / "nodes.csv").open(encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            label = validate_identifier(row["label"], ALLOWED_LABELS, "Label")
            key = validate_identifier(row["key"], ALLOWED_KEYS, "Cle")
            properties = clean_properties(row)
            if key not in properties:
                raise ValueError(f"Ligne CSV invalide: propriete cle {key} absente pour {label}")
            session.run(
                f"MERGE (n:{label} {{{key}: $value}}) SET n += $properties",
                value=properties[key],
                properties=properties,
            )
            count += 1
    return count


def load_relationships(session) -> int:
    count = 0
    with (DATA_DIR / "relationships.csv").open(encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            start_label = validate_identifier(row["startLabel"], ALLOWED_LABELS, "Label source")
            start_key = validate_identifier(row["startKey"], ALLOWED_KEYS, "Cle source")
            rel_type = validate_identifier(row["type"], ALLOWED_RELATIONSHIPS, "Relation")
            end_label = validate_identifier(row["endLabel"], ALLOWED_LABELS, "Label cible")
            end_key = validate_identifier(row["endKey"], ALLOWED_KEYS, "Cle cible")
            session.run(
                f"""
                MATCH (a:{start_label} {{{start_key}: $start_value}})
                MATCH (b:{end_label} {{{end_key}: $end_value}})
                MERGE (a)-[r:{rel_type}]->(b)
                """,
                start_value=row["startValue"],
                end_value=row["endValue"],
            )
            count += 1
    return count


def graph_counts(session) -> dict[str, int]:
    nodes = session.run("MATCH (n) RETURN count(n) AS total").single()["total"]
    relationships = session.run("MATCH ()-[r]->() RETURN count(r) AS total").single()["total"]
    return {"nodes": nodes, "relationships": relationships}


def main() -> None:
    parser = argparse.ArgumentParser(description="Import automatique du graphe CyberCorp depuis les fichiers CSV.")
    parser.add_argument("--clear", action="store_true", help="Supprime le graphe existant avant l'import.")
    args = parser.parse_args()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        create_constraints(session)
        if args.clear:
            session.run("MATCH (n) DETACH DELETE n")
        nodes = load_nodes(session)
        relationships = load_relationships(session)
        counts = graph_counts(session)
    driver.close()

    print("Import CSV termine.")
    print(f"Noeuds lus depuis CSV: {nodes}")
    print(f"Relations lues depuis CSV: {relationships}")
    print(f"Graphe Neo4j: {counts['nodes']} noeuds, {counts['relationships']} relations")


if __name__ == "__main__":
    main()
