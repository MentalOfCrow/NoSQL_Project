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


def load_nodes(session) -> None:
    with (DATA_DIR / "nodes.csv").open(encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            label = row["label"]
            key = row["key"]
            properties = clean_properties(row)
            session.run(
                f"MERGE (n:{label} {{{key}: $value}}) SET n += $properties",
                value=properties[key],
                properties=properties,
            )


def load_relationships(session) -> None:
    with (DATA_DIR / "relationships.csv").open(encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            session.run(
                f"""
                MATCH (a:{row['startLabel']} {{{row['startKey']}: $start_value}})
                MATCH (b:{row['endLabel']} {{{row['endKey']}: $end_value}})
                MERGE (a)-[r:{row['type']}]->(b)
                """,
                start_value=row["startValue"],
                end_value=row["endValue"],
            )


def main() -> None:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
        load_nodes(session)
        load_relationships(session)
    driver.close()
    print("Import CSV termine.")


if __name__ == "__main__":
    main()
