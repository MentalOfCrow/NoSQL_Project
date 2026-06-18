import os
from pathlib import Path

from neo4j import GraphDatabase


BASE_DIR = Path(__file__).resolve().parent.parent
CYPHER_DIR = BASE_DIR / "cypher"

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "cybercorp123")


def run_file(session, path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    statements = [statement.strip() for statement in content.split(";") if statement.strip()]
    for statement in statements:
        session.run(statement)


def main() -> None:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        run_file(session, CYPHER_DIR / "01_constraints.cypher")
        run_file(session, CYPHER_DIR / "02_seed_graph.cypher")
    driver.close()
    print("Graphe CyberCorp charge dans Neo4j.")


if __name__ == "__main__":
    main()
