import json
import sys
import urllib.error
import urllib.request


BASE_URL = "http://localhost:8000"


def request(path: str, method: str = "GET") -> dict:
    req = urllib.request.Request(f"{BASE_URL}{path}", method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    try:
        request("/api/bootstrap", method="POST")
        diagnostics = request("/api/diagnostics")
        counts = diagnostics["counts"]
        if counts["nodes"] < 31 or counts["relationships"] < 41:
            print(f"Erreur: graphe incomplet: {counts}")
            return 1
        print(f"OK: {counts['nodes']} noeuds, {counts['relationships']} relations")
        return 0
    except (urllib.error.URLError, TimeoutError, KeyError) as exc:
        print(f"Erreur smoke test: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
