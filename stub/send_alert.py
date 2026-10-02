"""Fake alert sender. Stands in for Team B's detector so we are not blocked."""
import json
import sys

import httpx

URL = "http://localhost:8000/alert"


def main(path="schema/sample_alert.json"):
    with open(path) as f:
        alert = json.load(f)
    r = httpx.post(URL, json=alert)
    print(r.status_code, r.json())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "schema/sample_alert.json")
