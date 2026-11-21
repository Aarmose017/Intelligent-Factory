"""Fake alert sender. Stands in for Team B's detector so we are not blocked."""
import json
import os
import sys

import httpx

URL = "http://localhost:8000/alert"


def main(path="schema/sample_alert.json"):
    with open(path) as f:
        alert = json.load(f)
    key = os.environ.get("ALERT_KEY")  # the same shared secret the receiver checks, when one is set
    r = httpx.post(URL, json=alert, headers={"X-Alert-Key": key} if key else None)
    print(r.status_code, r.json())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "schema/sample_alert.json")
