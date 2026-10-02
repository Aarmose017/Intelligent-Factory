import json
import pathlib
from datetime import datetime, timezone

LOG = pathlib.Path("logs/response.jsonl")


def write(alert, rule):
    """Append one JSON object per line. Every measurement later reads this file."""
    LOG.parent.mkdir(exist_ok=True)
    entry = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert.get("alert_id"),
        "incident_class": alert.get("incident_class"),
        "confidence": alert.get("confidence"),
        "affected_subsystem": alert.get("affected_subsystem"),
        "rule": rule["technique"] if rule else None,
        "tier": rule["tier"] if rule else None,
    }
    with LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry
