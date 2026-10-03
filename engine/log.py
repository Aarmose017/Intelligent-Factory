import json
import logging
import pathlib
from datetime import datetime, timezone

LOG = pathlib.Path("logs/response.jsonl")

logger = logging.getLogger(__name__)


def now():
    """UTC timestamp in ISO 8601. Used for every time we record ourselves."""
    return datetime.now(timezone.utc).isoformat()


def write(alert, rule, received_at=None):
    """Append one JSON object per line. Every measurement later reads this file.

    emitted_at and observed_at come from Team B's alert. received_at is when our
    receiver got it, logged_at is when the decision was written. Keeping all four
    lets Sprint 4 split detector latency from ours.

    A log failure is reported and swallowed. Losing one line is bad, but taking
    the response layer down because a disk is full is worse.
    """
    if not isinstance(alert, dict):
        alert = {}
    entry = {
        "logged_at": now(),
        "received_at": received_at,
        "emitted_at": alert.get("emitted_at"),
        "observed_at": alert.get("observed_at"),
        "alert_id": alert.get("alert_id"),
        "incident_class": alert.get("incident_class"),
        "confidence": alert.get("confidence"),
        "affected_subsystem": alert.get("affected_subsystem"),
        "rule": rule["technique"] if rule else None,
        "tier": rule["tier"] if rule else None,
    }
    try:
        line = json.dumps(entry, default=str)
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except (OSError, TypeError, ValueError):
        logger.exception("could not write response log entry for alert %s", entry["alert_id"])
    return entry
