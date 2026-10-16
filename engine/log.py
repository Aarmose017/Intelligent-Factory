import json
import logging
import math
import pathlib
import threading
from datetime import datetime, timezone

# Anchored to the repo, not the working directory, so the log always lands in
# the same place no matter where uvicorn is started from.
LOG = pathlib.Path(__file__).resolve().parent.parent / "logs" / "response.jsonl"

logger = logging.getLogger(__name__)

# FastAPI runs sync handlers in a thread pool. Appending from several threads at
# once is not atomic on Windows and large entries get lost or interleaved.
_lock = threading.Lock()


def now():
    """UTC timestamp in ISO 8601. Used for every time we record ourselves."""
    return datetime.now(timezone.utc).isoformat()


def _finite(value):
    """Replace NaN and infinity with a string so every line stays valid JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {k: _finite(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_finite(v) for v in value]
    return value


def write(alert, rule, received_at=None, decision_ms=None, **extra):
    """Append one JSON object per line. Every measurement later reads this file.

    emitted_at and observed_at come from Team B's alert. received_at is when our
    receiver got it, logged_at is when the decision was written. Keeping all four
    lets Sprint 4 split detector latency from ours. decision_ms is our own time
    from receipt to decision, taken from a monotonic clock, so it is not affected
    by clock changes or by the coarse wall clock on older Python on Windows.

    A log failure is reported and swallowed. Losing one line is bad, but taking
    the response layer down because a disk is full is worse.
    """
    if not isinstance(alert, dict):
        alert = {}
    if not isinstance(rule, dict):
        rule = {}
    entry = {
        "logged_at": now(),
        "received_at": received_at,
        "emitted_at": alert.get("emitted_at"),
        "observed_at": alert.get("observed_at"),
        "decision_ms": decision_ms,
        "alert_id": alert.get("alert_id"),
        "incident_class": alert.get("incident_class"),
        "confidence": alert.get("confidence"),
        "affected_subsystem": alert.get("affected_subsystem"),
        "rule": rule.get("technique"),
        "tier": rule.get("tier"),
        **extra,  # incident events: event, incident_id, sim time t, and the tier actually used
    }
    try:
        line = json.dumps(_finite(entry), default=str, allow_nan=False)
        with _lock:
            LOG.parent.mkdir(parents=True, exist_ok=True)
            # newline="\n" keeps line endings the same on Windows and Linux.
            with LOG.open("a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
    except (OSError, TypeError, ValueError):
        logger.exception("could not write response log entry for alert %s", entry["alert_id"])
    return entry
