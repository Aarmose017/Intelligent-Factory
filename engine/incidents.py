"""Incidents. Many alerts become one incident, and each incident moves open -> contained -> resolved.

shortcut: incidents live in memory and are lost on restart. CLAUDE.md plans SQLite; move there when the
live receiver has to survive a restart mid-incident. Every state change is in the JSONL log meanwhile.
"""

NEXT = {"open": {"contained", "resolved"}, "contained": {"resolved"}, "resolved": set()}


def move(incident, state, now):
    if state not in NEXT[incident["state"]]:
        raise ValueError(f"incident {incident['id']} cannot go from {incident['state']} to {state}")
    incident["state"] = state
    incident[f"{state}_at"] = now


class Incidents:
    def __init__(self, window):
        self.window = window
        self.all = []

    def correlate(self, alert, now):
        """Return (incident, is_new). An alert joins the latest incident with the same class and subsystem
        while that incident is unresolved, or within `window` after it was resolved. The second part soaks up
        stale readings that keep firing for a moment after recovery."""
        key = (alert.get("incident_class"), alert.get("affected_subsystem"))
        inc = next((i for i in reversed(self.all) if i["key"] == key), None)
        if inc and inc["state"] == "open" and (inc["tier"] or 0) < 2 and now - inc["last_alert"] > self.window:
            # Tier 0 and 1 change nothing on the line, so they end when their alerts stop.
            move(inc, "resolved", inc["last_alert"])
        if inc and (inc["state"] != "resolved" or now - inc["resolved_at"] <= self.window):
            inc["last_alert"] = now
            inc["alerts"] += 1
            return inc, False
        inc = {"id": len(self.all) + 1, "key": key, "incident_class": key[0], "subsystem": key[1],
               "state": "open", "tier": None, "technique": None, "opened_at": now, "last_alert": now,
               "alerts": 1, "actions": []}
        self.all.append(inc)
        return inc, True
