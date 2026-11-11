import math
import pathlib

import yaml

# Anchored to the repo, not the working directory, like the log path.
DEFAULT_PATH = pathlib.Path(__file__).resolve().parent.parent / "policy" / "policy.yaml"


def _number(x):
    # bool is a subclass of int in Python, and True would otherwise count as confidence 1.0.
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def load_policy(path=DEFAULT_PATH):
    """Read the policy table from YAML. Called once at startup, so a broken rule fails here, not mid-attack."""
    with open(path) as f:
        rules = yaml.safe_load(f)["rules"]
    for i, r in enumerate(rules, 1):
        if not isinstance(r.get("incident_class"), str):
            raise ValueError(f"policy rule {i}: incident_class must be a name, got {r.get('incident_class')!r}")
        if not (_number(r.get("min_confidence")) and 0 <= r["min_confidence"] <= 1):
            raise ValueError(f"policy rule {i}: min_confidence must be a number from 0 to 1, got {r.get('min_confidence')!r}")
        if isinstance(r.get("tier"), bool) or r.get("tier") not in (0, 1, 2, 3):
            raise ValueError(f"policy rule {i}: tier must be 0, 1, 2 or 3, got {r.get('tier')!r}")
    return rules


def load_settings(path=DEFAULT_PATH):
    """Timings and limits from the same file, so policy stays in config."""
    with open(path) as f:
        return yaml.safe_load(f)["settings"]


def pick_tier(alert, rules):
    """Return the matching rule with the highest tier, or None if nothing matches.
    A confidence that is not a number matches nothing, since it comes from outside our code."""
    confidence = alert.get("confidence", 0)
    if not _number(confidence):
        return None
    matches = [
        r for r in rules
        if r["incident_class"] == alert.get("incident_class")
        and confidence >= r["min_confidence"]
    ]
    if not matches:
        return None
    return max(matches, key=lambda r: r["tier"])
