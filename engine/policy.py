import yaml

DEFAULT_PATH = "policy/policy.yaml"


def load_policy(path=DEFAULT_PATH):
    """Read the policy table from YAML. Called once at startup."""
    with open(path) as f:
        return yaml.safe_load(f)["rules"]


def load_settings(path=DEFAULT_PATH):
    """Timings and limits from the same file, so policy stays in config."""
    with open(path) as f:
        return yaml.safe_load(f)["settings"]


def pick_tier(alert, rules):
    """Return the matching rule with the highest tier, or None if nothing matches."""
    matches = [
        r for r in rules
        if r["incident_class"] == alert.get("incident_class")
        and alert.get("confidence", 0) >= r["min_confidence"]
    ]
    if not matches:
        return None
    return max(matches, key=lambda r: r["tier"])
