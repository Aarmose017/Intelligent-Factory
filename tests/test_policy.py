import pathlib

import pytest

from engine import policy
from engine.policy import load_policy, pick_tier

RULES = load_policy()


@pytest.mark.parametrize("confidence", [None, "high", True, [0.9], float("nan")])
def test_confidence_that_is_not_a_number_matches_nothing(confidence):
    # B1: None and "high" crashed, and True counted as 1.0, which is tier 2.
    assert pick_tier({"incident_class": "sensor_drift", "confidence": confidence}, RULES) is None


@pytest.mark.parametrize("broken, message", [
    ("tier: 7", "tier"),
    ("min_confidence: high", "min_confidence"),
    ("incident_class: null", "incident_class"),
])
def test_broken_policy_fails_at_load_with_a_readable_error(tmp_path, broken, message):
    # B4: a bad rule used to load fine and crash later, in the middle of an attack.
    good = pathlib.Path(policy.DEFAULT_PATH).read_text(encoding="utf-8")
    key = broken.split(":")[0]
    bad = good.replace(next(line for line in good.splitlines() if line.strip().startswith(key + ":")),
                       "    " + broken, 1)
    (tmp_path / "policy.yaml").write_text(bad, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_policy(tmp_path / "policy.yaml")


def test_policy_path_does_not_depend_on_working_directory():
    # B5: the default path was relative, so starting anywhere but the repo folder failed.
    repo = pathlib.Path(__file__).resolve().parent.parent
    assert pathlib.Path(policy.DEFAULT_PATH) == repo / "policy" / "policy.yaml"


def test_high_confidence_drift_isolates():
    alert = {"incident_class": "sensor_drift", "confidence": 0.9}
    assert pick_tier(alert, RULES)["tier"] == 2


def test_low_confidence_drift_alerts_only():
    alert = {"incident_class": "sensor_drift", "confidence": 0.5}
    assert pick_tier(alert, RULES)["tier"] == 1


def test_below_all_thresholds_matches_nothing():
    alert = {"incident_class": "sensor_drift", "confidence": 0.1}
    assert pick_tier(alert, RULES) is None


def test_unknown_class_matches_nothing():
    alert = {"incident_class": "not_a_class", "confidence": 0.9}
    assert pick_tier(alert, RULES) is None
