from engine.policy import load_policy, pick_tier

RULES = load_policy()


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
