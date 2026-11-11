import pytest

from engine.incidents import Incidents, move

DRIFT = {"incident_class": "sensor_drift", "affected_subsystem": "MACHINE1"}


def test_alerts_close_together_are_one_incident():
    incidents = Incidents(window=10)
    first, new = incidents.correlate(DRIFT, 0)
    assert new
    for t in (1, 2, 3):
        assert incidents.correlate(DRIFT, t) == (first, False)
    assert first["alerts"] == 4 and len(incidents.all) == 1


def test_other_subsystem_or_class_is_its_own_incident():
    incidents = Incidents(window=10)
    incidents.correlate(DRIFT, 0)
    _, new_subsystem = incidents.correlate({**DRIFT, "affected_subsystem": "MACHINE2"}, 1)
    _, new_class = incidents.correlate({**DRIFT, "incident_class": "sequence_violation"}, 1)
    assert new_subsystem and new_class and len(incidents.all) == 3


def test_low_tier_incident_ends_when_its_alerts_stop():
    incidents = Incidents(window=10)
    first, _ = incidents.correlate(DRIFT, 0)
    first["tier"] = 1
    second, new = incidents.correlate(DRIFT, 25)
    assert new and second is not first
    assert first["state"] == "resolved" and first["resolved_at"] == 0  # ended when the alerts stopped


def test_disruptive_incident_stays_open_through_a_quiet_spell():
    incidents = Incidents(window=10)
    first, _ = incidents.correlate(DRIFT, 0)
    first["tier"] = 2
    assert incidents.correlate(DRIFT, 100) == (first, False)
    assert first["state"] == "open"


def test_stale_alert_right_after_recovery_is_absorbed_a_later_one_is_new():
    incidents = Incidents(window=10)
    first, _ = incidents.correlate(DRIFT, 0)
    first["tier"] = 2
    move(first, "contained", 1)
    move(first, "resolved", 50)
    assert incidents.correlate(DRIFT, 55) == (first, False)
    second, new = incidents.correlate(DRIFT, 61)
    assert new and second is not first


def test_states_only_move_forward():
    incident = {"id": 1, "state": "open"}
    move(incident, "contained", 1)
    move(incident, "resolved", 2)
    assert incident["contained_at"] == 1 and incident["resolved_at"] == 2
    with pytest.raises(ValueError):
        move(incident, "contained", 3)
    with pytest.raises(ValueError):
        move({"id": 2, "state": "contained"}, "open", 1)
    move({"id": 3, "state": "open"}, "resolved", 1)  # tier 0 and 1 never contain, they resolve directly
