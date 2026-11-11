from engine.policy import load_policy, load_settings
from engine.respond import Responder
from receiver import watchdog

DRIFT = {"incident_class": "sensor_drift", "confidence": 0.9, "affected_subsystem": "MACHINE1"}
SEQUENCE = {"incident_class": "sequence_violation", "confidence": 0.9, "affected_subsystem": "MACHINE1"}


def limited(max_actions):
    return Responder(load_policy(), {**load_settings(), "rate_limit": {"max_actions": max_actions, "per_seconds": 60}})


def test_rate_limit_drops_extra_disruptive_actions_to_tier_1(events):
    responder = limited(1)
    assert responder.handle(DRIFT, 0)["tier"] == 2
    assert responder.handle(SEQUENCE, 10)["tier"] == 1
    assert events()[-1]["reason"] == "rate_limited"


def test_rate_limit_allows_again_after_its_window(events):
    responder = limited(1)
    responder.handle(DRIFT, 0)
    assert responder.handle(SEQUENCE, 61)["tier"] == 3


def test_rate_limited_incident_can_still_escalate_later(events):
    responder = limited(1)
    responder.handle({**DRIFT, "affected_subsystem": "MACHINE2"}, 0)
    incident = responder.handle(DRIFT, 5)
    assert incident["tier"] == 1
    for t in range(10, 65, 5):  # the attack keeps alerting until the limit window has passed
        responder.handle(DRIFT, t)
    assert incident["tier"] == 2 and incident["actions"] == ["alert_operator", "isolate"]


def test_watchdog_sees_a_dead_layer():
    assert watchdog.alive("http://127.0.0.1:9/health") is False


def test_watchdog_alerts_once_per_change_not_per_check(events, monkeypatch):
    readings = iter([False, False, False, True, True])
    monkeypatch.setattr(watchdog, "alive", lambda url: next(readings))
    watchdog.watch(period=0, checks=5)
    assert [e["status"] for e in events()] == ["response_layer_down", "response_layer_up"]
