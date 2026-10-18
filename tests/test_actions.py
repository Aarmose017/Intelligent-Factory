from actions.line import LineControl
from engine.policy import load_policy, load_settings
from engine.respond import Responder
from sim.attacks import drift, skip_step
from sim.detector import detector
from sim.line import build, quiet
from sim.scenario import run

SETTINGS = load_settings()


def decisions(log):
    return [e for e in log if e["event"] == "decision"]


def at(log, event):
    return next(e["t"] for e in log if e["event"] == event)


def test_clean_run_raises_nothing(events):
    responder, _, labels = run(None)
    assert responder.incidents.all == [] and labels == [] and events() == []


def test_drift_alerts_operator_then_isolates_once_and_recovers_after_the_attack(events):
    responder, nodes, labels = run("drift")
    log = events()
    [incident] = responder.incidents.all
    assert incident["technique"] == "T0836" and incident["state"] == "resolved"
    assert incident["actions"] == ["alert_operator", "isolate"]  # escalated once confidence passed 0.8
    assert at(log, "contained") < at(log, "resolved")
    assert any(e["event"] == "precondition_failed" for e in log)  # attacker still active, so no early restart
    assert at(log, "resolved") > labels[0]["end"]
    assert nodes["MACHINE1"].processing_delay == 1.1 and responder.control.held == {}


def test_isolated_machine_works_again_after_recovery(events):
    responder, nodes, _ = run("drift")
    assert responder.incidents.all[0]["state"] == "resolved"
    processed = nodes["MACHINE1"].stats["num_item_processed"]
    with quiet():
        responder.env.run(until=responder.env.now + 20)
    assert nodes["MACHINE1"].stats["num_item_processed"] > processed


def test_overlapping_attacks_both_resolve_and_the_line_restarts(events):
    env, nodes = build()
    labels = []
    responder = Responder(load_policy(), SETTINGS, env, LineControl(env, nodes))
    env.process(drift(env, labels, nodes["MACHINE1"], 20, 60))
    env.process(skip_step(env, labels, nodes["BUF1"], nodes["BUF2"], "MACHINE1", 30, 50))
    env.process(detector(env, nodes, lambda a: responder.handle(a, env.now)))
    with quiet():
        env.run(until=200)
    assert {i["incident_class"] for i in responder.incidents.all} == {"sensor_drift", "sequence_violation"}
    assert all(i["state"] == "resolved" for i in responder.incidents.all)  # no deadlock between the two
    received = nodes["SINK"].stats["num_item_received"]
    with quiet():
        env.run(until=220)
    assert nodes["SINK"].stats["num_item_received"] > received


def test_one_incident_gets_exactly_one_isolation(events):
    responder, _, _ = run("drift")
    log = events()
    assert responder.incidents.all[0]["alerts"] > 10
    assert len([e for e in decisions(log) if e["action"] == "isolate"]) == 1


def test_skip_step_goes_to_safe_state_and_back(events):
    """Sprint 3 exit: an injected attack goes all the way to safe state and back."""
    responder, nodes, labels = run("skip_step")
    log = events()
    [incident] = responder.incidents.all
    assert incident["technique"] == "T0889" and incident["tier"] == 3 and incident["state"] == "resolved"
    decided = decisions(log)[0]["t"]
    assert at(log, "operator_confirmed") - decided == SETTINGS["operator_delay"]  # tier 3 waits for the operator
    assert at(log, "operator_confirmed") <= at(log, "contained") < at(log, "resolved")
    assert at(log, "resolved") > labels[0]["end"]
    # The line runs again after recovery.
    received = nodes["SINK"].stats["num_item_received"]
    with quiet():
        responder.env.run(until=responder.env.now + 20)
    assert nodes["SINK"].stats["num_item_received"] > received


def test_alert_for_a_machine_we_do_not_have_is_not_isolated(events):
    env, nodes = build()
    responder = Responder(load_policy(), SETTINGS, env, LineControl(env, nodes))
    incident = responder.handle({"incident_class": "sensor_drift", "confidence": 0.9,
                                 "affected_subsystem": "MACHINE9"}, 0)
    assert incident["tier"] == 1 and decisions(events())[0]["reason"] == "unknown_subsystem"


def test_without_a_line_actions_are_logged_not_carried_out(events):
    responder = Responder(load_policy(), SETTINGS)
    responder.handle({"incident_class": "sensor_drift", "confidence": 0.9, "affected_subsystem": "MACHINE1"}, 0)
    assert decisions(events())[0]["action"] == "isolate"


def test_alert_that_is_not_an_object_is_rejected_and_logged(events):
    # B2: anything but a dict crashed the responder.
    responder = Responder(load_policy(), SETTINGS)
    for bad in (None, [], "x"):
        assert responder.handle(bad, 0) is None
    assert [e["event"] for e in events()] == ["rejected"] * 3
    assert responder.incidents.all == []


def test_higher_tier_alert_right_after_recovery_does_not_reopen_the_incident(events):
    # B3: a stale alert asking for a higher tier started safe state on a resolved incident, then the
    # second resolve crashed the simulation. Needs a class with both a tier 2 and a tier 3 rule.
    rules = load_policy() + [{"technique": "T0836", "incident_class": "sensor_drift",
                              "min_confidence": 0.95, "tier": 3}]
    env, nodes = build()
    responder = Responder(rules, SETTINGS, env, LineControl(env, nodes))
    drift_alert = {"incident_class": "sensor_drift", "affected_subsystem": "MACHINE1"}
    incident = responder.handle({**drift_alert, "confidence": 0.9}, 0)
    with quiet():
        env.run(until=40)
    assert incident["state"] == "resolved"
    responder.handle({**drift_alert, "confidence": 0.99}, incident["resolved_at"] + 1)
    with quiet():
        env.run(until=120)
    assert incident["actions"] == ["isolate"] and events()[-1]["event"] == "suppressed"
    assert responder.control.stopped_at is None  # the line was not put into safe state


def test_same_seed_same_timeline(events):
    run("drift")
    first = [(e["event"], e.get("t"), e.get("action")) for e in events()]
    run("drift")
    both = [(e["event"], e.get("t"), e.get("action")) for e in events()]
    assert both == first + first
