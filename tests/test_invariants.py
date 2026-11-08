"""Randomized checks of the rules our layer must never break, over many seeded scenarios.

Each scenario is reproducible from its seed. A failure message names the seed, so it can be replayed exactly.
"""
import json
import random

import pytest

from actions.line import LineControl
from engine.policy import load_policy, load_settings
from engine.respond import Responder
from sim.attacks import drift, skip_step
from sim.detector import detector
from sim.line import build, quiet

SETTINGS = load_settings()
SEEDS = range(40)
# Seeds the 1000-scenario soak run caught: one incident's recovery undid another incident's safe state.
REGRESSION_SEEDS = [42, 58, 229, 313, 318, 361]


def check_invariants(log, responder, seed):
    """The rules from CLAUDE.md and the Sprint 3 cards, checked against what actually happened."""
    where = f"seed {seed}"
    decisions = [e for e in log if e["event"] == "decision"]
    for inc in responder.incidents.all:
        mine = [e for e in log if e.get("incident_id") == inc["id"]]
        tiers = [e["tier"] for e in mine if e["event"] == "decision" and e["tier"] is not None]
        assert tiers == sorted(set(tiers)), f"{where}: incident {inc['id']} repeated or lowered a tier {tiers}"
        states = [e["event"] for e in mine if e["event"] in ("contained", "resolved")]
        assert states.count("resolved") <= 1, f"{where}: incident {inc['id']} resolved twice"
        if "resolved" in states:
            assert states[-1] == "resolved", f"{where}: incident {inc['id']} moved after resolving {states}"
            done = next(e["t"] for e in mine if e["event"] == "resolved")
            assert not [e for e in mine if e["event"] == "decision" and e["t"] > done], \
                f"{where}: incident {inc['id']} acted after it was resolved"
        for d in (e for e in mine if e["event"] == "decision" and e["action"] == "safe_state"):
            confirmed = [e["t"] for e in mine if e["event"] == "operator_confirmed" and e["t"] >= d["t"]]
            # approx: fractional alert times give 5.000000000000002, which is float rounding, not a bug
            assert confirmed and confirmed[0] - d["t"] == pytest.approx(SETTINGS["operator_delay"]), \
                f"{where}: tier 3 without the operator delay"
    disruptive = [e["t"] for e in decisions if (e["tier"] or 0) >= 2]
    limit = SETTINGS["rate_limit"]
    for t in disruptive:
        window = [u for u in disruptive if t <= u < t + limit["per_seconds"]]
        assert len(window) <= limit["max_actions"], f"{where}: rate limit broken {window}"
    machines = responder.control.machines if responder.control else {}
    for d in decisions:
        if d["action"] == "isolate" and responder.control:
            assert d["affected_subsystem"] in machines, f"{where}: isolated a machine that does not exist"


def strict(line):
    def refuse(token):
        raise ValueError(token)
    return json.loads(line, parse_constant=refuse)


@pytest.mark.parametrize("seed", [*SEEDS, *REGRESSION_SEEDS])
def test_random_attack_schedules_keep_every_rule(seed, events):
    """Random mix of the two attacks, random start and length, often overlapping."""
    rng = random.Random(seed)
    env, nodes = build(seed)
    labels = []
    responder = Responder(load_policy(), SETTINGS, env, LineControl(env, nodes))
    ends = []
    for _ in range(rng.randint(1, 3)):
        start, length = rng.uniform(5, 120), rng.uniform(5, 60)
        ends.append(start + length)
        if rng.random() < 0.5:
            env.process(drift(env, labels, nodes["MACHINE1"], start, start + length))
        else:
            env.process(skip_step(env, labels, nodes["BUF1"], nodes["BUF2"], "MACHINE1", start, start + length))
    env.process(detector(env, nodes, lambda a: responder.handle(a, env.now)))
    with quiet():
        env.run(until=max(ends) + 200)  # long enough for every recovery to finish
    log = events()
    check_invariants(log, responder, seed)
    for inc in responder.incidents.all:
        if (inc["tier"] or 0) >= 2:
            assert inc["state"] == "resolved", f"seed {seed}: incident {inc['id']} never recovered"
    assert responder.control.held == {} and responder.control.stopped_at is None, f"seed {seed}: line left stopped"
    received = nodes["SINK"].stats["num_item_received"]
    with quiet():
        env.run(until=env.now + 20)
    assert nodes["SINK"].stats["num_item_received"] > received, f"seed {seed}: line not running at the end"


GARBAGE = [None, "high", True, float("nan"), -1, [0.9], {"x": 1}]


@pytest.mark.parametrize("seed", SEEDS)
def test_random_alert_streams_including_garbage_keep_every_rule(seed, events):
    """Alerts straight into the responder: random classes, confidences, subsystems and malformed values."""
    rng = random.Random(seed)
    env, nodes = build(seed)
    responder = Responder(load_policy(), SETTINGS, env, LineControl(env, nodes))
    for _ in range(60):
        with quiet():
            env.run(until=env.now + rng.expovariate(0.5))
        roll = rng.random()
        if roll < 0.08:
            alert = rng.choice([None, [], "alert", 42])
        else:
            alert = {
                "incident_class": rng.choice(["sensor_drift", "sequence_violation", "unknown_class", None]),
                "confidence": rng.choice(GARBAGE) if roll < 0.2 else round(rng.random(), 2),
                "affected_subsystem": rng.choice(["MACHINE1", "MACHINE1", "MACHINE9", "BUF1", None]),
            }
        responder.handle(alert, env.now)
    with quiet():
        env.run(until=env.now + 200)
    log = events()
    check_invariants(log, responder, seed)
    for e in log:
        if e["event"] == "decision" and e["tier"] is not None:
            assert isinstance(e["confidence"], (int, float)) and not isinstance(e["confidence"], bool), \
                f"seed {seed}: acted on a confidence that is not a number: {e['confidence']!r}"


def test_every_log_line_is_strict_json(tmp_path, monkeypatch):
    from engine import log
    monkeypatch.setattr(log, "LOG", tmp_path / "r.jsonl")
    env, nodes = build(7)
    responder = Responder(load_policy(), SETTINGS, env, LineControl(env, nodes))
    for conf in GARBAGE + [0.9, 0.99]:
        responder.handle({"incident_class": "sensor_drift", "confidence": conf, "affected_subsystem": "MACHINE1"}, 0)
    with quiet():
        env.run(until=100)
    lines = log.LOG.read_text(encoding="utf-8").splitlines()
    assert lines and all(strict(line) for line in lines)
