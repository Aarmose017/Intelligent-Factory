"""Replay harness: every attack on fixed seeds, our layer on and off, and the Sprint 4 measures from the logs.

    python -m sim.replay            (writes logs/replay/results.json and prints the tables)

All times are simulation seconds. Measures that depend on things the Product Owner has not signed off
(the harm proxy, the time unit) are marked provisional in the output.
"""
import json
import pathlib
import random
import re
import statistics
import sys

from actions.line import LineControl
from engine import log
from engine.policy import load_policy, load_settings
from engine.respond import Responder
from sim.attacks import drift, skip_step
from sim.detector import detector
from sim.line import build, quiet

HORIZON = 200
SEEDS = range(10)
# Same lengths as sim/scenario.py. The seed picks the start, so each run hits a different point in the line's
# cycle. The line itself has one edge in and one out, so without this every seed gave the identical run.
ATTACKS = {
    "drift": lambda env, labels, n, start: drift(env, labels, n["MACHINE1"], start, start + 40),
    "skip_step": lambda env, labels, n, start: skip_step(env, labels, n["BUF1"], n["BUF2"], "MACHINE1", start, start + 20),
}


def one_run(attack, seed, layer_on, settings, logfile):
    log.LOG = logfile
    env, nodes = build(seed)
    labels = []
    if attack:
        env.process(ATTACKS[attack](env, labels, nodes, random.Random(seed).uniform(15, 45)))
    responder = Responder(load_policy(), settings, env, LineControl(env, nodes) if layer_on else None)
    env.process(detector(env, nodes, lambda a: responder.handle(a, env.now)))
    with quiet():
        env.run(until=HORIZON)
    events = [json.loads(line) for line in logfile.read_text(encoding="utf-8").splitlines()] if logfile.exists() else []
    received, processed = nodes["SINK"].stats["num_item_received"], nodes["MACHINE1"].stats["num_item_processed"]
    bad = max(0, received - processed)  # items that reached the Sink without passing the machine
    return {"attack": attack, "seed": seed, "layer_on": layer_on, "labels": labels, "events": events,
            "incidents": responder.incidents.all, "good_items": received - bad, "bad_items": bad,
            "window": settings["correlation_window"]}


def measures(run):
    """The per-run numbers, measured from the attack's start in its ground-truth label."""
    start = run["labels"][0]["start"] if run["labels"] else 0
    decisions = [e for e in run["events"] if e["event"] == "decision"]
    first = {}
    for d in decisions:
        first.setdefault(d["action"], d["t"] - start)
    alerts = [e["t"] for e in run["events"] if e.get("alert_id")]
    contained3 = [e["t"] for e in run["events"] if e["event"] == "contained" and e.get("tier") == 3]
    resolved = [e["t"] for e in run["events"] if e["event"] == "resolved"]
    disruptive = [i for i in run["incidents"] if (i["tier"] or 0) >= 2]
    actions = [d for d in decisions if d["action"] not in ("no_rule", "log_only")]
    label = run["labels"][0] if run["labels"] else None
    # A wrong response: any action with no attack running, or one of the wrong class, or one outside the attack
    # window plus the correlation window (late stale readings are absorbed within that window).
    wrong = [d for d in actions if label is None or d["incident_class"] != label["incident_class"]
             or not label["start"] <= d["t"] <= label["end"] + run["window"]]
    return {
        "detect_s": alerts[0] - start if alerts else None,
        "decide_s": first,
        "safe_state_s": contained3[0] - start if contained3 else None,
        "resolve_s": resolved[-1] - start if resolved else None,
        "recovered": sum(i["state"] == "resolved" for i in disruptive), "disruptive": len(disruptive),
        "duplicate_actions": sum(len(i["actions"]) - len(set(i["actions"])) for i in run["incidents"]),
        "wrong_actions": len(wrong),
        "good_items": run["good_items"], "bad_items": run["bad_items"],
    }


def summarise(values):
    values = [v for v in values if v is not None]
    return {"median": statistics.median(values), "worst": max(values), "n": len(values)} if values else None


def coverage():
    threat = pathlib.Path(__file__).resolve().parent.parent / "docs" / "threat-analysis.md"
    listed = set(re.findall(r"^### (T\d{4})", threat.read_text(encoding="utf-8"), re.M))
    acted = {r["technique"] for r in load_policy()}
    return {"techniques_in_threat_analysis": len(listed), "with_a_policy_action": len(acted & listed),
            "covered": sorted(acted & listed), "not_covered": sorted(listed - acted)}


def replay(seeds=SEEDS, operator_delays=(5, 30), out=None):
    out = out or log.LOG.parent / "replay"
    out.mkdir(parents=True, exist_ok=True)
    live_log = log.LOG
    results = {"provisional": "time unit (1 tick = 1 s) and harm proxy not yet agreed with the Product Owner",
               "horizon_s": HORIZON, "seeds": list(seeds), "coverage": coverage(), "by_delay": {}}
    try:
        for delay in operator_delays:
            settings = {**load_settings(), "operator_delay": delay}
            rows = {}
            for attack in (None, *ATTACKS):
                for layer_on in (True, False):
                    runs = [measures(one_run(attack, s, layer_on, settings,
                                             out / f"{attack}-{'on' if layer_on else 'off'}-{s}-d{delay}.jsonl"))
                            for s in seeds]
                    actions = sorted({a for m in runs for a in m["decide_s"]})
                    rows[f"{attack or 'clean'} / layer {'on' if layer_on else 'off'}"] = {
                        "detect_s": summarise([m["detect_s"] for m in runs]),
                        "decide_s": {a: summarise([m["decide_s"].get(a) for m in runs]) for a in actions},
                        "safe_state_s": summarise([m["safe_state_s"] for m in runs]),
                        "resolve_s": summarise([m["resolve_s"] for m in runs]),
                        "recovery_rate": (sum(m["recovered"] for m in runs) / sum(m["disruptive"] for m in runs)
                                          if any(m["disruptive"] for m in runs) else None),
                        "duplicate_actions": sum(m["duplicate_actions"] for m in runs),
                        # Only counted with the layer on: with it off nothing is carried out.
                        "wrong_actions": sum(m["wrong_actions"] for m in runs) if layer_on else None,
                        "good_items": statistics.mean(m["good_items"] for m in runs),
                        "bad_items": statistics.mean(m["bad_items"] for m in runs),
                    }
            results["by_delay"][str(delay)] = rows
    finally:
        log.LOG = live_log
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def show(results):
    c = results["coverage"]
    print(f"policy coverage: {c['with_a_policy_action']} of {c['techniques_in_threat_analysis']} threat-analysis "
          f"techniques have an action {c['covered']}")
    for delay, rows in results["by_delay"].items():
        print(f"\noperator delay {delay} s  ({results['provisional']})")
        for name, r in rows.items():
            fmt = lambda s: f"{s['median']:.1f}/{s['worst']:.1f}" if s else "-"
            decide = ", ".join(f"{a} {fmt(s)}" for a, s in r["decide_s"].items()) or "-"
            rate = f"{r['recovery_rate']:.0%}" if r["recovery_rate"] is not None else "-"
            print(f"  {name:24} detect {fmt(r['detect_s']):10} decide [{decide}]  safe state {fmt(r['safe_state_s']):10}"
                  f" resolved {fmt(r['resolve_s']):11}"
                  f" recovered {rate:5} dup {r['duplicate_actions']} wrong {r['wrong_actions'] if r['wrong_actions'] is not None else '-':>2}"
                  f"  good {r['good_items']:.0f} bad {r['bad_items']:.0f}")
    print("\n(median/worst seconds from attack start)")


if __name__ == "__main__":
    show(replay())
    print("written:", log.LOG.parent / "replay" / "results.json", file=sys.stderr)
