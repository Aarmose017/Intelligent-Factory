"""Run one attack through the whole loop: inject, detect, decide, act, recover. Same seed, same result.

    python -m sim.scenario skip_step     (or drift, or none)
"""
import json
import sys

from actions.line import LineControl
from engine import log
from engine.policy import load_policy, load_settings
from engine.respond import Responder
from sim.attacks import drift, skip_step
from sim.detector import detector
from sim.line import build, quiet

ATTACKS = {
    "drift": lambda env, labels, n: drift(env, labels, n["MACHINE1"], start=20, end=60),
    "skip_step": lambda env, labels, n: skip_step(env, labels, n["BUF1"], n["BUF2"], "MACHINE1", start=20, end=40),
}


def run(attack=None, until=150, seed=0):
    env, nodes = build(seed)
    labels = []
    if attack:
        env.process(ATTACKS[attack](env, labels, nodes))
    responder = Responder(load_policy(), load_settings(), env, LineControl(env, nodes))
    env.process(detector(env, nodes, lambda a: responder.handle(a, env.now)))
    with quiet():
        env.run(until=until)
    return responder, nodes, labels


if __name__ == "__main__":
    log.LOG = log.LOG.parent / "scenario.jsonl"  # keep simulation runs out of the live receiver's log
    attack = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "none" else None
    responder, nodes, labels = run(attack)
    with (log.LOG.parent / "labels.jsonl").open("a", encoding="utf-8") as f:
        f.writelines(json.dumps(label) + "\n" for label in labels)
    for i in responder.incidents.all:
        print(f"incident {i['id']} {i['incident_class']} {i['technique']} tier {i['tier']} {i['state']} | "
              f"opened {i['opened_at']} contained {i.get('contained_at')} resolved {i.get('resolved_at')} | "
              f"{i['alerts']} alerts, actions {i['actions']}")
    print("labels:", labels)
    print("sink received:", nodes["SINK"].stats["num_item_received"], "| log:", log.LOG)
