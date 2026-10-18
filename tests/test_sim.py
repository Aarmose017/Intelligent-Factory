import json
import pathlib
import runpy
import sys

from engine import log
from sim.attacks import drift, skip_step
from sim.detector import detector
from sim.line import build, quiet

REPO = pathlib.Path(__file__).resolve().parent.parent

# Copied from Team B's test.py (github.com/Rat-mon/FactorySimPy, checked 2026-10-18). If either side changes
# the line, node ids in alerts stop meaning the same thing, so this has to be agreed again.
TEAM_B = {
    "SRC": {"flow_item_type": "item", "inter_arrival_time": 0.8, "blocking": False, "out_edge_selection": "RANDOM"},
    "MACHINE1": {"work_capacity": 4, "processing_delay": 1.1, "blocking": False,
                 "in_edge_selection": "RANDOM", "out_edge_selection": "RANDOM"},
    "BUF1": {"capacity": 4, "delay": 0.5, "mode": "FIFO"},
    "BUF2": {"capacity": 4, "delay": 0.5, "mode": "FIFO"},
}


def run_with(attack=None, until=150, seed=0):
    env, nodes = build(seed)
    labels, alerts = [], []
    if attack == "drift":
        env.process(drift(env, labels, nodes["MACHINE1"], 20, 60))
    if attack == "skip_step":
        env.process(skip_step(env, labels, nodes["BUF1"], nodes["BUF2"], "MACHINE1", 20, 40))
    env.process(detector(env, nodes, alerts.append))
    with quiet():
        env.run(until=until)
    return labels, alerts


def test_line_matches_team_b():
    _, nodes = build()
    assert set(nodes) == set(TEAM_B) | {"SINK"}
    for node_id, settings in TEAM_B.items():
        for name, value in settings.items():
            assert getattr(nodes[node_id], name) == value, (node_id, name)
    assert nodes["BUF1"].inbuiltstore.capacity == 4  # the real limit, not just the attribute
    assert (nodes["BUF1"].src_node.id, nodes["BUF1"].dest_node.id) == ("SRC", "MACHINE1")
    assert (nodes["BUF2"].src_node.id, nodes["BUF2"].dest_node.id) == ("MACHINE1", "SINK")


def test_detector_alerts_use_the_shared_schema_fields():
    _, alerts = run_with("drift", until=80)
    schema = json.loads((REPO / "schema" / "sample_alert.json").read_text(encoding="utf-8"))
    assert alerts and all(set(a) == set(schema) for a in alerts)


def test_no_alerts_without_an_attack():
    for seed in range(3):
        assert run_with(None, until=500, seed=seed)[1] == []


def test_each_attack_writes_its_label():
    for attack, technique in (("drift", "T0836"), ("skip_step", "T0889")):
        labels, alerts = run_with(attack)
        assert alerts
        [label] = labels
        assert label["technique"] == technique and label["subsystem"] == "MACHINE1"
        assert (label["start"], label["end"]) == ((20, 60) if attack == "drift" else (20, 40))


def test_detector_goes_quiet_once_the_attack_ends():
    labels, alerts = run_with("skip_step", until=200)
    assert alerts and max(a["observed_at"] for a in alerts) <= labels[0]["end"] + 1


def test_scenario_runner_never_writes_the_live_log(tmp_path, monkeypatch):
    monkeypatch.setattr(log, "LOG", tmp_path / "response.jsonl")
    monkeypatch.setattr(sys, "argv", ["sim.scenario", "drift"])
    with quiet():
        runpy.run_module("sim.scenario", run_name="__main__")
    assert not (tmp_path / "response.jsonl").exists()
    assert (tmp_path / "scenario.jsonl").exists() and (tmp_path / "labels.jsonl").exists()
