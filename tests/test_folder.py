import json

import pytest

from engine import log
from receiver.folder import replay

ALERT = {"schema_version": "1.0", "alert_id": "a1", "emitted_at": "2026-10-01T14:22:31Z",
         "observed_at": "2026-10-01T14:22:29Z", "incident_class": "sensor_drift", "confidence": 0.82,
         "affected_subsystem": "MACHINE1"}


@pytest.fixture
def folder(tmp_path, monkeypatch):
    monkeypatch.setattr(log, "LOG", tmp_path / "folder.jsonl")
    alerts = tmp_path / "alerts"
    alerts.mkdir()
    # File names out of time order on purpose: the replay must go by emitted_at, not by name.
    files = {
        "1-later.json": {**ALERT, "alert_id": "late", "emitted_at": "2026-10-01T14:30:00Z"},
        "2-first.json": {**ALERT, "alert_id": "first", "confidence": 0.5},
        "3-second.json": {**ALERT, "alert_id": "second", "emitted_at": "2026-10-01T14:22:36Z"},
    }
    for name, alert in files.items():
        (alerts / name).write_text(json.dumps(alert), encoding="utf-8")
    (alerts / "4-bad.json").write_text(json.dumps({**ALERT, "alert_id": "bad", "confidence": "high"}),
                                       encoding="utf-8")
    (alerts / "5-broken.json").write_text("{not json", encoding="utf-8")
    (alerts / "notes.txt").write_text("ignored", encoding="utf-8")
    return alerts


def lines():
    return [json.loads(line) for line in log.LOG.read_text(encoding="utf-8").splitlines()]


def test_folder_replay_goes_by_emitted_at_and_correlates_on_those_times(folder):
    responder, accepted, rejected = replay(folder)
    assert (accepted, rejected) == (3, 2)
    decided = [(e["alert_id"], e["event"], e.get("action")) for e in lines() if e["event"] != "rejected"]
    # first opens at tier 1, second 5 s later escalates the same incident to tier 2, and late arrives
    # more than one correlation window after the last alert, so it is a new incident.
    assert decided == [("first", "decision", "alert_operator"), ("second", "decision", "isolate"),
                       ("late", "decision", "isolate")]
    assert [i["id"] for i in responder.incidents.all] == [1, 2]


def test_folder_replay_logs_bad_files_and_keeps_going(folder):
    replay(folder)
    rejected = {e["file"]: e for e in lines() if e["event"] == "rejected"}
    assert set(rejected) == {"4-bad.json", "5-broken.json"}
    assert rejected["4-bad.json"]["fields"] == ["confidence"] and rejected["4-bad.json"]["alert_id"] == "bad"
    assert rejected["5-broken.json"]["reason"].startswith("could not read")


def test_folder_replay_gives_the_same_decisions_every_time(folder):
    def decisions():
        log.LOG.unlink(missing_ok=True)
        replay(folder)
        return [(e["alert_id"], e["event"], e.get("action"), e.get("incident_id")) for e in lines()]
    assert decisions() == decisions()


def test_folder_replay_never_writes_the_live_log(folder, monkeypatch):
    import runpy
    import sys

    live = log.LOG.parent / "response.jsonl"
    monkeypatch.setattr(log, "LOG", live)
    monkeypatch.setattr(sys, "argv", ["receiver.folder", str(folder)])
    runpy.run_module("receiver.folder", run_name="__main__")
    assert not live.exists() and (live.parent / "folder.jsonl").exists()
