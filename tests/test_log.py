import json

import pytest
from fastapi.testclient import TestClient

from engine import log

RULE = {"technique": "sensor_drift_high", "tier": 2}

ALERT = {
    "alert_id": "a1",
    "emitted_at": "2026-10-01T14:22:31Z",
    "observed_at": "2026-10-01T14:22:29Z",
    "incident_class": "sensor_drift",
    "confidence": 0.82,
    "affected_subsystem": "machine_02",
}


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "response.jsonl"
    monkeypatch.setattr(log, "LOG", path)
    return path


def read_lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_one_entry_per_alert(log_file):
    for i in range(3):
        log.write({**ALERT, "alert_id": f"a{i}"}, RULE, log.now())
    lines = read_lines(log_file)
    assert [e["alert_id"] for e in lines] == ["a0", "a1", "a2"]


def test_entry_keeps_all_four_timestamps(log_file):
    log.write(ALERT, RULE, "2026-10-01T14:22:32+00:00")
    entry = read_lines(log_file)[0]
    assert entry["observed_at"] == ALERT["observed_at"]
    assert entry["emitted_at"] == ALERT["emitted_at"]
    assert entry["received_at"] == "2026-10-01T14:22:32+00:00"
    assert entry["logged_at"] is not None


def test_appends_rather_than_overwrites(log_file):
    log_file.parent.mkdir(parents=True)
    log_file.write_text(json.dumps({"alert_id": "old"}) + "\n", encoding="utf-8")
    log.write(ALERT, RULE, log.now())
    lines = read_lines(log_file)
    assert [e["alert_id"] for e in lines] == ["old", "a1"]


@pytest.mark.parametrize("bad", [
    None,
    [],
    "not an alert",
    {},
    {"alert_id": "a9", "confidence": "very high"},
    {"alert_id": "a9", "emitted_at": object()},
])
def test_malformed_alert_does_not_crash(log_file, bad):
    log.write(bad, None, log.now())
    lines = read_lines(log_file)
    assert len(lines) == 1


def test_unwritable_log_does_not_crash(tmp_path, monkeypatch, caplog):
    # A directory where the file should be. Opening it for append fails on
    # every OS, which stands in for a full disk or a permissions problem.
    blocked = tmp_path / "response.jsonl"
    blocked.mkdir()
    monkeypatch.setattr(log, "LOG", blocked)
    entry = log.write(ALERT, RULE, log.now())
    assert entry["alert_id"] == "a1"
    # The failure is swallowed but not silent.
    assert "could not write response log entry" in caplog.text


def test_receiver_records_received_at(log_file):
    from receiver.main import app

    r = TestClient(app).post("/alert", json=ALERT)
    assert r.status_code == 200
    entry = read_lines(log_file)[0]
    assert entry["received_at"] is not None
    assert entry["received_at"] <= entry["logged_at"]
