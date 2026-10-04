import json
import pathlib
import threading

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


def strict_loads(line):
    # Python's json accepts NaN and Infinity, other readers do not. Refuse them
    # here so every test also checks the lines are standard JSON.
    def refuse(token):
        raise ValueError(f"non-standard JSON constant {token}")
    return json.loads(line, parse_constant=refuse)


def read_lines(path):
    return [strict_loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


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


def test_concurrent_writes_are_not_lost_or_mixed(log_file):
    # Entries well over the 8 KB write buffer, from many threads at once, like
    # the uvicorn thread pool under load. Without the lock this lost lines.
    threads, per_thread = 20, 10
    start = threading.Barrier(threads)

    def worker(t):
        start.wait()
        for i in range(per_thread):
            log.write({"alert_id": f"{t}-{i}", "affected_subsystem": "x" * 40000}, RULE)

    pool = [threading.Thread(target=worker, args=(t,)) for t in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    ids = sorted(e["alert_id"] for e in read_lines(log_file))
    assert ids == sorted(f"{t}-{i}" for t in range(threads) for i in range(per_thread))


def test_nan_and_infinity_still_give_valid_json(log_file):
    log.write({"alert_id": "a1", "confidence": float("nan"),
               "affected_subsystem": {"reading": float("inf")}}, None)
    entry = read_lines(log_file)[0]
    assert entry["confidence"] == "nan"
    assert entry["affected_subsystem"] == {"reading": "inf"}


def test_line_endings_are_lf_on_every_os(log_file):
    log.write(ALERT, RULE)
    log.write(ALERT, RULE)
    assert b"\r\n" not in log_file.read_bytes()


def test_rule_missing_keys_does_not_crash(log_file):
    log.write(ALERT, {"tier": 1})
    entry = read_lines(log_file)[0]
    assert entry["rule"] is None
    assert entry["tier"] == 1


def test_default_log_path_does_not_depend_on_working_directory():
    repo = pathlib.Path(__file__).resolve().parent.parent
    assert log.LOG.is_absolute()
    assert log.LOG == repo / "logs" / "response.jsonl"


def test_receiver_records_received_at_and_decision_time(log_file):
    from receiver.main import app

    r = TestClient(app).post("/alert", json=ALERT)
    assert r.status_code == 200
    entry = read_lines(log_file)[0]
    assert entry["received_at"] is not None
    assert entry["received_at"] <= entry["logged_at"]
    assert isinstance(entry["decision_ms"], float)
    assert entry["decision_ms"] >= 0


def test_receiver_logs_unmatched_alert(log_file):
    # Records today's behaviour only. What no-match should do is still a team
    # decision, this just makes sure the line is written either way.
    from receiver.main import app

    r = TestClient(app).post("/alert", json={**ALERT, "incident_class": "not_a_class"})
    assert r.json() == {"decision": "no_rule_matched"}
    entry = read_lines(log_file)[0]
    assert entry["rule"] is None and entry["tier"] is None
