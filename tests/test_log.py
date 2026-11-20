import json
import pathlib
import threading

import pytest
from fastapi.testclient import TestClient

from engine import log

RULE = {"technique": "sensor_drift_high", "tier": 2}

ALERT = {
    "schema_version": "1.0",
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


@pytest.fixture
def client(log_file, monkeypatch):
    # A fresh Responder per test, so incidents from one test cannot correlate with the next one's alerts.
    from engine.policy import load_settings
    from engine.respond import Responder
    from receiver import main

    monkeypatch.setattr(main, "RESPONDER", Responder(main.RULES, load_settings()))
    monkeypatch.setattr(main, "SEEN", {})  # alert_ids from earlier tests would count as repeats
    monkeypatch.setattr(main, "KEY", None)
    return TestClient(main.app)


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


def test_receiver_records_received_at_and_decision_time(client, log_file):
    r = client.post("/alert", json=ALERT)
    assert r.status_code == 200
    entry = read_lines(log_file)[0]
    assert entry["received_at"] is not None
    assert entry["received_at"] <= entry["logged_at"]
    assert isinstance(entry["decision_ms"], float)
    assert entry["decision_ms"] >= 0


def test_receiver_logs_unmatched_alert(client, log_file):
    # An unknown class is not a schema error. What no-match should do is still a team
    # decision, this just makes sure the line is written either way.
    r = client.post("/alert", json={**ALERT, "incident_class": "not_a_class"})
    assert r.json() == {"decision": "no_rule_matched", "incident_id": 1}
    entry = read_lines(log_file)[0]
    assert entry["rule"] is None and entry["tier"] is None


def test_nan_inside_a_list_still_gives_valid_json(log_file):
    log.write({"alert_id": "a1", "affected_subsystem": [1.0, float("nan"), (float("-inf"),)]}, None)
    assert read_lines(log_file)[0]["affected_subsystem"] == [1.0, "nan", ["-inf"]]


def test_health_reports_the_rules_and_policy_it_loaded(client):
    import hashlib
    from engine.policy import DEFAULT_PATH

    expected = hashlib.sha256(pathlib.Path(DEFAULT_PATH).read_bytes()).hexdigest()
    assert client.get("/health").json() == {"status": "ok", "rules_loaded": 3, "policy_sha256": expected,
                                            "sender_key_required": False}


def test_startup_logs_which_policy_is_in_force(client, log_file):
    from receiver.main import POLICY_SHA256, app

    with TestClient(app):  # entering runs the startup step, like uvicorn does
        pass
    entry = read_lines(log_file)[0]
    assert entry["event"] == "startup" and entry["policy_sha256"] == POLICY_SHA256
    assert entry["rules_loaded"] == 3 and entry["sender_key_required"] is False


def test_a_repeated_alert_id_is_rejected(client, log_file):
    assert client.post("/alert", json=ALERT).status_code == 200
    r = client.post("/alert", json=ALERT)
    assert r.status_code == 409
    entries = read_lines(log_file)
    assert [e["event"] for e in entries] == ["decision", "rejected"]
    assert entries[1]["reason"] == "duplicate alert_id" and entries[1]["alert_id"] == "a1"


def test_only_the_newest_alert_ids_are_remembered(client, monkeypatch):
    from receiver import main

    monkeypatch.setattr(main, "MAX_SEEN", 2)
    for i in range(3):
        client.post("/alert", json={**ALERT, "alert_id": f"a{i}", "affected_subsystem": f"M{i}"})
    assert list(main.SEEN) == ["a1", "a2"]


def test_a_rejected_alert_is_not_remembered(client):
    assert client.post("/alert", json={**ALERT, "confidence": "high"}).status_code == 422
    assert client.post("/alert", json=ALERT).status_code == 200  # the fixed version can still be sent


def test_stale_alerts_are_rejected_when_switched_on(client, log_file, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from receiver import main

    monkeypatch.setattr(main, "SETTINGS", {**main.SETTINGS, "max_alert_age_s": 60})
    fresh = datetime.now(timezone.utc).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    assert client.post("/alert", json={**ALERT, "alert_id": "new", "emitted_at": fresh}).status_code == 200
    r = client.post("/alert", json={**ALERT, "alert_id": "old", "emitted_at": old})
    assert r.status_code == 422
    entry = read_lines(log_file)[1]
    assert entry["reason"] == "alert is stale" and entry["age_s"] >= 120


def test_stale_check_is_off_by_default(client):
    # The sample alert is dated 2026-10-01, which only passes while the check is off.
    from engine.policy import load_settings

    assert load_settings()["max_alert_age_s"] is None
    assert client.post("/alert", json=ALERT).status_code == 200


@pytest.mark.parametrize("headers", [{}, {"X-Alert-Key": "wrong"}])
def test_sender_key_is_required_when_set(client, log_file, monkeypatch, headers):
    from receiver import main

    monkeypatch.setattr(main, "KEY", "s3cret")
    r = client.post("/alert", json=ALERT, headers=headers)
    assert r.status_code == 401
    entry = read_lines(log_file)[0]
    assert entry["event"] == "rejected" and entry["reason"] == "missing or wrong sender key"
    assert entry["alert_id"] is None  # the body of an unknown sender is not even read


def test_right_sender_key_is_accepted_and_health_needs_none(client, monkeypatch):
    from receiver import main

    monkeypatch.setattr(main, "KEY", "s3cret")
    assert client.post("/alert", json=ALERT, headers={"X-Alert-Key": "s3cret"}).status_code == 200
    assert client.get("/health").json()["sender_key_required"] is True  # the watchdog has no key


def test_stub_sends_the_key_when_one_is_set(client, monkeypatch, capsys):
    import httpx
    from receiver import main
    from stub import send_alert

    monkeypatch.setattr(main, "KEY", "s3cret")
    monkeypatch.setenv("ALERT_KEY", "s3cret")
    monkeypatch.setattr(httpx, "post", lambda url, json, headers=None: client.post("/alert", json=json,
                                                                                   headers=headers))
    send_alert.main(str(pathlib.Path(__file__).resolve().parent.parent / "schema" / "sample_alert.json"))
    assert capsys.readouterr().out.startswith("200")


def test_live_alerts_are_handled_one_at_a_time(client, monkeypatch):
    # FastAPI runs each request on its own worker thread. Without the lock two alerts could correlate against the
    # incident list at the same time. This counts how many are inside the responder at once.
    import time
    from receiver import main

    inside, most = [0], [0]
    real = main.RESPONDER.handle

    def slow(*args):
        inside[0] += 1
        most[0] = max(most[0], inside[0])
        time.sleep(0.02)
        try:
            return real(*args)
        finally:
            inside[0] -= 1

    monkeypatch.setattr(main.RESPONDER, "handle", slow)
    replies = []
    workers = [threading.Thread(target=lambda i=i: replies.append(client.post(
        "/alert", json={**ALERT, "alert_id": f"a{i}", "affected_subsystem": f"M{i}"}).json()))
        for i in range(10)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert most[0] == 1
    assert sorted(r["incident_id"] for r in replies) == list(range(1, 11))


def test_stub_sends_the_sample_alert_and_it_is_logged(client, log_file, monkeypatch, capsys):
    import httpx
    from stub import send_alert

    monkeypatch.setattr(httpx, "post", lambda url, json, headers=None: client.post("/alert", json=json))
    send_alert.main(str(pathlib.Path(__file__).resolve().parent.parent / "schema" / "sample_alert.json"))
    assert "200" in capsys.readouterr().out
    entry = read_lines(log_file)[0]
    assert entry["alert_id"] == "a1" and entry["tier"] == 2
    assert entry["observed_at"] == "2026-10-01T14:22:29Z"  # the string Team B sent, not a reformatted one


def test_receiver_rejects_a_confidence_that_is_not_a_number(client, log_file):
    # B6: this was a 500 with nothing in the log. Now it breaks the schema and says which field.
    r = client.post("/alert", json={**ALERT, "confidence": "high"})
    assert r.status_code == 422
    entry = read_lines(log_file)[0]
    assert entry["event"] == "rejected" and entry["fields"] == ["confidence"]
    assert entry["alert_id"] == "a1" and entry["confidence"] == "high"


def test_receiver_logs_a_body_it_rejects(client, log_file):
    # B6: a body that is not a JSON object got a 422 and left no trace.
    r = client.post("/alert", content=b"[1, 2]", headers={"content-type": "application/json"})
    assert r.status_code == 422
    entry = read_lines(log_file)[0]
    assert entry["event"] == "rejected" and entry["received_at"] is not None


@pytest.mark.parametrize("change, field", [
    ({"schema_version": "2.0"}, "schema_version"),
    ({"alert_id": ""}, "alert_id"),
    ({"alert_id": 7}, "alert_id"),
    ({"emitted_at": "yesterday"}, "emitted_at"),
    ({"observed_at": "2026-10-01T14:22:29"}, "observed_at"),  # no timezone
    ({"incident_class": None}, "incident_class"),
    ({"confidence": True}, "confidence"),
    ({"confidence": "0.9"}, "confidence"),
    ({"confidence": 1.5}, "confidence"),
    ({"confidence": -0.1}, "confidence"),
    ({"affected_subsystem": ""}, "affected_subsystem"),
])
def test_receiver_enforces_the_alert_schema(client, log_file, change, field):
    r = client.post("/alert", json={**ALERT, **change})
    assert r.status_code == 422
    entry = read_lines(log_file)[0]
    assert entry["event"] == "rejected" and entry["fields"] == [field]


@pytest.mark.parametrize("field", ["schema_version", "alert_id", "emitted_at", "observed_at",
                                   "incident_class", "confidence", "affected_subsystem"])
def test_receiver_rejects_an_alert_missing_a_field(client, log_file, field):
    r = client.post("/alert", json={k: v for k, v in ALERT.items() if k != field})
    assert r.status_code == 422
    assert read_lines(log_file)[0]["fields"] == [field]


def test_receiver_lets_extra_fields_through(client, log_file):
    deviation = {"signal": "cycle_time_s", "expected_band": [10.0, 12.0], "actual": 17.4}
    r = client.post("/alert", json={**ALERT, "confidence": 1, "observed_deviation": deviation})
    assert r.status_code == 200 and r.json()["tier"] == 2


def test_live_alerts_are_correlated_and_repeats_suppressed(client, log_file):
    first = client.post("/alert", json=ALERT).json()
    second = client.post("/alert", json={**ALERT, "alert_id": "a2"}).json()
    assert first == second == {"decision": "matched", "tier": 2, "rule": "T0836", "incident_id": 1}
    assert [e["event"] for e in read_lines(log_file)] == ["decision", "suppressed"]


def test_live_alerts_escalate_one_incident(client, log_file):
    low = client.post("/alert", json={**ALERT, "confidence": 0.5}).json()
    high = client.post("/alert", json={**ALERT, "alert_id": "a2"}).json()
    assert low["tier"] == 1 and high["tier"] == 2 and low["incident_id"] == high["incident_id"]
    entries = read_lines(log_file)
    assert [(e["event"], e["action"]) for e in entries] == [("decision", "alert_operator"), ("decision", "isolate")]
    assert entries[1]["escalated"] is True


def test_live_disruptive_actions_are_rate_limited(client, log_file):
    # policy: at most 2 tier 2 or 3 actions per 60 seconds, extra ones drop to tier 1.
    tiers = [client.post("/alert", json={**ALERT, "alert_id": f"a{i}", "affected_subsystem": f"M{i}"}).json()["tier"]
             for i in range(3)]
    assert tiers == [2, 2, 1]
    assert read_lines(log_file)[2]["reason"] == "rate_limited"
