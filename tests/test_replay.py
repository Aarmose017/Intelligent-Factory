from engine import log
from sim.replay import replay


def small(tmp_path, name):
    return replay(seeds=range(2), operator_delays=(5,), out=tmp_path / name)["by_delay"]["5"]


def test_measures_hold_what_the_layer_promises(tmp_path):
    rows = small(tmp_path, "a")
    assert rows["clean / layer on"]["wrong_actions"] == 0 and rows["clean / layer on"]["bad_items"] == 0
    for attack in ("drift", "skip_step"):
        assert rows[f"{attack} / layer on"]["recovery_rate"] == 1.0
        assert rows[f"{attack} / layer on"]["duplicate_actions"] == 0
    # With a 5 s operator delay, safe state stops some unprocessed items reaching the Sink.
    assert rows["skip_step / layer on"]["bad_items"] < rows["skip_step / layer off"]["bad_items"]
    assert rows["skip_step / layer on"]["safe_state_s"]["median"] > 5  # includes the operator delay


def test_same_seeds_give_the_same_numbers(tmp_path):
    assert small(tmp_path, "a") == small(tmp_path, "b")


def test_coverage_counts_threat_analysis_techniques_with_an_action(tmp_path):
    c = replay(seeds=range(1), operator_delays=(5,), out=tmp_path)["coverage"]
    assert c["techniques_in_threat_analysis"] == 18 and c["covered"] == ["T0836", "T0889"]


def test_replay_leaves_the_live_log_alone(tmp_path):
    before = log.LOG
    small(tmp_path, "a")
    assert log.LOG == before and (tmp_path / "a" / "results.json").exists()
