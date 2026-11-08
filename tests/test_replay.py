from engine import log
from sim.replay import replay, show, summarise


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


def test_median_and_worst_are_computed_correctly():
    # Found by mutation testing: reporting the best case as "worst" passed every other test.
    assert summarise([3.0, 1.0, 2.0, None]) == {"median": 2.0, "worst": 3.0, "n": 3}
    assert summarise([None, None]) is None and summarise([]) is None


def test_printed_table_matches_the_computed_numbers(tmp_path, capsys):
    results = replay(seeds=range(2), operator_delays=(5,), out=tmp_path)
    show(results)
    out = capsys.readouterr().out
    row = results["by_delay"]["5"]["skip_step / layer on"]
    printed = next(line for line in out.splitlines() if "skip_step / layer on" in line)
    s = row["safe_state_s"]
    assert f"safe state {s['median']:.1f}/{s['worst']:.1f}" in printed
    assert f"recovered {row['recovery_rate']:.0%}" in printed and f"bad {row['bad_items']:.0f}" in printed
    clean = next(line for line in out.splitlines() if "clean / layer off" in line)
    assert "detect -" in clean and "safe state -" in clean and "wrong  -" in clean  # nothing measured shows as -
    assert "2 of 18" in out


def test_replay_leaves_the_live_log_alone(tmp_path):
    before = log.LOG
    small(tmp_path, "a")
    assert log.LOG == before and (tmp_path / "a" / "results.json").exists()
