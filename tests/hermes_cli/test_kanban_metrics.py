from pathlib import Path

import json

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc


@pytest.fixture
def board(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    with kbc.connect() as conn:
        yield conn


def _task(conn, task_id, created, completed=None, status="done"):
    conn.execute(
        "INSERT INTO tasks (id,title,status,priority,created_at,completed_at,workspace_kind) "
        "VALUES (?,?,?,0,?,?,'scratch')",
        (task_id, task_id, status, created, completed),
    )


def _run(conn, task_id, started, ended, outcome):
    conn.execute(
        "INSERT INTO task_runs (task_id,status,started_at,ended_at,outcome) VALUES (?,?,?,?,?)",
        (task_id, outcome, started, ended, outcome),
    )


def test_cohort_metrics_are_deterministic_and_classify_failures(board):
    _task(board, "a", 100, 140)
    _run(board, "a", 110, 140, "completed")
    _task(board, "b", 100, 190)
    _run(board, "b", 120, 150, "timed_out")
    _run(board, "b", 170, 190, "completed")

    got = kb.cohort_metrics(board, ["b", "a"], as_of=200)

    assert got["cohort_task_ids"] == ["a", "b"]
    assert got["run_outcomes"] == {"completed": 2, "timed_out": 1}
    assert got["durations"]["run_seconds"] == {
        "count": 3, "min": 20, "p50": 30, "p95": 30, "max": 30
    }
    assert got["durations"]["creation_to_first_start_seconds"] == {
        "count": 2, "min": 10, "p50": 10, "p95": 20, "max": 20
    }
    assert got["durations"]["retry_delay_seconds"] == {
        "count": 1, "min": 20, "p50": 20, "p95": 20, "max": 20
    }
    assert got["durations"]["cohort_wall_seconds"] == 90
    assert got["rates"]["worker_failure"] == {
        "numerator": 1, "denominator": 3, "value": pytest.approx(1 / 3)
    }
    assert got["rates"]["retry"] == {
        "numerator": 1, "denominator": 2, "value": 0.5
    }
    assert got["rates"]["first_attempt_success"] == {
        "numerator": 1, "denominator": 2, "value": 0.5
    }


def test_cohort_metrics_reject_unknown_and_duplicate_ids(board):
    _task(board, "a", 100, 110)
    with pytest.raises(ValueError, match="duplicate"):
        kb.cohort_metrics(board, ["a", "a"], as_of=200)
    with pytest.raises(ValueError, match="unknown"):
        kb.cohort_metrics(board, ["missing"], as_of=200)


def test_metrics_cli_emits_json_for_explicit_ids(board):
    _task(board, "a", 100, 140)
    _run(board, "a", 110, 140, "completed")
    payload = json.loads(kc.run_slash("metrics a --as-of 200 --json"))
    assert payload["cohort_task_ids"] == ["a"]
    assert payload["durations"]["cohort_wall_seconds"] == 40


def test_as_of_excludes_future_runs_and_terminal_events(board):
    _task(board,"a",100,250,status="done")
    _run(board,"a",110,150,"timed_out")
    _run(board,"a",210,250,"completed")
    got=kb.cohort_metrics(board,["a"],as_of=200)
    assert got["run_outcomes"]=={"timed_out":1}
    assert got["active_runs"]==0
    assert got["task_counts"]["incomplete"]==1
    assert got["durations"]["cohort_wall_seconds"] is None

def test_active_first_attempt_is_not_counted_as_failure(board):
    _task(board,"a",100,None,status="running")
    _run(board,"a",110,None,"running")
    got=kb.cohort_metrics(board,["a"],as_of=200)
    assert got["rates"]["first_attempt_success"]=={"numerator":0,"denominator":0,"value":None}

def test_negative_creation_to_start_counts_clock_anomaly(board):
    _task(board,"a",100,120)
    _run(board,"a",90,120,"completed")
    got=kb.cohort_metrics(board,["a"],as_of=200)
    assert got["clock_anomalies"]==1


def test_as_of_reconstructs_completion_then_reopen_from_events(board):
    _task(board,"a",100,None,status="ready")
    board.execute("INSERT INTO task_events(task_id,kind,payload,created_at) VALUES ('a','completed',NULL,120)")
    board.execute("INSERT INTO task_events(task_id,kind,payload,created_at) VALUES ('a','status',?,180)",(json.dumps({"status":"ready"}),))
    at_150=kb.cohort_metrics(board,["a"],as_of=150)
    at_200=kb.cohort_metrics(board,["a"],as_of=200)
    assert at_150["task_counts"]["incomplete"]==0
    assert at_150["durations"]["cohort_wall_seconds"]==20
    assert at_200["task_counts"]["incomplete"]==1
