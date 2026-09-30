from __future__ import annotations
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_triage_resolution as tr
from hermes_cli import kanban_verified_archive as kva

@pytest.fixture
def board(tmp_path):
    path = tmp_path / "board.db"
    kbc.init_db(path)
    conn = kbc.connect(path)
    yield conn
    conn.close()

def triage(conn, **kwargs):
    task = kb.create_task(conn, title="gate", body="x", **kwargs)
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET status='triage' WHERE id=?", (task,))
    return task

def test_resolve_triage_records_run_comment_and_events(board):
    task = triage(board)
    result = tr.resolve_triage(board, task, verdict="PASS: independently checked", reason="reviewed evidence", actor="operator")
    assert result == {"task_id": task, "status": "done", "verdict": "PASS: independently checked"}
    assert kb.get_task(board, task).status == "done"
    assert [row["kind"] for row in board.execute("SELECT kind FROM task_events WHERE task_id=? AND kind IN ('triage_resolved','completed')", (task,))] == ["triage_resolved", "completed"]
    assert board.execute("SELECT result FROM tasks WHERE id=?", (task,)).fetchone()["result"] == result["verdict"]
    assert board.execute("SELECT COUNT(*) FROM task_runs WHERE task_id=? AND outcome='completed'", (task,)).fetchone()[0] == 1

@pytest.mark.parametrize("verdict,reason", [("FAIL","reason"),("REJECT","reason"),("PASS", ""),("", "reason")])
def test_refuses_rejection_or_empty_proof(board, verdict, reason):
    task = triage(board)
    with pytest.raises(tr.TriageResolutionDenied):
        tr.resolve_triage(board, task, verdict=verdict, reason=reason, actor="operator")
    assert kb.get_task(board,task).status == "triage"

def test_rejected_gate_cannot_be_resolved_to_success(board):
    task = triage(board)
    kva.record_gate_verdict(board, task, gate_kind="qa", verdict="FAIL", candidate_sha="a"*40, reviewer="hermes:qa", author="hermes:builder")
    with pytest.raises(tr.TriageResolutionDenied, match="rejected gate"):
        tr.resolve_triage(board, task, verdict="PASS", reason="not a replacement", actor="operator")
    assert kb.get_task(board,task).status == "triage"

def test_nontriage_and_unsatisfied_parent_denied(board):
    task = kb.create_task(board,title="ready")
    with pytest.raises(tr.TriageResolutionDenied, match="must be triage"):
        tr.resolve_triage(board, task, verdict="PASS", reason="checked", actor="operator")
    task = triage(board)
    parent = kb.create_task(board,title="parent")
    kb.link_tasks(board,parent,task)
    with pytest.raises(tr.TriageResolutionDenied, match="unsatisfied parents"):
        tr.resolve_triage(board, task, verdict="PASS", reason="checked", actor="operator")


def test_triage_cannot_bypass_merge_or_review_stage(board):
    merge = triage(board)
    review = triage(board)
    with kb.write_txn(board):
        kb._append_event(board, merge, "pipeline_stage", {"stage": "closure_merge", "feature_id": "F-003"})
        kb._append_event(board, review, "pipeline_stage", {"stage": "security_review", "feature_id": "F-003"})
    with pytest.raises(tr.TriageResolutionDenied, match="merge stage"):
        tr.resolve_triage(board, merge, verdict="PASS", reason="not authorized", actor="operator")
    with pytest.raises(tr.TriageResolutionDenied, match="structured approving"):
        tr.resolve_triage(board, review, verdict="PASS", reason="not authorized", actor="operator")


def test_triage_cannot_bypass_pr_acceptance(board):
    task = triage(board)
    with kb.write_txn(board):
        board.execute("UPDATE tasks SET completion_contract=? WHERE id=?", ("example/repo", task))
    with pytest.raises(tr.TriageResolutionDenied, match="PR contract"):
        tr.resolve_triage(board, task, verdict="PASS", reason="not authorized", actor="operator")


def test_resolve_cli_json_and_worker_denial(board, monkeypatch, capsys):
    import argparse
    from contextlib import contextmanager
    from hermes_cli import kanban as cli
    task = triage(board)
    @contextmanager
    def connection():
        yield board
    monkeypatch.setattr(cli.kbc, "connect_closing", connection)
    monkeypatch.setattr(cli, "_profile_author", lambda: "operator")
    args = argparse.Namespace(task_id=task, verdict="PASS", reason="independent evidence", json=True)
    assert cli._cmd_resolve_triage(args) == 0
    import json
    assert json.loads(capsys.readouterr().out) == {"task_id": task, "status": "done", "verdict": "PASS"}
    other = triage(board)
    args.task_id = other
    monkeypatch.setenv("HERMES_KANBAN_TASK", "some-worker-card")
    assert cli._cmd_resolve_triage(args) == 2
    assert kb.get_task(board, other).status == "triage"
