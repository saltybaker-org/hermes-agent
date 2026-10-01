import sys
import json
from types import SimpleNamespace
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_operator_seam as seam
from hermes_cli import kanban_db_dispatch as dispatch

@pytest.fixture
def board(tmp_path):
    db = tmp_path / "kanban.db"
    kbc.init_db(db)
    conn = kbc.connect(db)
    yield conn
    conn.close()

def test_exact_head_continuation_orders_comment_and_event_with_same_second(board, monkeypatch):
    tid = kb.create_task(board, title="gate", body="Repository: `example/repo`", assignee="worker")
    sha = "a" * 40
    url = "https:" + "//github.com/example/repo/pull/12"
    pr = {"url": url, "state": "OPEN", "headRefOid": sha,
          "headRefName": "feature", "baseRepository": {"nameWithOwner": "example/repo"}}
    seam.bind_pr_target(board, tid, pr_url=url, head_sha=sha, actor="operator", reason="operator readback",
        run=lambda *a: json.dumps(pr))
    monkeypatch.setattr(dispatch, "check_respawn_guard", lambda conn, task_id: None)
    def spawn(conn):
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='running',last_heartbeat_at=123,current_run_id=NULL WHERE id=?", (tid,))
            kb._append_event(conn, tid, "heartbeat", {"note": "fresh"})
        return SimpleNamespace(spawned=[(tid, "worker", "/tmp")])
    receipt = seam.continue_verified_pr(board, tid, pr_url=url, head_sha=sha,
        actor="operator", reason="read only gate", timeout=0, dispatch_fn=spawn,
        run=lambda *a: json.dumps(pr))
    assert receipt["heartbeat_at"] == 123
    comments = kb.list_comments(board, tid)
    events = [e for e in kb.list_events(board, tid) if e.kind == "pr_continuation"]
    assert len(comments) == len(events) == 1
    assert events[0].payload["after_comment_id"] == comments[0].id

def test_mismatched_head_refuses_without_audit(board):
    tid = kb.create_task(board, title="gate", body="Repository: `example/repo`")
    url = "https:" + "//github.com/example/repo/pull/12"
    seam.bind_pr_target(board, tid, pr_url=url, head_sha="a"*40, actor="operator", reason="operator readback",
        run=lambda *a: json.dumps({"url":url,"state":"OPEN","headRefOid":"a"*40,
            "headRefName":"feature","baseRepository":{"nameWithOwner":"example/repo"}}))
    with pytest.raises(seam.OperatorSeamError, match="head mismatch"):
        seam.continue_verified_pr(board, tid, pr_url=url, head_sha="a"*40,
            actor="operator", reason="gate", run=lambda *a: json.dumps({"url":url,"state":"OPEN","headRefOid":"b"*40}))
    assert not kb.list_comments(board, tid)
    assert not [e for e in kb.list_events(board, tid) if e.kind == "pr_continuation"]

@pytest.mark.parametrize("url", ["https:"+"//evil.invalid/a/b/pull/1", "https:"+"//github.com/a/b/pull/1?x=y"])
def test_bad_target_refuses_before_network(board, url):
    tid = kb.create_task(board, title="gate")
    with pytest.raises(seam.OperatorSeamError):
        seam.continue_verified_pr(board, tid, pr_url=url, head_sha="a"*40,
            actor="operator", reason="gate", run=lambda *a: pytest.fail("network called"))

def test_operator_wakeup_requires_typed_wait_and_heartbeat(board):
    tid = kb.create_task(board, title="wait", assignee="worker")
    with pytest.raises(seam.OperatorSeamError, match="not waiting"):
        seam.wake_operator_wait(board, tid, reason="ready", timeout=0)
    assert kb.block_task(board, tid, kind="operator_wait", reason="seam")
    def spawn(conn):
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='running',last_heartbeat_at=123 WHERE id=?", (tid,))
            kb._append_event(conn, tid, "heartbeat", {"note": "fresh"})
        return SimpleNamespace(spawned=[(tid,"worker","/tmp")])
    assert seam.wake_operator_wait(board, tid, reason="operator completed seam", dispatch_fn=spawn, timeout=0)["heartbeat_at"] == 123
    assert any(e.kind == "unblocked" for e in kb.list_events(board, tid))


def test_binding_refuses_pr_from_another_repository(board):
    tid = kb.create_task(board, title="review", body="Repository: `example/repo`", assignee="worker")
    sha = "a" * 40
    url = "https:" + "//github.com/other/repo/pull/12"
    with pytest.raises(seam.OperatorSeamError, match="repository"):
        seam.bind_pr_target(board, tid, pr_url=url, head_sha=sha, actor="operator", reason="operator readback",
            run=lambda *args, **kwargs: pytest.fail("unrelated PR should not be fetched"))
    assert not [e for e in kb.list_events(board, tid) if e.kind == "pr_target_bound"]


def test_same_head_on_unbound_pr_cannot_continue(board):
    task = kb.create_task(board, title="review", body="Repository: `example/repo`")
    bound = "https:" + "//github.com/example/repo/pull/12"
    other = "https:" + "//github.com/example/repo/pull/13"
    sha = "a" * 40
    seam.bind_pr_target(board, task, pr_url=bound, head_sha=sha, actor="operator", reason="operator readback",
        run=lambda *a: json.dumps({"url":bound,"state":"OPEN","headRefOid":sha,
            "headRefName":"feature","baseRepository":{"nameWithOwner":"example/repo"}}))
    with pytest.raises(seam.OperatorSeamError, match="bound card target"):
        seam.continue_verified_pr(board, task, pr_url=other, head_sha=sha,
            actor="operator", reason="read only", run=lambda *a: pytest.fail("unbound PR fetched"))
    assert not [e for e in kb.list_events(board, task) if e.kind == "pr_continuation"]


@pytest.mark.parametrize("action", ["operator-wake", "operator-bind-pr", "operator-continue-pr", "operator-publish-pr"])
def test_delegated_child_cannot_call_operator_cli(action, monkeypatch):
    from hermes_cli import kanban
    from agent import delegation_context
    monkeypatch.setattr(delegation_context, "kanban_path_is_fenced", lambda path: True)
    assert kanban._is_delegated_child_cli_mutation(SimpleNamespace(kanban_action=action))


def test_operator_bind_cli_persists_its_required_reason(board, monkeypatch):
    from contextlib import contextmanager
    from hermes_cli import kanban as cli
    task = kb.create_task(board, title="review", body="Repository: `example/repo`")
    url = "https:" + "//github.com/example/repo/pull/12"
    sha = "a" * 40
    pr = {"url": url, "state": "OPEN", "headRefOid": sha,
          "headRefName": "feature", "baseRepository": {"nameWithOwner": "example/repo"}}
    @contextmanager
    def connection():
        yield board
    monkeypatch.setattr(cli.kbc, "connect_closing", connection)
    monkeypatch.setattr(cli, "_profile_author", lambda: "operator")
    original_bind = seam.bind_pr_target
    monkeypatch.setattr(seam, "bind_pr_target", lambda *a, **kw: original_bind(*a, run=lambda *cmd: json.dumps(pr), **kw))
    args = SimpleNamespace(kanban_action="operator-bind-pr", task_id=task,
                           pr_url=url, head_sha=sha, reason=["manual", "review"])
    assert cli._cmd_operator_seam(args) == 0
    event = next(e for e in kb.list_events(board, task) if e.kind == "pr_target_bound")
    assert event.payload["reason"] == "manual review"


def test_operator_publication_never_executes_worker_worktree_commands(board, tmp_path):
    task = kb.create_task(board, title="publish", workspace_kind="worktree",
                          workspace_path=str(tmp_path), branch_name="feature")
    with pytest.raises(seam.OperatorSeamError, match="credentialed auto-push is disabled"):
        seam.publish_and_continue(board, task, repo=tmp_path, remote="origin", base="main",
                                  actor="operator", reason="scoped",
                                  run=lambda *a, **kw: pytest.fail("untrusted card Git config executed"))


def test_manual_pr_publication_recovery_binds_then_continues(board, monkeypatch, tmp_path):
    from contextlib import contextmanager
    from hermes_cli import kanban as cli
    task = kb.create_task(board, title="review", body="Repository: `example/repo`",
                          workspace_kind="worktree", workspace_path=str(tmp_path),
                          branch_name="feature", assignee="worker")
    url = "https:" + "//github.com/example/repo/pull/12"
    sha = "a" * 40
    pr = {"url": url, "state": "OPEN", "headRefOid": sha,
          "headRefName": "feature", "baseRepository": {"nameWithOwner": "example/repo"}}
    @contextmanager
    def connection():
        yield board
    monkeypatch.setattr(cli.kbc, "connect_closing", connection)
    monkeypatch.setattr(cli, "_profile_author", lambda: "operator")
    original_bind, original_continue = seam.bind_pr_target, seam.continue_verified_pr
    monkeypatch.setattr(seam, "bind_pr_target", lambda *a, **kw: original_bind(*a, run=lambda *cmd: json.dumps(pr), **kw))
    def spawn(conn):
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='running',last_heartbeat_at=123 WHERE id=?", (task,))
            kb._append_event(conn, task, "heartbeat", {"note": "fresh"})
        return SimpleNamespace(spawned=[(task, "worker", "isolated")])
    monkeypatch.setattr(dispatch, "check_respawn_guard", lambda conn, task_id: None)
    monkeypatch.setattr(seam, "continue_verified_pr", lambda *a, **kw: original_continue(
        *a, run=lambda *cmd: json.dumps(pr), dispatch_fn=spawn, timeout=0, **kw))
    bind = SimpleNamespace(kanban_action="operator-bind-pr", task_id=task, pr_url=url,
                           head_sha=sha, reason=["existing", "PR", "readback"])
    assert cli._cmd_operator_seam(bind) == 0
    cont = SimpleNamespace(kanban_action="operator-continue-pr", task_id=task, pr_url=url,
                           head_sha=sha, reason=["recover", "after", "publication"])
    assert cli._cmd_operator_seam(cont) == 0
    assert kb.get_task(board, task).status == "running"
    assert len([e for e in kb.list_events(board, task) if e.kind == "pr_target_bound"]) == 1
    assert len([e for e in kb.list_events(board, task) if e.kind == "pr_continuation"]) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="Linux operator binary trust anchor")
def test_github_readback_does_not_execute_path_substitute(tmp_path, monkeypatch):
    fake = tmp_path / "gh"
    fake.write_text("#!/bin/sh\nprintf 'FAKE GH\n'\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert seam.command("gh", "--version").startswith("gh version")


def test_concurrent_binding_cannot_create_two_immutable_targets(board):
    task = kb.create_task(board, title="review", body="Repository: `example/repo`")
    url = "https:" + "//github.com/example/repo/pull/12"
    sha = "a" * 40
    pr = {"url": url, "state": "OPEN", "headRefOid": sha,
          "headRefName": "feature", "baseRepository": {"nameWithOwner": "example/repo"}}
    def competing_readback(*args):
        with kb.write_txn(board):
            kb._append_event(board, task, "pr_target_bound", {"pr_url": url,
                "head_sha": sha, "repository": "example/repo", "head_ref": "feature",
                "actor": "other", "reason": "first bind"})
        return json.dumps(pr)
    with pytest.raises(seam.OperatorSeamError, match="immutable"):
        seam.bind_pr_target(board, task, pr_url=url, head_sha=sha,
                            actor="operator", reason="second bind", run=competing_readback)
    assert len([e for e in kb.list_events(board, task) if e.kind == "pr_target_bound"]) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="Linux operator environment isolation")
def test_operator_github_command_scrubs_untrusted_environment(monkeypatch):
    from types import SimpleNamespace as NS
    monkeypatch.setenv("LD_PRELOAD", "/untrusted/agent-hook.so")
    monkeypatch.setenv("GH_TOKEN", "untrusted-token")
    seen = []
    def run(argv, **kwargs):
        seen.append(kwargs)
        return NS(returncode=0, stdout='{"state":"OPEN"}')
    monkeypatch.setattr(seam.subprocess, "run", run)
    assert seam.command("gh", "pr", "view", "https://github.com/example/repo/pull/12")
    assert "LD_PRELOAD" not in seen[0]["env"]
    assert "GH_TOKEN" not in seen[0]["env"]
    assert seen[0]["cwd"] == seen[0]["env"]["HOME"]


def test_card_repository_change_during_github_readback_refuses_binding(board):
    task = kb.create_task(board, title="review", body="Repository: `example/repo`")
    url = "https:" + "//github.com/example/repo/pull/12"
    sha = "a" * 40
    pr = {"url": url, "state": "OPEN", "headRefOid": sha,
          "headRefName": "feature", "baseRepository": {"nameWithOwner": "example/repo"}}
    def concurrent_edit(*args):
        with kb.write_txn(board):
            board.execute("UPDATE tasks SET body=? WHERE id=?", ("Repository: `other/repo`", task))
        return json.dumps(pr)
    with pytest.raises(seam.OperatorSeamError, match="card repository changed"):
        seam.bind_pr_target(board, task, pr_url=url, head_sha=sha,
                            actor="operator", reason="readback", run=concurrent_edit)
    assert not [e for e in kb.list_events(board, task) if e.kind == "pr_target_bound"]
