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
    seam.bind_pr_target(board, tid, pr_url=url, head_sha=sha, actor="operator",
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
    seam.bind_pr_target(board, tid, pr_url=url, head_sha="a"*40, actor="operator",
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


def test_publish_aborts_on_existing_pr_without_push(board, tmp_path):
    tid = kb.create_task(board, title="publish", workspace_kind="worktree",
                         workspace_path=str(tmp_path), branch_name="feature")
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("git", "branch", "--show-current"):
            return "feature"
        if args[:3] == ("git", "rev-parse", "HEAD"):
            return "a"*40
        if args[:2] == ("git", "status"):
            return ""
        if args[:3] == ("gh", "pr", "list"):
            return json.dumps([{"url":"existing"}])
        pytest.fail("unexpected command")
    with pytest.raises(seam.OperatorSeamError, match="already exists"):
        seam.publish_and_continue(board, tid, repo=tmp_path, remote="origin", base="main",
                                  actor="operator", reason="publish", run=run)
    assert not any(c[:2] == ("git", "push") for c in calls)


def test_publish_verifies_remote_sha_before_creating_pr(board, tmp_path):
    tid = kb.create_task(board, title="publish", workspace_kind="worktree",
                         workspace_path=str(tmp_path), branch_name="feature")
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("git", "branch", "--show-current"):
            return "feature"
        if args[:3] == ("git", "rev-parse", "HEAD"):
            return "a"*40
        if args[:2] == ("git", "status"):
            return ""
        if args[:3] == ("gh", "pr", "list"):
            return "[]"
        if args[:2] == ("git", "push"):
            return ""
        if args[:2] == ("git", "ls-remote"):
            return "b"*40 + " refs/heads/feature"
        pytest.fail("PR created despite remote head mismatch")
    with pytest.raises(seam.OperatorSeamError, match="remote head mismatch"):
        seam.publish_and_continue(board, tid, repo=tmp_path, remote="origin", base="main",
                                  actor="operator", reason="publish", run=run)
    assert not any(c[:3] == ("gh", "pr", "create") for c in calls)


def test_binding_refuses_pr_from_another_repository(board):
    tid = kb.create_task(board, title="review", body="Repository: `example/repo`", assignee="worker")
    sha = "a" * 40
    url = "https:" + "//github.com/other/repo/pull/12"
    with pytest.raises(seam.OperatorSeamError, match="repository"):
        seam.bind_pr_target(board, tid, pr_url=url, head_sha=sha, actor="operator",
            run=lambda *args, **kwargs: pytest.fail("unrelated PR should not be fetched"))
    assert not [e for e in kb.list_events(board, tid) if e.kind == "pr_target_bound"]


def test_same_head_on_unbound_pr_cannot_continue(board):
    task = kb.create_task(board, title="review", body="Repository: `example/repo`")
    bound = "https:" + "//github.com/example/repo/pull/12"
    other = "https:" + "//github.com/example/repo/pull/13"
    sha = "a" * 40
    seam.bind_pr_target(board, task, pr_url=bound, head_sha=sha, actor="operator",
        run=lambda *a: json.dumps({"url":bound,"state":"OPEN","headRefOid":sha,
            "headRefName":"feature","baseRepository":{"nameWithOwner":"example/repo"}}))
    with pytest.raises(seam.OperatorSeamError, match="bound card target"):
        seam.continue_verified_pr(board, task, pr_url=other, head_sha=sha,
            actor="operator", reason="read only", run=lambda *a: pytest.fail("unbound PR fetched"))
    assert not [e for e in kb.list_events(board, task) if e.kind == "pr_continuation"]
