import json
import subprocess
from pathlib import Path

import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_dispatch as dispatch
from hermes_cli import kanban_db_workspace as workspace
from hermes_cli import kanban_jev_gate as gate


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test")
    (repo / "required.txt").write_text("base")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "branch", "upstream")
    wt = tmp_path / "worker"
    git(repo, "worktree", "add", "-qb", "worker-branch", str(wt))
    db = tmp_path / "board" / "kanban.db"
    db.parent.mkdir()
    kbc.init_db(db)
    conn = kbc.connect(db)
    (db.parent / "board.json").write_text(json.dumps({
        "jev_mutation_gate": {"enabled": True},
        "workspace_preflight": {"upstream_ref": "refs/heads/upstream", "required_paths": ["required.txt"]},
    }))
    monkeypatch.setattr(gate, "authorize_card", lambda *args: {"dispatch_allowed": True})
    monkeypatch.setattr(dispatch, "_profile_exists_fn", lambda: lambda _: True)
    yield repo, wt, conn
    conn.close()


def task(conn, wt):
    tid = kb.create_task(conn, title="repair", body="valid", assignee="worker",
                         workspace_kind="worktree", workspace_path=str(wt), branch_name="worker-branch")
    return kb.get_task(conn, tid)


def test_registered_worktree_passes(checkout):
    repo, wt, conn = checkout
    receipt = workspace.preflight_registered_worktree(task(conn, wt), wt, conn=conn)
    assert receipt["branch"] == "worker-branch"
    assert receipt["head"] == git(wt, "rev-parse", "HEAD")


@pytest.mark.parametrize("defect", ["stale", "missing_path", "deleted_registration", "dirty"])
def test_invalid_worktree_fails_before_worker_spawn(checkout, defect):
    repo, wt, conn = checkout
    t = task(conn, wt)
    if defect == "stale":
        (repo / "new.txt").write_text("new upstream")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "upstream")
        git(repo, "branch", "-f", "upstream", "HEAD")
    elif defect == "missing_path":
        (wt / "required.txt").unlink()
        git(wt, "add", ".")
        git(wt, "commit", "-qm", "remove")
    elif defect == "deleted_registration":
        (wt / ".git").unlink()
    else:
        (wt / "required.txt").write_text("dirty")
    spawned = []
    result = dispatch.dispatch_once(conn, spawn_fn=lambda *_args, **_kw: spawned.append(1) or 10)
    assert not spawned
    assert t.id in result.auto_blocked
    assert kb.get_task(conn, t.id).status == "blocked"


def test_missing_contract_is_fail_closed(checkout):
    repo, wt, conn = checkout
    t = task(conn, wt)
    db = Path(conn.execute("PRAGMA database_list").fetchall()[0][2])
    (db.parent / "board.json").write_text(json.dumps({"jev_mutation_gate": {"enabled": True}}))
    with pytest.raises(gate.JevAuthorizationError, match="upstream_ref"):
        workspace.preflight_registered_worktree(t, wt, conn=conn)


def test_operator_wait_is_typed_sticky_and_wakes(checkout):
    repo, wt, conn = checkout
    t = task(conn, wt)
    assert kb.block_task(conn, t.id, kind="operator_wait", reason="credentialed publication needed")
    assert kb.get_task(conn, t.id).block_kind == "operator_wait"
    assert kb.get_task(conn, t.id).status == "blocked"
    assert any(e.kind == "blocked" and e.payload.get("kind") == "operator_wait" for e in kb.list_events(conn, t.id))
