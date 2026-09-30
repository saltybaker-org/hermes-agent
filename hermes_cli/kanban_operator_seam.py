"""Credentialed PR publication and continuation with exact-head readback."""
import json
import re
import sqlite3
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_dispatch as dispatch

class OperatorSeamError(RuntimeError):
    pass

def command(*argv, cwd=None):
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise OperatorSeamError("operator command failed: " + argv[0])
    return result.stdout.strip()

def valid_url(value):
    u = urlparse(value)
    return (u.scheme == "https" and u.hostname == "github.com" and
            not u.username and not u.password and not u.port and not u.query and
            not u.fragment and bool(re.fullmatch(r"/[^/]+/[^/]+/pull/[1-9][0-9]*", u.path)))

def continue_verified_pr(conn, task_id, *, pr_url, head_sha, actor, reason,
                         run=command, dispatch_fn=None, timeout=30):
    """Authorize exact open PR, dispatch and require fresh worker heartbeat."""
    if not valid_url(pr_url) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise OperatorSeamError("exact PR URL and head SHA required")
    if not actor.strip() or not reason.strip():
        raise OperatorSeamError("actor and scoped reason required")
    card = kb.get_task(conn, task_id)
    if card is None or card.status != "ready":
        raise OperatorSeamError("card must be ready")
    try:
        pr = json.loads(run("gh", "pr", "view", pr_url, "--json", "url,state,headRefOid"))
    except (ValueError, KeyError) as exc:
        raise OperatorSeamError("PR readback malformed") from exc
    if pr.get("url") != pr_url or pr.get("state") != "OPEN" or pr.get("headRefOid") != head_sha:
        raise OperatorSeamError("open PR or head mismatch")
    kb.add_comment(conn, task_id, actor, f"Verified PR {pr_url} at head {head_sha}; {reason}")
    if not kb.record_pr_continuation(conn, task_id, actor=actor, reason=reason):
        raise OperatorSeamError("card changed before authorization")
    if dispatch.check_respawn_guard(conn, task_id) == "active_pr":
        raise OperatorSeamError("PR guard remains armed")
    prior_heartbeat = conn.execute("SELECT COALESCE(MAX(id),0) FROM task_events WHERE task_id=? AND kind='heartbeat'", (task_id,)).fetchone()[0]
    result = (dispatch_fn or dispatch.dispatch_once)(conn)
    if task_id not in [item[0] for item in result.spawned]:
        raise OperatorSeamError("dispatch did not spawn authorized card")
    deadline = time.monotonic() + timeout
    while True:
        current = kb.get_task(conn, task_id)
        fresh = conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='heartbeat' AND id>? LIMIT 1", (task_id, prior_heartbeat)).fetchone()
        if current and current.status == "running" and current.last_heartbeat_at and fresh:
            return {"task_id": task_id, "pr_url": pr_url, "head_sha": head_sha,
                    "run_id": current.current_run_id, "heartbeat_at": current.last_heartbeat_at}
        if time.monotonic() >= deadline:
            raise OperatorSeamError("spawned but no heartbeat observed")
        time.sleep(min(.2, max(0, deadline - time.monotonic())))

def publish_and_continue(conn, task_id, *, repo, remote, base, actor, reason,
                         run=command, **kwargs):
    """Push exact branch, open PR and perform audited continuation. Never merge."""
    card = kb.get_task(conn, task_id)
    if card is None or card.status != "ready" or card.workspace_kind != "worktree":
        raise OperatorSeamError("publication requires ready worktree card")
    repo = Path(repo).resolve(strict=True)
    if repo != Path(card.workspace_path).resolve(strict=True):
        raise OperatorSeamError("repository differs from card workspace")
    branch = run("git", "branch", "--show-current", cwd=repo)
    sha = run("git", "rev-parse", "HEAD", cwd=repo)
    if branch != card.branch_name or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise OperatorSeamError("card branch/head mismatch")
    if run("git", "status", "--porcelain", cwd=repo):
        raise OperatorSeamError("dirty publication checkout")
    try:
        existing = json.loads(run("gh", "pr", "list", "--head", branch,
                                  "--state", "open", "--json", "url", cwd=repo))
    except ValueError as exc:
        raise OperatorSeamError("existing PR query malformed") from exc
    if not isinstance(existing, list) or existing:
        raise OperatorSeamError("open PR already exists; use exact-head continuation")
    run("git", "push", remote, "HEAD:refs/heads/" + branch, cwd=repo)
    if run("git", "ls-remote", remote, "refs/heads/" + branch, cwd=repo).split()[0] != sha:
        raise OperatorSeamError("remote head mismatch")
    url = run("gh", "pr", "create", "--base", base, "--head", branch,
              "--title", card.title, "--body", card.body or "", cwd=repo).splitlines()[-1]
    return continue_verified_pr(conn, task_id, pr_url=url, head_sha=sha,
                                actor=actor, reason=reason, run=run, **kwargs)


def wake_operator_wait(conn, task_id, *, reason, dispatch_fn=None, timeout=30):
    """Wake a typed operator wait, dispatch and observe the new heartbeat."""
    card = kb.get_task(conn, task_id)
    if card is None or card.status != "blocked" or card.block_kind != "operator_wait":
        raise OperatorSeamError("card is not waiting on operator")
    if not reason.strip() or not kb.unblock_task(conn, task_id, reason=reason, author="operator"):
        raise OperatorSeamError("operator wakeup requires an audited reason")
    prior_heartbeat = conn.execute("SELECT COALESCE(MAX(id),0) FROM task_events WHERE task_id=? AND kind='heartbeat'", (task_id,)).fetchone()[0]
    result = (dispatch_fn or dispatch.dispatch_once)(conn)
    if task_id not in [item[0] for item in result.spawned]:
        raise OperatorSeamError("wakeup did not spawn card")
    deadline = time.monotonic() + timeout
    while True:
        current = kb.get_task(conn, task_id)
        fresh = conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='heartbeat' AND id>? LIMIT 1", (task_id, prior_heartbeat)).fetchone()
        if current and current.status == "running" and current.last_heartbeat_at and fresh:
            return {"task_id": task_id, "run_id": current.current_run_id,
                    "heartbeat_at": current.last_heartbeat_at}
        if time.monotonic() >= deadline:
            raise OperatorSeamError("wakeup spawned but no heartbeat observed")
        time.sleep(min(.2, max(0, deadline - time.monotonic())))
