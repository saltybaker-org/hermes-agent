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
    result = subprocess.run(argv, cwd=cwd, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=60)
    if result.returncode:
        raise OperatorSeamError("operator command failed: " + argv[0])
    return result.stdout.strip()

def valid_url(value):
    u = urlparse(value)
    return (u.scheme == "https" and u.hostname == "github.com" and
            not u.username and not u.password and not u.port and not u.query and
            not u.fragment and bool(re.fullmatch(r"/[^/]+/[^/]+/pull/[1-9][0-9]*", u.path)))

def _card_repository(card):
    declared = re.search(r"(?im)^\s*-?\s*Repository:\s*`?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`?", card.body or "")
    if declared:
        return declared.group(1).lower()
    raise OperatorSeamError("card has no immutable Repository: owner/repo declaration")


def bind_pr_target(conn, task_id, *, pr_url, head_sha, actor, reason, run=command):
    """Operator readback binds a PR to the card's immutable repository row."""
    if not valid_url(pr_url) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise OperatorSeamError("exact PR URL and head SHA required")
    card = kb.get_task(conn, task_id)
    if card is None or card.status in {"done", "archived"} or not actor.strip() or not reason or not reason.strip():
        raise OperatorSeamError("target card must be active with named actor and scoped reason")
    expected_repo = _card_repository(card)
    url_repo = "/".join(urlparse(pr_url).path.strip("/").split("/")[:2]).lower()
    if url_repo != expected_repo:
        raise OperatorSeamError("PR repository differs from card repository")
    if conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='pr_target_bound'", (task_id,)).fetchone():
        raise OperatorSeamError("PR target is immutable; create a replacement card")
    try:
        pr = json.loads(run("gh", "pr", "view", pr_url, "--json",
            "url,state,headRefOid,headRefName,baseRepository"))
    except (ValueError, KeyError) as exc:
        raise OperatorSeamError("PR readback malformed") from exc
    base_repo = pr.get("baseRepository") or {}
    if (pr.get("url") != pr_url or pr.get("state") != "OPEN" or
        pr.get("headRefOid") != head_sha or
        base_repo.get("nameWithOwner", "").lower() != expected_repo):
        raise OperatorSeamError("PR repository, state or head mismatch")
    if card.branch_name and pr.get("headRefName") != card.branch_name:
        raise OperatorSeamError("PR branch differs from card branch")
    payload = {"pr_url": pr_url, "head_sha": head_sha, "repository": expected_repo,
               "head_ref": pr.get("headRefName"), "actor": actor.strip(), "reason": reason.strip()}
    with kb.write_txn(conn):
        kb._append_event(conn, task_id, "pr_target_bound", payload)
    return payload


def _pr_binding(conn, task_id, pr_url, head_sha):
    row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_target_bound' ORDER BY id", (task_id,)).fetchall()
    if len(row) != 1:
        raise OperatorSeamError("one immutable PR target binding is required")
    try:
        binding = json.loads(row[0]["payload"])
    except (ValueError, TypeError) as exc:
        raise OperatorSeamError("PR binding malformed") from exc
    if binding.get("pr_url") != pr_url or binding.get("head_sha") != head_sha:
        raise OperatorSeamError("PR differs from bound card target")
    return binding


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
    binding = _pr_binding(conn, task_id, pr_url, head_sha)
    if _card_repository(card) != binding["repository"]:
        raise OperatorSeamError("card repository changed after binding")
    try:
        pr = json.loads(run("gh", "pr", "view", pr_url, "--json", "url,state,headRefOid,headRefName,baseRepository"))
    except (ValueError, KeyError) as exc:
        raise OperatorSeamError("PR readback malformed") from exc
    base_repo = pr.get("baseRepository") or {}
    if (pr.get("url") != pr_url or pr.get("state") != "OPEN" or pr.get("headRefOid") != head_sha or
        base_repo.get("nameWithOwner", "").lower() != binding["repository"] or
        pr.get("headRefName") != binding["head_ref"]):
        raise OperatorSeamError("open PR, repository, branch or head mismatch")
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
    """Fail closed: card worktrees may define credential-stealing Git hooks/config."""
    raise OperatorSeamError(
        "credentialed auto-push is disabled; publish from a trusted operator checkout, "
        "then use operator-bind-pr and operator-continue-pr with exact head readback"
    )


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
