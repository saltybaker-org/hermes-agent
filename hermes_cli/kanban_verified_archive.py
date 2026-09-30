"""Fail-closed archival of superseded review/QA gates."""
from __future__ import annotations

import json
import re
import sqlite3
import os
import hashlib
import subprocess
from typing import Any

from hermes_cli import kanban_db as kb

SCHEMA_VERSION = "kanban-verified-archive.v2"
LEGACY_SCHEMA_VERSION = "kanban-verified-archive.v1"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_PRINCIPAL = re.compile(r"^[a-z][a-z0-9._-]{0,31}:[A-Za-z0-9][A-Za-z0-9|@._-]{0,255}$")
_REJECTED = frozenset({"REJECT", "FAIL"})
_APPROVED = frozenset({"APPROVE", "PASS"})
_TABLES = {"event": "task_events", "comment": "task_comments", "attachment": "task_attachments"}

class VerifiedArchiveDenied(ValueError):
    pass

def _gate_payload(payload: Any, task_id: str) -> dict:
    payload = _object(payload, "gate verdict")
    required = {"gate_kind", "verdict", "candidate_sha", "reviewer", "author"}
    if set(payload) != required:
        raise VerifiedArchiveDenied(f"malformed gate_verdict evidence for {task_id}")
    reviewer = payload["reviewer"]
    author = payload["author"]
    if not isinstance(reviewer,str) or not isinstance(author,str) or not _PRINCIPAL.fullmatch(reviewer) or not _PRINCIPAL.fullmatch(author) or reviewer == author:
        raise VerifiedArchiveDenied("gate principal IDs must be canonical and independent")
    if payload["gate_kind"] not in {"security", "qa", "closure_review"}:
        raise VerifiedArchiveDenied("invalid gate kind evidence")
    if payload["verdict"] not in _REJECTED | _APPROVED or not isinstance(payload["candidate_sha"],str) or not _SHA.fullmatch(payload["candidate_sha"]):
        raise VerifiedArchiveDenied("malformed gate verdict authority")
    return payload

def _object(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise VerifiedArchiveDenied(f"{name} must be an object")
    return value

def _event_payload(conn: sqlite3.Connection, task_id: str, kind: str) -> tuple[int, dict] | None:
    rows = conn.execute(
        "SELECT id,payload FROM task_events WHERE task_id=? AND kind=? ORDER BY id DESC",
        (task_id, kind),
    ).fetchall()
    if not rows:
        return None
    try:
        payload = json.loads(rows[0]["payload"] or "null")
    except (TypeError, json.JSONDecodeError) as exc:
        raise VerifiedArchiveDenied(f"malformed {kind} evidence for {task_id}") from exc
    if not isinstance(payload, dict):
        raise VerifiedArchiveDenied(f"malformed {kind} evidence for {task_id}")
    return int(rows[0]["id"]), payload

def record_gate_verdict(conn: sqlite3.Connection, task_id: str, *, gate_kind: str, verdict: str,
                        candidate_sha: str, reviewer: str, author: str) -> int:
    verdict = str(verdict).upper()
    if verdict not in _REJECTED | _APPROVED:
        raise ValueError("verdict must be REJECT, FAIL, APPROVE, or PASS")
    if gate_kind not in {"security", "qa", "closure_review"}:
        raise ValueError("gate_kind must be security, qa, or closure_review")
    if not isinstance(candidate_sha,str) or not _SHA.fullmatch(candidate_sha):
        raise ValueError("candidate_sha must be 40 lowercase hex characters")
    if not isinstance(reviewer,str) or not isinstance(author,str):
        raise ValueError("gate author and reviewer principal IDs must be canonical and independent")
    if not _PRINCIPAL.fullmatch(reviewer) or not _PRINCIPAL.fullmatch(author) or reviewer == author:
        raise ValueError("gate author and reviewer principal IDs must be canonical and independent")
    with kb.write_txn(conn):
        if kb.get_task(conn, task_id) is None:
            raise ValueError("unknown gate task")
        if conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='gate_verdict'", (task_id,)).fetchone():
            raise ValueError("gate verdict evidence is immutable; create a replacement gate")
        kb._append_event(conn, task_id, "gate_verdict", {
            "gate_kind": gate_kind, "verdict": verdict, "candidate_sha": candidate_sha,
            "reviewer": reviewer, "author": author,
        })
        return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

def _digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _gh_json(endpoint: str) -> dict:
    try:
        proc = subprocess.run(["gh", "api", endpoint, "--hostname", "github.com"],
                              capture_output=True, text=True, timeout=30, check=True,
                              stdin=subprocess.DEVNULL)
        value = json.loads(proc.stdout)
        if not isinstance(value, dict): raise ValueError("response is not an object")
        return value
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise VerifiedArchiveDenied("authenticated GitHub read failed") from exc

def _authorized_login() -> str:
    allowed = {x.strip().lower() for x in os.environ.get("HERMES_KANBAN_ARCHIVE_AUTHORIZED_LOGINS", "").split(",") if x.strip()}
    if not allowed:
        raise VerifiedArchiveDenied("archive authorizer allowlist is not configured")
    login = _gh_json("user").get("login")
    if not isinstance(login, str) or login.lower() not in allowed:
        raise VerifiedArchiveDenied("authenticated GitHub caller is not an authorized archiver")
    return login.lower()

def collect_human_merge(pr_url: str, candidate_sha: str) -> dict:
    """Collect GitHub's merged_by identity; never accept a caller-supplied claim."""
    prefix = "https:" + "//github.com/"
    match = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)", pr_url[len(prefix):]) if isinstance(pr_url, str) and pr_url.startswith(prefix) else None
    if not match or not isinstance(candidate_sha, str) or not _SHA.fullmatch(candidate_sha):
        raise VerifiedArchiveDenied("exact GitHub PR URL and candidate SHA required")
    expected = os.environ.get("HERMES_KANBAN_HUMAN_MERGE_LOGIN", "").strip().lower()
    if not expected:
        raise VerifiedArchiveDenied("human merge login is not configured")
    pr = _gh_json(f"repos/{match[1]}/pulls/{match[2]}")
    merged_by = pr.get("merged_by")
    merged_login = merged_by.get("login") if isinstance(merged_by, dict) else None
    commit = pr.get("merge_commit_sha")
    head = pr.get("head")
    if (pr.get("html_url") != pr_url or pr.get("merged") is not True or
        not pr.get("merged_at") or not isinstance(head, dict) or head.get("sha") != candidate_sha or
        not isinstance(commit, str) or not _SHA.fullmatch(commit) or
        not isinstance(merged_login, str) or merged_login.lower() != expected):
        raise VerifiedArchiveDenied("PR is not merged by the configured human at the exact candidate head")
    return {"schema_version": "kanban-human-merge.v1", "pr_url": pr_url,
            "candidate_sha": candidate_sha, "merge_sha": commit,
            "merged_by": merged_login.lower(), "merged_at": pr["merged_at"]}

def record_merge_evidence(conn: sqlite3.Connection, task_id: str, *,
                          candidate_sha: str, pr_url: str) -> int:
    receipt = collect_human_merge(pr_url, candidate_sha)
    with kb.write_txn(conn):
        if kb.get_task(conn, task_id) is None:
            raise VerifiedArchiveDenied("unknown merge task")
        if conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind IN ('merge_verified','human_merge_verified')", (task_id,)).fetchone():
            raise VerifiedArchiveDenied("merge evidence is immutable")
        kb._append_event(conn, task_id, "human_merge_verified", receipt)
        return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

def _task(conn: sqlite3.Connection, task_id: Any, role: str):
    if not isinstance(task_id, str) or not task_id:
        raise VerifiedArchiveDenied(f"{role} task id is required")
    task = kb.get_task(conn, task_id)
    if task is None:
        raise VerifiedArchiveDenied(f"unknown {role} task: {task_id}")
    return task

def _verify_ref(conn: sqlite3.Connection, ref: Any) -> tuple[str, int, str]:
    ref = _object(ref, "evidence reference")
    if set(ref)!={"table","id","task_id"}: raise VerifiedArchiveDenied("evidence reference schema is closed")
    kind, row_id, task_id = ref.get("table"), ref.get("id"), ref.get("task_id")
    if kind not in _TABLES or isinstance(row_id, bool) or not isinstance(row_id, int) or row_id <= 0:
        raise VerifiedArchiveDenied("invalid evidence reference")
    row = conn.execute(f"SELECT task_id FROM {_TABLES[kind]} WHERE id=?", (row_id,)).fetchone()
    if row is None or row["task_id"] != task_id:
        raise VerifiedArchiveDenied("evidence reference is missing or bound to another task")
    return kind, row_id, task_id

def _retention_receipt_task_ids(owner_id:str,payload:Any)->set[str]:
    payload=_object(payload,"verified archive receipt")
    fields={"schema_version","replacement_task_id","gate_kind","candidate_sha","merge_task_id","merge_sha","replacement_verdict","required_child_ids","required_edges","evidence_refs"}
    version=payload.get("schema_version")
    if version==SCHEMA_VERSION:
        fields |= {"authorization","merge_pr_url","merge_receipt_sha256"}
    if version not in {SCHEMA_VERSION, LEGACY_SCHEMA_VERSION} or set(payload)!=fields:
        raise VerifiedArchiveDenied("verified archive receipt schema is invalid")
    replacement=payload.get("replacement_task_id");merge=payload.get("merge_task_id")
    if not isinstance(replacement,str) or not replacement or not isinstance(merge,str) or not merge: raise VerifiedArchiveDenied("verified archive receipt task identities are invalid")
    if payload.get("gate_kind") not in {"security","qa","closure_review"} or payload.get("replacement_verdict") not in _APPROVED: raise VerifiedArchiveDenied("verified archive receipt authority is invalid")
    if not isinstance(payload.get("candidate_sha"),str) or not _SHA.fullmatch(payload["candidate_sha"]) or not isinstance(payload.get("merge_sha"),str) or not _SHA.fullmatch(payload["merge_sha"]): raise VerifiedArchiveDenied("verified archive receipt SHAs are invalid")
    children=payload.get("required_child_ids")
    if not isinstance(children,list) or not children or any(not isinstance(item,str) or not item for item in children) or len(children)!=len(set(children)) or not {owner_id,replacement,merge}.issubset(children): raise VerifiedArchiveDenied("verified archive receipt children are invalid")
    edges=payload.get("required_edges")
    if not isinstance(edges,list) or not edges: raise VerifiedArchiveDenied("verified archive receipt edges are invalid")
    for edge in edges:
        if not isinstance(edge,dict) or set(edge)!={"parent_id","child_id"} or any(not isinstance(edge[key],str) or not edge[key] for key in edge): raise VerifiedArchiveDenied("verified archive receipt edge schema is invalid")
    refs=payload.get("evidence_refs")
    if not isinstance(refs,list) or not refs: raise VerifiedArchiveDenied("verified archive receipt references are invalid")
    ref_tasks=set()
    for ref in refs:
        if not isinstance(ref,dict) or set(ref)!={"table","id","task_id"} or ref.get("table") not in _TABLES or isinstance(ref.get("id"),bool) or not isinstance(ref.get("id"),int) or ref["id"]<=0 or not isinstance(ref.get("task_id"),str) or not ref["task_id"]: raise VerifiedArchiveDenied("verified archive receipt reference schema is invalid")
        ref_tasks.add(ref["task_id"])
    authorization=payload.get("authorization")
    if version==SCHEMA_VERSION and (not isinstance(authorization,dict) or set(authorization)!={"actor_login","scope"} or authorization["scope"]!="archive-superseded-gate" or not isinstance(authorization["actor_login"],str) or not authorization["actor_login"]):
        raise VerifiedArchiveDenied("verified archive authorization receipt is invalid")
    if version==SCHEMA_VERSION and (not isinstance(payload.get("merge_pr_url"),str) or not isinstance(payload.get("merge_receipt_sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",payload["merge_receipt_sha256"])):
        raise VerifiedArchiveDenied("verified archive merge receipt digest is invalid")
    return {owner_id,replacement,merge,*children,*ref_tasks}

def hard_delete_is_protected(conn:sqlite3.Connection,task_id:str)->bool:
    # A rejected gate may only leave the board through verified archival, whose
    # receipt then permanently protects it. Malformed or duplicate authority
    # evidence cannot safely establish that ordinary destructive deletion is allowed.
    gate_rows=conn.execute(
        "SELECT payload FROM task_events WHERE task_id=? AND kind='gate_verdict' ORDER BY id",
        (task_id,),
    ).fetchall()
    if gate_rows:
        if len(gate_rows)!=1:
            return True
        try:
            gate=_gate_payload(json.loads(gate_rows[0]["payload"] or "null"),task_id)
        except Exception:
            return True
        if gate["verdict"] in _REJECTED:
            return True
        status=conn.execute("SELECT status FROM tasks WHERE id=?",(task_id,)).fetchone()
        if status is not None and status["status"]!="archived":
            return True
    rows=conn.execute("SELECT task_id,payload FROM task_events WHERE kind='verified_superseded_archive'").fetchall()
    for row in rows:
        try:
            payload=json.loads(row["payload"] or "null")
            protected=_retention_receipt_task_ids(row["task_id"],payload)
        except Exception:
            # Once a receipt exists, malformed identity data makes every hard deletion unsafe.
            return True
        if task_id in protected: return True
    return False


def assert_ordinary_archive_allowed(conn: sqlite3.Connection, task_id: str) -> None:
    """Any structured gate must have one complete approving authority event."""
    rows = conn.execute(
        "SELECT payload FROM task_events WHERE task_id=? AND kind='gate_verdict' ORDER BY id",
        (task_id,),
    ).fetchall()
    if not rows:
        return
    if len(rows) != 1:
        raise VerifiedArchiveDenied("structured gate requires exactly one authority verdict")
    try:
        payload = json.loads(rows[0]["payload"] or "null")
        payload = _gate_payload(payload, task_id)
    except (TypeError, json.JSONDecodeError) as exc:
        raise VerifiedArchiveDenied("structured gate evidence is malformed") from exc
    if payload["verdict"] not in _APPROVED:
        raise VerifiedArchiveDenied("rejected structured gate requires verified archive evidence")

def _successful_terminal(conn:sqlite3.Connection,task)->bool:
    if task.status=="done": return True
    if task.status!="archived": return False
    successful=False;archived=False
    for row in conn.execute("SELECT kind,payload FROM task_events WHERE task_id=? ORDER BY id",(task.id,)).fetchall():
        kind=row["kind"]
        if kind=="completed": successful=True
        elif kind in {"reopened","descendant_invalidated"}: successful=False
        elif kind=="status":
            try: payload=json.loads(row["payload"] or "null")
            except (TypeError,json.JSONDecodeError): return False
            status=payload.get("status") if isinstance(payload,dict) else None
            if status=="done": successful=True
            elif status not in {None,"archived"}: successful=False
        elif kind in {"archived","verified_superseded_archive"}: archived=True
    return successful and archived

def verified_archive_superseded_gate(conn: sqlite3.Connection, manifest: dict) -> dict:
    """Verify all identities and evidence, then archive exactly one rejected gate."""
    manifest = _object(manifest, "manifest")
    fields={"schema_version","gate_kind","rejected_task_id","replacement_task_id","replacement_verdict","candidate_sha","merge_task_id","merge_sha","required_child_ids","required_edges","evidence_refs","authorization","merge_pr_url","merge_receipt_sha256"}
    if set(manifest)!=fields: raise VerifiedArchiveDenied("manifest schema is closed")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise VerifiedArchiveDenied("unsupported manifest schema")
    candidate = manifest.get("candidate_sha")
    merge_sha = manifest.get("merge_sha")
    if not isinstance(candidate,str) or not isinstance(merge_sha,str) or not _SHA.fullmatch(candidate) or not _SHA.fullmatch(merge_sha):
        raise VerifiedArchiveDenied("candidate_sha and merge_sha must be 40 lowercase hex")
    gate_kind = manifest.get("gate_kind")
    if gate_kind not in {"security", "qa", "closure_review"}:
        raise VerifiedArchiveDenied("invalid gate_kind")
    replacement_expected = str(manifest.get("replacement_verdict", "")).upper()
    if replacement_expected not in _APPROVED:
        raise VerifiedArchiveDenied("replacement_verdict must be APPROVE or PASS")
    child_ids = manifest.get("required_child_ids")
    if not isinstance(child_ids, list) or not child_ids or any(not isinstance(x, str) or not x for x in child_ids):
        raise VerifiedArchiveDenied("required_child_ids must be a non-empty string array")
    if len(child_ids) != len(set(child_ids)):
        raise VerifiedArchiveDenied("duplicate required child id")
    edge_items=manifest.get("required_edges")
    if not isinstance(edge_items,list) or not edge_items: raise VerifiedArchiveDenied("required_edges must be non-empty")
    required_edges=set()
    for edge in edge_items:
        if not isinstance(edge,dict) or set(edge)!={"parent_id","child_id"} or not all(isinstance(edge[k],str) and edge[k] for k in edge): raise VerifiedArchiveDenied("required edge schema is closed")
        required_edges.add((edge["parent_id"],edge["child_id"]))
    if len(required_edges)!=len(edge_items): raise VerifiedArchiveDenied("duplicate required edge")
    refs = manifest.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        raise VerifiedArchiveDenied("evidence_refs must be non-empty")
    authorization = _object(manifest.get("authorization"), "archive authorization")
    if set(authorization) != {"actor_login", "scope"} or authorization.get("scope") != "archive-superseded-gate" or authorization.get("actor_login") != _authorized_login():
        raise VerifiedArchiveDenied("archive authorization does not match authenticated caller")
    with kb.write_txn(conn):
        rejected = _task(conn, manifest.get("rejected_task_id"), "rejected")
        replacement = _task(conn, manifest.get("replacement_task_id"), "replacement")
        merge_task = _task(conn, manifest.get("merge_task_id"), "merge")
        if len({rejected.id, replacement.id, merge_task.id}) != 3:
            raise VerifiedArchiveDenied("gate and merge task identities must be distinct")
        if rejected.status != "blocked":
            raise VerifiedArchiveDenied("rejected gate must remain blocked")
        if replacement.status != "done":
            raise VerifiedArchiveDenied("replacement gate must be done")
        if not _successful_terminal(conn,merge_task):
            raise VerifiedArchiveDenied("merge task must be terminal and successful")
        old = _event_payload(conn, rejected.id, "gate_verdict")
        new = _event_payload(conn, replacement.id, "gate_verdict")
        merged = _event_payload(conn, merge_task.id, "human_merge_verified")
        evidence_counts = {
            "rejected": conn.execute("SELECT COUNT(*) FROM task_events WHERE task_id=? AND kind='gate_verdict'", (rejected.id,)).fetchone()[0],
            "replacement": conn.execute("SELECT COUNT(*) FROM task_events WHERE task_id=? AND kind='gate_verdict'", (replacement.id,)).fetchone()[0],
            "merge": conn.execute("SELECT COUNT(*) FROM task_events WHERE task_id=? AND kind='human_merge_verified'", (merge_task.id,)).fetchone()[0],
        }
        if conn.execute("SELECT 1 FROM task_events WHERE task_id=? AND kind='merge_verified'", (merge_task.id,)).fetchone():
            raise VerifiedArchiveDenied("legacy unauthenticated merge claim is not authority")
        if any(count != 1 for count in evidence_counts.values()):
            raise VerifiedArchiveDenied("duplicate or missing structured authority evidence")
        if old is None or new is None:
            raise VerifiedArchiveDenied("gate authority evidence is missing")
        old_payload = _gate_payload(old[1], rejected.id)
        new_payload = _gate_payload(new[1], replacement.id)
        if old_payload["verdict"] not in _REJECTED:
            raise VerifiedArchiveDenied("rejected gate lacks a structured rejecting verdict")
        if new_payload["verdict"] != replacement_expected:
            raise VerifiedArchiveDenied("replacement gate lacks the expected structured verdict")
        if old_payload.get("gate_kind") != gate_kind or new_payload.get("gate_kind") != gate_kind:
            raise VerifiedArchiveDenied("replacement gate kind mismatch")
        if old_payload.get("candidate_sha") != candidate or new_payload.get("candidate_sha") != candidate:
            raise VerifiedArchiveDenied("gate candidate SHA mismatch")
        if merged is None or merged[1] != collect_human_merge(manifest["merge_pr_url"], candidate) or merged[1]["merge_sha"] != merge_sha or _digest(merged[1]) != manifest["merge_receipt_sha256"]:
            raise VerifiedArchiveDenied("merge evidence does not bind the authenticated human merge")
        graph_rows = conn.execute(
            "WITH RECURSIVE ancestors(id) AS ("
            "SELECT parent_id FROM task_links WHERE child_id=? UNION "
            "SELECT l.parent_id FROM task_links l JOIN ancestors a ON l.child_id=a.id) "
            "SELECT id FROM ancestors", (merge_task.id,),
        ).fetchall()
        authoritative_ids = {row["id"] for row in graph_rows} | {merge_task.id}
        if set(child_ids) != authoritative_ids:
            raise VerifiedArchiveDenied("required children do not match the dependency graph")
        placeholders=",".join("?" for _ in child_ids)
        actual_edges={(row["parent_id"],row["child_id"]) for row in conn.execute(f"SELECT parent_id,child_id FROM task_links WHERE parent_id IN ({placeholders}) AND child_id IN ({placeholders})",(*child_ids,*child_ids)).fetchall()}
        if required_edges!=actual_edges: raise VerifiedArchiveDenied("required edges do not match the dependency graph")
        if (rejected.id,merge_task.id) not in actual_edges or (replacement.id,merge_task.id) not in actual_edges:
            raise VerifiedArchiveDenied("both gate roles must directly authorize the merge task")
        required = [_task(conn, task_id, "required child") for task_id in child_ids]
        if any(task.id != rejected.id and not _successful_terminal(conn,task) for task in required):
            raise VerifiedArchiveDenied("every required child except the rejected gate must be successful and terminal")
        if not {rejected.id, replacement.id, merge_task.id}.issubset(set(child_ids)):
            raise VerifiedArchiveDenied("required children must include both gates and merge evidence task")
        verified_refs = [_verify_ref(conn, ref) for ref in refs]
        if len(verified_refs) != len(set(verified_refs)):
            raise VerifiedArchiveDenied("duplicate evidence reference")
        authority_refs = {("event", old[0], rejected.id), ("event", new[0], replacement.id),
                          ("event", merged[0], merge_task.id)}
        if set(verified_refs)!=authority_refs:
            raise VerifiedArchiveDenied("evidence references must equal the exact structured authority rows")
        before = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in _TABLES.values()}
        cur = conn.execute(
            "UPDATE tasks SET status='archived', claim_lock=NULL, claim_expires=NULL, "
            "worker_pid=NULL, worker_started_at=NULL WHERE id=? AND status='blocked'",
            (rejected.id,),
        )
        if cur.rowcount != 1:
            raise VerifiedArchiveDenied("rejected gate changed during verification")
        kb._append_event(conn, rejected.id, "verified_superseded_archive", {
            "schema_version": SCHEMA_VERSION,
            "replacement_task_id": replacement.id, "gate_kind": gate_kind,
            "candidate_sha": candidate, "merge_task_id": merge_task.id,
            "merge_sha": merge_sha, "replacement_verdict": replacement_expected,
            "required_child_ids": sorted(child_ids),
            "required_edges": [{"parent_id":p,"child_id":c} for p,c in sorted(required_edges)],
            "evidence_refs": [dict(ref) for ref in refs],
            "authorization": authorization, "merge_pr_url": manifest["merge_pr_url"],
            "merge_receipt_sha256": manifest["merge_receipt_sha256"],
        })
        after = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                 for table in _TABLES.values()}
        # One archive event is added; nothing evidentiary may disappear.
        if after["task_comments"] != before["task_comments"] or after["task_attachments"] != before["task_attachments"] or after["task_events"] != before["task_events"] + 1:
            raise VerifiedArchiveDenied("evidence retention invariant failed")
    return {"archived_task_id": rejected.id, "replacement_task_id": replacement.id,
            "candidate_sha": candidate, "merge_sha": merge_sha,
            "merge_receipt_sha256": manifest["merge_receipt_sha256"],
            "archive_manifest_sha256": _digest(manifest),
            "authorized_actor": authorization["actor_login"],
            "schema_version": SCHEMA_VERSION}



def build_archive_manifest(conn: sqlite3.Connection, rejected_id: str, replacement_id: str,
                           merge_id: str) -> dict:
    """Enumerate the complete current merge ancestry and exact authority rows.

    This is a proposal, not a waiver: verified_archive_superseded_gate rechecks
    each assertion under a write transaction and refuses graph drift.
    """
    rejected = _task(conn, rejected_id, "rejected")
    replacement = _task(conn, replacement_id, "replacement")
    merge = _task(conn, merge_id, "merge")
    if len({rejected.id, replacement.id, merge.id}) != 3:
        raise VerifiedArchiveDenied("archive roles must be distinct")
    old = _event_payload(conn, rejected.id, "gate_verdict")
    new = _event_payload(conn, replacement.id, "gate_verdict")
    merged = _event_payload(conn, merge.id, "human_merge_verified")
    if old is None or new is None or merged is None:
        raise VerifiedArchiveDenied("structured gate and authenticated merge evidence required")
    old_payload = _gate_payload(old[1], rejected.id)
    new_payload = _gate_payload(new[1], replacement.id)
    receipt = merged[1]
    if set(receipt) != {"schema_version", "pr_url", "candidate_sha", "merge_sha", "merged_by", "merged_at"} or receipt.get("schema_version") != "kanban-human-merge.v1":
        raise VerifiedArchiveDenied("malformed human merge receipt")
    rows = conn.execute("WITH RECURSIVE ancestors(id) AS (SELECT parent_id FROM task_links WHERE child_id=? "
                        "UNION SELECT l.parent_id FROM task_links l JOIN ancestors a ON l.child_id=a.id) "
                        "SELECT id FROM ancestors", (merge.id,)).fetchall()
    ids = sorted({row["id"] for row in rows} | {merge.id})
    placeholders = ",".join("?" for _ in ids)
    edges = conn.execute(f"SELECT parent_id,child_id FROM task_links WHERE parent_id IN ({placeholders}) "
                         f"AND child_id IN ({placeholders}) ORDER BY parent_id,child_id", (*ids,*ids)).fetchall()
    manifest = {"schema_version": SCHEMA_VERSION, "gate_kind": old_payload["gate_kind"],
        "rejected_task_id": rejected.id, "replacement_task_id": replacement.id,
        "replacement_verdict": new_payload["verdict"], "candidate_sha": old_payload["candidate_sha"],
        "merge_task_id": merge.id, "merge_sha": receipt["merge_sha"],
        "merge_pr_url": receipt["pr_url"], "merge_receipt_sha256": _digest(receipt),
        "required_child_ids": ids,
        "required_edges": [{"parent_id": row["parent_id"], "child_id": row["child_id"]} for row in edges],
        "evidence_refs": [{"table": "event", "id": event[0], "task_id": task_id}
                          for event,task_id in ((old,rejected.id),(new,replacement.id),(merged,merge.id))],
        "authorization": {"actor_login": _authorized_login(), "scope": "archive-superseded-gate"}}
    return manifest

def load_manifest(path) -> dict:
    """Load JSON while rejecting duplicate object keys."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerifiedArchiveDenied(f"duplicate manifest key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerifiedArchiveDenied(f"unreadable archive manifest: {exc}") from exc
