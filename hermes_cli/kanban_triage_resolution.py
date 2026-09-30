"""Operator-only, auditable resolution of a triaged verdict."""
from __future__ import annotations
import time
from hermes_cli import kanban_db as kb

class TriageResolutionDenied(ValueError):
    pass

def resolve_triage(conn, task_id: str, *, verdict: str, reason: str, actor: str) -> dict:
    """Resolve only an already-triaged card with a documented terminal verdict.

    This never turns a rejecting gate into a successful dependency: that gate
    remains blocked until a replacement has passed independently.
    """
    if not isinstance(verdict, str) or not verdict.strip() or not isinstance(reason, str) or not reason.strip():
        raise TriageResolutionDenied("a non-empty verdict and operator reason are required")
    if not isinstance(actor, str) or not actor.strip():
        raise TriageResolutionDenied("an operator identity is required")
    label, marker, detail = verdict.strip().partition(":")
    if label.upper() not in {"PASS", "APPROVE", "DONE", "COMPLETE", "RESOLVED"} or (marker and not detail.strip()):
        raise TriageResolutionDenied("only an explicit successful verdict can satisfy dependencies")
    with kb.write_txn(conn):
        task = kb.get_task(conn, task_id)
        if task is None or task.status != "triage" or task.current_run_id is not None:
            raise TriageResolutionDenied("task must be triage with no live run")
        from hermes_cli.kanban_verified_archive import _event_payload, _gate_payload, VerifiedArchiveDenied
        gate = _event_payload(conn, task_id, "gate_verdict")
        if gate is not None:
            try:
                payload = _gate_payload(gate[1], task_id)
            except VerifiedArchiveDenied as exc:
                raise TriageResolutionDenied(str(exc)) from exc
            if payload["verdict"] in {"FAIL", "REJECT"}:
                raise TriageResolutionDenied("rejected gate cannot resolve as done")
        row = conn.execute("SELECT completion_contract FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row["completion_contract"] not in (None, "local-only"):
            raise TriageResolutionDenied("PR contract requires the normal acceptance collector")
        from hermes_cli.kanban_closure_mutation import _stage
        stage = (_stage(conn, task_id) or {}).get("payload", {}).get("stage")
        if isinstance(stage, str) and "merge" in stage:
            raise TriageResolutionDenied("merge stage requires its human/closure authorization boundary")
        if isinstance(stage, str) and ("review" in stage or "qa" in stage):
            if gate is None or _gate_payload(gate[1], task_id)["verdict"] not in {"APPROVE", "PASS"}:
                raise TriageResolutionDenied("review/QA stage requires a structured approving gate verdict")
        if not kb._parents_satisfied(conn, task_id):
            raise TriageResolutionDenied("task has unsatisfied parents")
        now = int(time.time())
        result = verdict.strip()
        changed = conn.execute("UPDATE tasks SET status='done', completed_at=?, result=?, "
            "block_kind=NULL, block_recurrences=0, consecutive_failures=0, "
            "claim_lock=NULL, claim_expires=NULL, worker_pid=NULL, worker_started_at=NULL "
            "WHERE id=? AND status='triage' AND current_run_id IS NULL", (now, result, task_id))
        if changed.rowcount != 1:
            raise TriageResolutionDenied("task changed during resolution")
        kb._synthesize_ended_run(conn, task_id, outcome="completed", summary=result, metadata={"triage_reason": reason.strip()})
        kb._insert_comment(conn, task_id, actor.strip(), f"TRIAGE RESOLVED: {reason.strip()}", now)
        kb._append_event(conn, task_id, "triage_resolved", {"actor": actor.strip(), "reason": reason.strip(), "verdict": result})
        kb._append_event(conn, task_id, "completed", {"summary": result, "triage_resolution": True})
    return {"task_id": task_id, "status": "done", "verdict": result}
