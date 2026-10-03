"""Guarded, evidence-bound closure publication boundary."""
from __future__ import annotations
import hashlib,json,tempfile
from pathlib import Path
from hermes_cli.kanban_jev_gate import JevAuthorizationError,authorize_closure
_CAPABILITY=object()
def _canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _stage(conn,task_id):
 row=conn.execute("SELECT id,payload FROM task_events WHERE task_id=? AND kind='pipeline_stage' ORDER BY id DESC LIMIT 1",(task_id,)).fetchone()
 if row is None: return None
 try: payload=json.loads(row["payload"] or "null")
 except (TypeError,json.JSONDecodeError) as exc: raise JevAuthorizationError("malformed pipeline stage evidence") from exc
 if not isinstance(payload,dict): raise JevAuthorizationError("malformed pipeline stage evidence")
 return {"event_id":int(row["id"]),"payload":payload}
def _binding(conn,task_id,evidence,document_bytes):
 stage=_stage(conn,task_id)
 if stage is None or stage["payload"].get("stage")!="closure_merge": raise JevAuthorizationError("task is not a closure_merge stage")
 feature=stage["payload"].get("feature_id")
 if not isinstance(feature,str) or not feature: raise JevAuthorizationError("closure stage lacks feature identity")
 if evidence.get("feature_id")!=feature: raise JevAuthorizationError("closure evidence feature identity mismatch")
 return {"task_id":task_id,"feature_id":feature,"stage_event_id":stage["event_id"],"stage_sha256":hashlib.sha256(_canonical(stage["payload"])).hexdigest(),"evidence_sha256":hashlib.sha256(_canonical(evidence)).hexdigest(),"document_sha256":hashlib.sha256(document_bytes).hexdigest()}
def require_completion_capability(conn,task_id,capability,report):
 stage=_stage(conn,task_id)
 if stage is None or stage["payload"].get("stage")!="closure_merge": return False
 if capability is not _CAPABILITY or not isinstance(report,dict): raise JevAuthorizationError("closure_merge tasks must use publish_closure")
 if report.get("schema_version")!="fellowship-closure-preflight.v1" or report.get("ok") is not True or report.get("mutate_board") is not False or not isinstance(report.get("hermes_binding"),dict): raise JevAuthorizationError("invalid closure authorization receipt")
 binding=report["hermes_binding"]
 if binding.get("task_id")!=task_id or binding.get("stage_event_id")!=stage["event_id"] or binding.get("stage_sha256")!=hashlib.sha256(_canonical(stage["payload"])).hexdigest(): raise JevAuthorizationError("closure authorization is not bound to this task stage")
 return True
def publish_closure(conn,task_id,*,evidence:dict,document:Path,result=None,summary=None,metadata=None,created_cards=None,expected_run_id=None,force=False):
 if not isinstance(evidence,dict): raise JevAuthorizationError("closure evidence must be an object")
 if "closure_document" in evidence and evidence["closure_document"] != Path(document).name:
  raise JevAuthorizationError("closure document name does not match evidence")
 try: document_bytes=Path(document).read_bytes()
 except OSError as exc: raise JevAuthorizationError("closure document is unreadable") from exc
 binding=_binding(conn,task_id,evidence,document_bytes)
 report=authorize_closure(conn,evidence,document_bytes)
 if report is None: raise JevAuthorizationError("closure publication requires an enabled JEV gate")
 report=dict(report);report["hermes_binding"]=binding
 merged=dict(metadata or {});merged["closure_publication"]=binding
 from hermes_cli import kanban_db as kb
 return kb.complete_task(conn,task_id,result=result,summary=summary,metadata=merged,created_cards=created_cards,expected_run_id=expected_run_id,force=force,_closure_capability=_CAPABILITY,_closure_report=report,_closure_artifacts={"evidence_json":_canonical(evidence).decode(),"document_bytes":document_bytes})
