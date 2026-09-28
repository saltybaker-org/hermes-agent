"""Atomic pipeline construction guarded by deterministic JEV preflight."""
from __future__ import annotations
from typing import Any
import json
from pathlib import Path
from hermes_cli import kanban_db as kb
from hermes_cli.kanban_jev_gate import authorize_pipeline

class PipelineConstructionError(ValueError): pass
_PIPELINE_CAPABILITY=object()
def require_pipeline_capability(value):
    if value is not _PIPELINE_CAPABILITY: raise PipelineConstructionError("invalid pipeline authorization capability")

def _canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _existing_pipeline(conn,feature_id,manifest_sha):
    row=conn.execute("SELECT manifest_sha256,mapping_json FROM jev_pipeline_publications WHERE feature_id=?",(feature_id,)).fetchone()
    if row is None: return None
    if row["manifest_sha256"]!=manifest_sha: raise PipelineConstructionError("pipeline feature_id was already used with a different manifest")
    try: mapping=json.loads(row["mapping_json"])
    except (TypeError,json.JSONDecodeError) as exc: raise PipelineConstructionError("stored pipeline mapping is malformed") from exc
    if not isinstance(mapping,dict) or not mapping or any(not isinstance(k,str) or not isinstance(v,str) or kb.get_task(conn,v) is None for k,v in mapping.items()): raise PipelineConstructionError("stored pipeline mapping is incomplete")
    return mapping

def create_pipeline(conn, manifest: dict, cards: list[dict[str, Any]]) -> dict[str,str]:
    if not isinstance(manifest,dict) or not isinstance(cards,list) or not cards: raise PipelineConstructionError("manifest object and non-empty cards array required")
    if set(manifest)!={"schema_version","feature_id","cards"} or manifest.get("schema_version")!="fellowship-pipeline.v1" or not isinstance(manifest.get("feature_id"),str) or not manifest["feature_id"]: raise PipelineConstructionError("exact pipeline schema and feature_id required")
    manifest_cards=manifest.get("cards")
    if not isinstance(manifest_cards,list) or manifest_cards!=cards: raise PipelineConstructionError("manifest cards must exactly match construction cards")
    specs={}
    for card in cards:
        if not isinstance(card,dict) or not isinstance(card.get("key"),str) or not card["key"] or card["key"] in specs: raise PipelineConstructionError("every card requires a unique key")
        parents=card.get("parents",[])
        if not isinstance(parents,list) or any(not isinstance(x,str) for x in parents): raise PipelineConstructionError("card parents must be key arrays")
        if card.get("idempotency_key") is not None: raise PipelineConstructionError("pipeline cards cannot use idempotency_key")
        specs[card["key"]]=card
    if any(parent not in specs for card in cards for parent in card.get("parents",[])): raise PipelineConstructionError("unknown pipeline parent")
    manifest_sha=__import__("hashlib").sha256(_canonical(manifest)).hexdigest();feature_id=manifest["feature_id"]
    existing=_existing_pipeline(conn,feature_id,manifest_sha)
    if existing is not None: return existing
    report=authorize_pipeline(conn,manifest)
    if report is None: raise PipelineConstructionError("pipeline construction requires an enabled JEV gate")
    from hermes_cli.kanban_jev_gate import authorize_card
    import time
    task_ids={key:kb._new_task_id() for key in specs};created_at=int(time.time());planned={};tenants={};pending=dict(specs)
    while pending:
        ready=sorted(key for key,card in pending.items() if all(parent in planned for parent in card.get("parents",[])))
        if not ready: raise PipelineConstructionError("pipeline dependency cycle")
        for key in ready:
            card=pending.pop(key);parent_keys=card.get("parents",[]);parent_ids=[task_ids[parent] for parent in parent_keys]
            kwargs={name:value for name,value in card.items() if name not in {"key","parents","stage"}}
            explicit=kwargs.get("tenant")
            inherited={tenants[parent] for parent in parent_keys}
            if explicit is None and len(inherited)>1: raise PipelineConstructionError("pipeline parents have incompatible tenants")
            tenant=explicit if explicit is not None else (next(iter(inherited)) if inherited else None);tenants[key]=tenant
            status="blocked" if kwargs.get("initial_status")=="blocked" else ("triage" if kwargs.get("triage") else ("todo" if parent_keys else "ready"))
            payload=kb.create_task(conn,parents=parent_ids,_task_id=task_ids[key],_created_at=created_at,_preview_only=True,_planned_status=status,_planned_tenant=tenant,**kwargs)
            if authorize_card(conn,payload) is None: raise PipelineConstructionError("pipeline cards require an enabled JEV gate")
            planned[key]=(kwargs,parent_ids,payload)
    created={}
    with kb.write_txn(conn):
        existing=_existing_pipeline(conn,feature_id,manifest_sha)
        if existing is not None: return existing
        pending=dict(specs)
        while pending:
            ready=sorted(key for key,card in pending.items() if all(parent in created for parent in card.get("parents",[])))
            if not ready: raise PipelineConstructionError("pipeline dependency cycle")
            for key in ready:
                card=pending.pop(key);kwargs,parent_ids,payload=planned[key]
                created[key]=kb.create_task(conn,parents=parent_ids,_task_id=task_ids[key],_created_at=created_at,_pipeline_capability=_PIPELINE_CAPABILITY,_preauthorized_payload=payload,**kwargs)
                if card.get("stage"): kb._append_event(conn,created[key],"pipeline_stage",{"stage":card["stage"],"key":key,"feature_id":feature_id})
        conn.execute("INSERT INTO jev_pipeline_publications(feature_id,manifest_sha256,mapping_json,created_at) VALUES (?,?,?,?)",(feature_id,manifest_sha,json.dumps(created,sort_keys=True,separators=(",",":")),created_at))
    return created


def load_json_object(path: Path):
    def pairs(items):
        out={}
        for key,value in items:
            if key in out: raise PipelineConstructionError(f"duplicate JSON key: {key}")
            out[key]=value
        return out
    try: value=json.loads(Path(path).read_text(encoding="utf-8"),object_pairs_hook=pairs)
    except (OSError,UnicodeError,json.JSONDecodeError) as exc: raise PipelineConstructionError(f"unreadable pipeline input: {exc}") from exc
    if not isinstance(value,(dict,list)): raise PipelineConstructionError("pipeline input must be an object or array")
    return value
