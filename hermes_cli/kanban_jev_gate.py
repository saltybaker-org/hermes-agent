"""Local deterministic JEV authorization adapter for Kanban mutations."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any

class JevAuthorizationError(PermissionError):
    pass

def _strict_json(text: str) -> dict:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise JevAuthorizationError(f"duplicate JEV response key: {key}")
            out[key] = value
        return out
    try:
        value = json.loads(text, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise JevAuthorizationError("JEV returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise JevAuthorizationError("JEV response must be an object")
    return value

def _config(conn: sqlite3.Connection) -> dict | None:
    rows=conn.execute("PRAGMA database_list").fetchall();main=next((row for row in rows if row[1]=="main"),None)
    if main is None or not main[2]: return None
    path=Path(main[2]).resolve().parent/"board.json"
    try: raw=json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError: return None
    except (OSError,UnicodeError,json.JSONDecodeError) as exc: raise JevAuthorizationError("enabled board JEV metadata is unreadable") from exc
    if not isinstance(raw,dict) or "jev_mutation_gate" not in raw: return None
    cfg=raw.get("jev_mutation_gate")
    if not isinstance(cfg,dict): raise JevAuthorizationError("configured JEV gate is malformed")
    if cfg.get("enabled") is not True: raise JevAuthorizationError("configured JEV gate is disabled")
    if "command" in cfg: raise JevAuthorizationError("board-controlled JEV commands are forbidden")
    timeout=cfg.get("timeout_seconds",10)
    if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not 0<timeout<=30: raise JevAuthorizationError("JEV timeout must be in (0, 30] seconds")
    return {"timeout":float(timeout)}

def _trusted_command()->list[str]:
    path=Path("/usr/local/bin/fellowship-jev")
    try: stat=path.stat()
    except OSError as exc: raise JevAuthorizationError("trusted JEV executable is unavailable") from exc
    if stat.st_uid!=0 or stat.st_mode & 0o022: raise JevAuthorizationError("trusted JEV executable ownership is unsafe")
    return [str(path)]

def _sandbox_argv(command:list[str],args:list[str],directory:Path)->list[str]:
    # A PATH-selected executable is attacker-controlled, not a sandbox boundary.
    bwrap=Path("/usr/bin/bwrap")
    try: binary_stat=bwrap.stat()
    except OSError as exc: raise JevAuthorizationError("JEV sandbox is unavailable") from exc
    if binary_stat.st_uid!=0 or binary_stat.st_mode & 0o022 or not bwrap.is_file():
        raise JevAuthorizationError("JEV sandbox executable ownership is unsafe")
    argv=[str(bwrap),"--die-with-parent","--new-session","--unshare-net","--unshare-pid","--clearenv",
          "--ro-bind","/usr","/usr","--ro-bind","/bin","/bin","--ro-bind","/lib","/lib"]
    if Path("/lib64").exists(): argv += ["--ro-bind","/lib64","/lib64"]
    # no-tmp: ok — bubblewrap gives the isolated evaluator a private tmpfs, not host scratch.
    argv += ["--dev","/dev","--proc","/proc","--tmpfs","/tmp","--bind",str(directory),"/work",
             "--chdir","/work","--setenv","HOME","/work","--setenv","PATH","/usr/local/bin:/usr/bin:/bin",
             "--setenv","LANG","C.UTF-8","--"]
    return argv+command+args


def _private_json(directory: Path, name: str, value: dict) -> Path:
    path = directory / name
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(data, encoding="utf-8")
    os.chmod(path, 0o600)
    return path

def _execute(cfg:dict,args:list[str],files:dict[str,dict|bytes])->dict:
    with tempfile.TemporaryDirectory(prefix="hermes-jev-") as raw:
        directory=Path(raw);os.chmod(directory,0o700);resolved={}
        for name,value in files.items():
            path=directory/name
            if isinstance(value,bytes): path.write_bytes(value);os.chmod(path,0o600)
            else: _private_json(directory,name,value)
            resolved[name]=Path("/work")/name
        mapped=[str(resolved[item[1:]]) if item.startswith("@") else item for item in args]
        argv=_sandbox_argv(_trusted_command(),mapped,directory)
        try:
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding="utf-8",errors="replace",
                                  timeout=cfg["timeout"],check=False,env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"},cwd="/")
        except (OSError,subprocess.TimeoutExpired) as exc: raise JevAuthorizationError(f"JEV authorization unavailable: {type(exc).__name__}") from exc
        report=_strict_json(result.stdout)
        if result.returncode!=0: raise JevAuthorizationError("JEV denied mutation")
        return report

def _run(conn:sqlite3.Connection,args:list[str],files:dict[str,dict|bytes])->dict|None:
    cfg=_config(conn)
    return None if cfg is None else _execute(cfg,args,files)

def authorize_card(conn: sqlite3.Connection, card: dict) -> dict | None:
    report = _run(conn, ["decide-policy", "@card.json"], {"card.json": card})
    if report is None:
        return None
    if report.get("schema_version") != "fellowship-authoritative-policy.v2" or report.get("authoritative") is not True or report.get("dispatch_allowed") is not True or report.get("mutate_board") is not False:
        raise JevAuthorizationError("JEV card authorization was not an explicit non-mutating allow")
    return report

def authorize_pipeline(conn: sqlite3.Connection, manifest: dict) -> dict | None:
    report = _run(conn, ["validate-pipeline", "@pipeline.json"], {"pipeline.json": manifest})
    if report is None:
        return None
    if report.get("schema_version") != "fellowship-pipeline-preflight.v1" or report.get("ok") is not True or report.get("mutate_board") is not False:
        raise JevAuthorizationError("JEV pipeline authorization was not an explicit non-mutating allow")
    return report

def authorize_closure(conn:sqlite3.Connection,evidence:dict,document_bytes:bytes)->dict|None:
    cfg=_config(conn)
    if cfg is None: return None
    if not isinstance(document_bytes,(bytes,bytearray)): raise JevAuthorizationError("closure document bytes are required")
    name = evidence.get("closure_document")
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
          or name == "evidence.json"):
        raise JevAuthorizationError("unsafe closure document name")
    report=_execute(cfg,["validate-closure","@evidence.json","--document",f"@{name}"],{"evidence.json":evidence,name:bytes(document_bytes)})
    if report.get("schema_version")!="fellowship-closure-preflight.v1" or report.get("ok") is not True or report.get("mutate_board") is not False:
        raise JevAuthorizationError("JEV closure authorization was not an explicit non-mutating allow")
    return report

def card_payload(task_id:str,**fields)->dict:
    payload={"id":task_id,**fields}
    payload["mutation_sha256"]=__import__("hashlib").sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
    return payload


def existing_card_payload(conn:sqlite3.Connection,task_id:str)->dict:
    from hermes_cli import kanban_db as kb
    task=kb.get_task(conn,task_id)
    if task is None: raise JevAuthorizationError(f"unknown card: {task_id}")
    parents=[row["parent_id"] for row in conn.execute("SELECT parent_id FROM task_links WHERE child_id=? ORDER BY parent_id",(task_id,)).fetchall()]
    fields={name:getattr(task,name) for name in task.__dataclass_fields__ if name not in {"id","comments","events","runs","attachments"}}
    fields["parents"]=parents
    return card_payload(task.id,**fields)

def authorize_existing_card(conn:sqlite3.Connection,task_id:str)->dict|None:
    payload=existing_card_payload(conn,task_id)
    report=authorize_card(conn,payload)
    if report is None: return None
    bound=dict(report);bound["hermes_mutation_sha256"]=payload["mutation_sha256"]
    return bound

def assert_existing_card_authorized(conn:sqlite3.Connection,task_id:str,receipt:dict|None)->None:
    if receipt is None:
        if _config(conn) is not None: raise JevAuthorizationError("missing JEV authorization receipt")
        return
    current=existing_card_payload(conn,task_id)
    if receipt.get("hermes_mutation_sha256")!=current["mutation_sha256"]:
        raise JevAuthorizationError("card changed after JEV authorization")
