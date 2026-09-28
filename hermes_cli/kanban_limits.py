"""Deterministic admission policy for Kanban card and worker budgets."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
from pathlib import Path

CARD_BUDGET_BYTES = 8 * 1024
HARD_MAX_WORKER_TURNS = 500
BUDGET_POLICY_VERSION = "kanban-card-budget.v1"


class CardBudgetError(ValueError):
    """The requested card cannot be admitted under the deterministic policy."""


def _trusted_public_key_path() -> Path:
    path=Path("/etc/hermes/budget-exception-ed25519.pub")
    try: st=path.stat()
    except OSError as exc: raise CardBudgetError("trusted budget-exception public key is unavailable") from exc
    if st.st_uid!=0 or st.st_mode & 0o022: raise CardBudgetError("budget-exception public key ownership is unsafe")
    return path

def _canonical(value:dict)->bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _card_sha(title,body,turns,idempotency_key)->str:
    return hashlib.sha256(_canonical({"title":str(title),"body":body or "","worker_max_turns":turns,"idempotency_key":idempotency_key})).hexdigest()
def verify_exception_receipt(receipt:dict,*,title:str,body:str|None,worker_max_turns:int,idempotency_key:str|None,admission_time:int)->dict:
    if not isinstance(receipt,dict) or set(receipt)!={"schema_version","actor","reason","issued_at","expires_at","card_sha256","idempotency_key","signature"}:
        raise CardBudgetError("budget exception receipt schema is invalid")
    if receipt["schema_version"]!="hermes-card-budget-exception.v1": raise CardBudgetError("budget exception receipt schema is invalid")
    actor=str(receipt["actor"]).strip();reason=str(receipt["reason"]).strip()
    if not actor or not reason or not idempotency_key or receipt["idempotency_key"]!=idempotency_key: raise CardBudgetError("budget exception receipt is not narrowly scoped")
    issued=int(receipt["issued_at"]);expires=int(receipt["expires_at"])
    if issued>admission_time+60 or expires<admission_time or expires-issued>86400: raise CardBudgetError("budget exception receipt is expired or invalid")
    if receipt["card_sha256"]!=_card_sha(title,body,worker_max_turns,idempotency_key): raise CardBudgetError("budget exception receipt does not match card content")
    import base64
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    signed=dict(receipt);signature=signed.pop("signature")
    try:
        key=load_pem_public_key(_trusted_public_key_path().read_bytes())
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(key, Ed25519PublicKey):
            raise CardBudgetError("budget exception key must be Ed25519")
        key.verify(base64.b64decode(signature,validate=True),_canonical(signed))
    except CardBudgetError:
        raise
    except Exception as exc:
        raise CardBudgetError("budget exception signature is invalid") from exc
    return receipt

@dataclass(frozen=True)
class CardBudgetDecision:
    measured_bytes:int;limit_bytes:int;worker_max_turns:int;hard_max_worker_turns:int
    violations:tuple[str,...];exception_authorized:bool;policy_version:str=BUDGET_POLICY_VERSION

def evaluate_card_budget(title:str,body:str|None,*,worker_max_turns:int,exception_receipt:dict|None=None,idempotency_key:str|None=None,admission_time:int|None=None,limit_bytes:int=CARD_BUDGET_BYTES)->CardBudgetDecision:
    measured=len((str(title)+"\n"+(body or "")).encode("utf-8"))
    if type(worker_max_turns) is not int: raise CardBudgetError("worker_max_turns must be an exact integer")
    if worker_max_turns<1 or worker_max_turns>HARD_MAX_WORKER_TURNS: raise CardBudgetError(f"worker_max_turns={worker_max_turns} outside 1..{HARD_MAX_WORKER_TURNS}")
    oversize=measured>int(limit_bytes);authorized=False
    if exception_receipt is not None:
        if not oversize: raise CardBudgetError("budget exception exists for a card that is within budget")
        verify_exception_receipt(exception_receipt,title=title,body=body,worker_max_turns=worker_max_turns,idempotency_key=idempotency_key,admission_time=int(admission_time if admission_time is not None else time.time()));authorized=True
    if oversize and not authorized: raise CardBudgetError(f"card_bytes={measured} exceeds limit={int(limit_bytes)}")
    violations=(f"card_bytes={measured} exceeds limit={int(limit_bytes)}",) if oversize else ()
    return CardBudgetDecision(measured,int(limit_bytes),worker_max_turns,HARD_MAX_WORKER_TURNS,violations,authorized)

def validate_persisted_task_budget(task)->CardBudgetDecision:
    try: receipt=json.loads(task.budget_exception_receipt) if task.budget_exception_receipt else None
    except (TypeError,json.JSONDecodeError) as exc: raise CardBudgetError("budget exception receipt is malformed") from exc
    decision=evaluate_card_budget(task.title,task.body,worker_max_turns=task.worker_max_turns,exception_receipt=receipt,idempotency_key=task.idempotency_key,admission_time=int(task.created_at))
    if decision.exception_authorized:
        expected=(decision.measured_bytes,decision.limit_bytes,decision.policy_version)
        stored=(task.budget_exception_measured_bytes,task.budget_exception_limit_bytes,task.budget_policy_version)
        if stored!=expected or task.budget_exception_at is None: raise CardBudgetError("budget exception receipt is stale or incomplete")
    return decision
