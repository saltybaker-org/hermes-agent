from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_dispatch as kbd
from hermes_cli.kanban_limits import (
    BUDGET_POLICY_VERSION,
    CARD_BUDGET_BYTES,
    HARD_MAX_WORKER_TURNS,
    CardBudgetError,
    evaluate_card_budget,
)


@pytest.fixture
def signed_receipt(tmp_path,monkeypatch):
    import base64,time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from hermes_cli import kanban_limits as limits
    private=Ed25519PrivateKey.generate();public=tmp_path/"budget.pub"
    public.write_bytes(private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(limits,"_trusted_public_key_path",lambda:public)
    def issue(title,body,turns=100,key="signed-card"):
        now=int(time.time());receipt={"schema_version":"hermes-card-budget-exception.v1","actor":"security-officer","reason":"single audited migration rehearsal","issued_at":now-1,"expires_at":now+3600,"card_sha256":limits._card_sha(title,body,turns,key),"idempotency_key":key}
        receipt["signature"]=base64.b64encode(private.sign(limits._canonical(receipt))).decode();return receipt
    return issue


def test_utf8_budget_boundary_and_turn_ceiling():
    title = "t"
    exact_body = "x" * (CARD_BUDGET_BYTES - len((title + "\n").encode()))
    allowed = evaluate_card_budget(title, exact_body, worker_max_turns=HARD_MAX_WORKER_TURNS)
    assert allowed.measured_bytes == CARD_BUDGET_BYTES
    assert allowed.violations == ()

    with pytest.raises(CardBudgetError, match="card_bytes"):
        evaluate_card_budget(title, exact_body + "é", worker_max_turns=HARD_MAX_WORKER_TURNS)
    with pytest.raises(CardBudgetError, match="worker_max_turns"):
        evaluate_card_budget(title, "small", worker_max_turns=HARD_MAX_WORKER_TURNS + 1)


def test_oversize_exception_requires_signed_receipt(signed_receipt):
    body="x"*CARD_BUDGET_BYTES
    with pytest.raises(CardBudgetError): evaluate_card_budget("t",body,worker_max_turns=100)
    receipt=signed_receipt("t",body)
    allowed=evaluate_card_budget("t",body,worker_max_turns=100,exception_receipt=receipt,idempotency_key="signed-card",admission_time=receipt["issued_at"]+1)
    assert allowed.exception_authorized is True
    assert allowed.measured_bytes>allowed.limit_bytes


@pytest.fixture
def board(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    with kbc.connect() as conn:
        yield conn


def test_create_enforces_budget_and_persists_audited_exception(board,signed_receipt):
    with pytest.raises(CardBudgetError, match="card_bytes"):
        kb.create_task(board, title="t", body="x" * CARD_BUDGET_BYTES)
    assert board.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0

    task_id = kb.create_task(
        board,
        title="t",
        body="x" * CARD_BUDGET_BYTES,
        worker_max_turns=250,
        idempotency_key="signed-card", budget_exception_receipt=signed_receipt("t","x"*CARD_BUDGET_BYTES,250),
    )
    task = kb.get_task(board, task_id)
    assert task.worker_max_turns == 250
    assert task.budget_exception_actor == "security-officer"
    assert task.budget_exception_receipt
    event = next(e for e in kb.list_events(board, task_id) if e.kind == "budget_exception")
    assert event.payload["measured_bytes"] > event.payload["limit_bytes"]
    assert event.payload["policy_version"] == BUDGET_POLICY_VERSION


def test_worker_argv_pins_task_turn_budget(board):
    task_id = kb.create_task(board, title="bounded", assignee="worker", worker_max_turns=123)
    argv = kbd._worker_argv(kb.get_task(board, task_id), "worker", None)
    index = argv.index("--max-turns")
    assert argv[index + 1] == "123"


def test_dispatch_blocks_oversize_row_inserted_outside_create(board, all_assignees_spawnable):
    board.execute(
        "INSERT INTO tasks (id,title,body,assignee,status,priority,created_at,workspace_kind) "
        "VALUES ('legacy','t',?,'worker','ready',0,1,'scratch')",
        ("x" * CARD_BUDGET_BYTES,),
    )
    spawned = []
    result = kbd.dispatch_once(
        board,
        spawn_fn=lambda task, workspace, board=None: spawned.append(task.id) or 42,
    )
    assert spawned == []
    assert "legacy" in result.auto_blocked
    task = kb.get_task(board, "legacy")
    assert task.status == "blocked"
    assert task.block_kind == "needs_input"
    events = [e for e in kb.list_events(board, "legacy") if e.kind == "budget_rejected"]
    assert len(events) == 1
    assert events[0].payload["policy_version"] == BUDGET_POLICY_VERSION


def test_create_parser_exposes_worker_budget_and_audited_exception():
    import argparse
    from hermes_cli import kanban_parser
    parser = argparse.ArgumentParser()
    kanban_parser.build_parser(parser.add_subparsers(dest="command"))
    args = parser.parse_args([
        "kanban", "create", "title", "--worker-max-turns", "120",
        "--budget-exception-receipt", "/tmp/receipt.json",
    ])
    assert args.worker_max_turns == 120
    assert args.budget_exception_receipt == "/tmp/receipt.json"


def test_specify_rejects_oversize_growth_without_mutation(board):
    task_id = kb.create_task(board, title="small", body="body", triage=True)
    with pytest.raises(CardBudgetError):
        kb.specify_triage_task(board, task_id, body="x" * CARD_BUDGET_BYTES)
    task = kb.get_task(board, task_id)
    assert task.status == "triage"
    assert task.body == "body"


def test_worker_context_cannot_authorize_size_exception(board, monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_TASK", "parent-task")
    with pytest.raises(PermissionError, match="self-asserted"):
        kb.create_task(
            board, title="large", body="x" * CARD_BUDGET_BYTES,
            budget_exception_reason="self-authorized",
        )
    assert kb.list_tasks(board) == []


def test_turn_budget_rejects_non_integer_values():
    for value in (True,500.9,"500"):
        with pytest.raises(CardBudgetError,match="integer"):
            evaluate_card_budget("t","body",worker_max_turns=value)

def test_dispatch_blocks_malformed_persisted_turn_budget(board,all_assignees_spawnable):
    task_id=kb.create_task(board,title="bad",assignee="worker")
    board.execute("UPDATE tasks SET worker_max_turns=500.5 WHERE id=?",(task_id,))
    spawned=[]
    result=kbd.dispatch_once(board,spawn_fn=lambda task,workspace,board=None: spawned.append(task.id) or 1)
    assert spawned==[]
    assert task_id in result.auto_blocked

def test_shrinking_excepted_card_clears_obsolete_receipt(board,signed_receipt):
    body="x"*CARD_BUDGET_BYTES
    task_id=kb.create_task(board,title="t",body=body,triage=True,idempotency_key="signed-card",budget_exception_receipt=signed_receipt("t",body,500))
    assert kb.specify_triage_task(board,task_id,body="small")
    task=kb.get_task(board,task_id)
    assert task.budget_exception_actor is None
    assert task.budget_exception_reason is None


def test_budget_exception_rejects_non_ed25519_public_key(tmp_path,monkeypatch):
    import base64,time
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from hermes_cli import kanban_limits as limits
    private=Ed448PrivateKey.generate();public=tmp_path/"budget.pub"
    public.write_bytes(private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(limits,"_trusted_public_key_path",lambda:public)
    body="x"*CARD_BUDGET_BYTES;now=int(time.time());receipt={"schema_version":"hermes-card-budget-exception.v1","actor":"security-officer","reason":"migration","issued_at":now-1,"expires_at":now+60,"card_sha256":limits._card_sha("t",body,100,"signed-card"),"idempotency_key":"signed-card"}
    receipt["signature"]=base64.b64encode(private.sign(limits._canonical(receipt))).decode()
    with pytest.raises(CardBudgetError,match="Ed25519"):
        evaluate_card_budget("t",body,worker_max_turns=100,exception_receipt=receipt,idempotency_key="signed-card",admission_time=now)


def test_idempotent_retry_returns_existing_after_receipt_expiry(board,signed_receipt,monkeypatch):
    from types import SimpleNamespace
    body="x"*CARD_BUDGET_BYTES;receipt=signed_receipt("t",body,100,"retry-key")
    first=kb.create_task(board,title="t",body=body,worker_max_turns=100,idempotency_key="retry-key",budget_exception_receipt=receipt)
    monkeypatch.setattr(kb,"time",SimpleNamespace(time=lambda:receipt["expires_at"]+100))
    second=kb.create_task(board,title="t",body=body,worker_max_turns=100,idempotency_key="retry-key",budget_exception_receipt=receipt)
    assert second==first
    assert board.execute("SELECT COUNT(*) FROM tasks WHERE idempotency_key='retry-key'").fetchone()[0]==1
