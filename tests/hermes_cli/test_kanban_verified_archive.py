from __future__ import annotations
import json
from pathlib import Path
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_verified_archive as kva

@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_ARCHIVE_AUTHORIZED_LOGINS", "bob")
    monkeypatch.setenv("HERMES_KANBAN_HUMAN_MERGE_LOGIN", "bob")
    def gh(endpoint):
        if endpoint == "user": return {"login": "bob"}
        return {"html_url": "https:" + "//github.com/example/repo/pull/1", "merged": True,
                "merged_at": "2026-09-30T00:00:00Z", "merged_by": {"login": "bob"},
                "head": {"sha": "a" * 40}, "merge_commit_sha": "b" * 40}
    monkeypatch.setattr(kva, "_gh_json", gh)
    path=tmp_path/"kanban.db"
    kbc.init_db(path)
    conn=kbc.connect(path)
    yield conn
    conn.close()

def _status(conn, task_id, status):
    with kb.write_txn(conn): conn.execute("UPDATE tasks SET status=? WHERE id=?",(status,task_id))

def _fixture(conn):
    sha="a"*40; merge="b"*40
    rejected=kb.create_task(conn,title="rejected",body="x")
    replacement=kb.create_task(conn,title="replacement",body="x")
    merge_task=kb.create_task(conn,title="merge",body="x")
    assert kb.complete_task(conn,replacement,result="replacement gate approved");assert kb.complete_task(conn,merge_task,result="merge verified");_status(conn,rejected,"blocked")
    kb.link_tasks(conn,rejected,merge_task); kb.link_tasks(conn,replacement,merge_task)
    r=kva.record_gate_verdict(conn,rejected,gate_kind="security",verdict="REJECT",candidate_sha=sha,reviewer="hermes:reviewer",author="hermes:author")
    n=kva.record_gate_verdict(conn,replacement,gate_kind="security",verdict="APPROVE",candidate_sha=sha,reviewer="hermes:other",author="hermes:author")
    m=kva.record_merge_evidence(conn,merge_task,candidate_sha=sha,pr_url="https:" + "//github.com/example/repo/pull/1")
    manifest={"schema_version":kva.SCHEMA_VERSION,"gate_kind":"security","rejected_task_id":rejected,
      "replacement_task_id":replacement,"replacement_verdict":"APPROVE","candidate_sha":sha,
      "merge_task_id":merge_task,"merge_sha":merge,
      "merge_pr_url":"https:" + "//github.com/example/repo/pull/1",
      "merge_receipt_sha256":kva._digest(kva._event_payload(conn,merge_task,"human_merge_verified")[1]),
      "authorization":{"actor_login":"bob","scope":"archive-superseded-gate"},
      "required_child_ids":[rejected,replacement,merge_task],
      "required_edges":[{"parent_id":rejected,"child_id":merge_task},{"parent_id":replacement,"child_id":merge_task}],
      "evidence_refs":[{"table":"event","id":r,"task_id":rejected},{"table":"event","id":n,"task_id":replacement},{"table":"event","id":m,"task_id":merge_task}]}
    return rejected,replacement,merge_task,manifest

def test_verified_archive_retains_evidence_and_archives_rejection(board):
    rejected,_,_,manifest=_fixture(board)
    before={t:board.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("task_comments","task_attachments","task_events")}
    result=kva.verified_archive_superseded_gate(board,manifest)
    assert result["archived_task_id"]==rejected
    assert kb.get_task(board,rejected).status=="archived"
    after={t:board.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in before}
    assert after["task_comments"]==before["task_comments"]
    assert after["task_attachments"]==before["task_attachments"]
    assert after["task_events"]==before["task_events"]+1

def test_mixed_candidate_identity_denies_without_mutation(board):
    rejected,_,_,manifest=_fixture(board);manifest["candidate_sha"]="c"*40
    before=board.total_changes
    with pytest.raises(kva.VerifiedArchiveDenied,match="candidate SHA mismatch"):
        kva.verified_archive_superseded_gate(board,manifest)
    assert board.total_changes==before
    assert kb.get_task(board,rejected).status=="blocked"

def test_nonterminal_or_duplicate_children_deny(board):
    rejected,replacement,merge_task,manifest=_fixture(board)
    extra=kb.create_task(board,title="still running",body="x")
    manifest["required_child_ids"].append(extra)
    with pytest.raises(kva.VerifiedArchiveDenied,match="dependency graph"):
        kva.verified_archive_superseded_gate(board,manifest)
    assert kb.get_task(board,rejected).status=="blocked"
    manifest["required_child_ids"]=[rejected,replacement,merge_task,rejected]
    with pytest.raises(kva.VerifiedArchiveDenied,match="duplicate"):
        kva.verified_archive_superseded_gate(board,manifest)

def test_missing_or_rebound_evidence_denies(board):
    rejected,_,_,manifest=_fixture(board)
    manifest["evidence_refs"][0]["task_id"]="wrong"
    with pytest.raises(kva.VerifiedArchiveDenied,match="missing or bound"):
        kva.verified_archive_superseded_gate(board,manifest)
    assert kb.get_task(board,rejected).status=="blocked"


def test_ordinary_archive_cannot_bypass_rejected_gate_verification(board):
    rejected,_,_,_=_fixture(board)
    with pytest.raises(kva.VerifiedArchiveDenied, match="verified archive"):
        kb.archive_task(board,rejected)
    assert kb.get_task(board,rejected).status=="blocked"


def test_rejecting_gate_verdict_cannot_be_rewritten_on_same_task(board):
    task=kb.create_task(board,title="gate",body="x")
    kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha="a"*40,reviewer="hermes:reviewer",author="hermes:author")
    with pytest.raises(ValueError,match="immutable"):
        kva.record_gate_verdict(board,task,gate_kind="security",verdict="APPROVE",candidate_sha="a"*40,reviewer="hermes:other",author="hermes:author")
    with pytest.raises(kva.VerifiedArchiveDenied,match="verified archive"):
        kb.archive_task(board,task)


def test_empty_or_aliased_gate_identities_are_rejected(board):
    task=kb.create_task(board,title="gate")
    for reviewer,author in [("hermes:reviewer",""),("hermes:same","hermes:same")]:
        with pytest.raises(ValueError,match="independent"):
            kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha="a"*40,reviewer=reviewer,author=author)

def test_manifest_cannot_omit_actual_ancestor(board):
    rejected,_,merge_task,manifest=_fixture(board)
    extra=kb.create_task(board,title="actual parent")
    kb.link_tasks(board,extra,merge_task)
    manifest["required_child_ids"].remove(extra) if extra in manifest["required_child_ids"] else None
    with pytest.raises(kva.VerifiedArchiveDenied,match="dependency graph"):
        kva.verified_archive_superseded_gate(board,manifest)
    assert kb.get_task(board,rejected).status=="blocked"

def test_unrelated_evidence_refs_cannot_replace_authority_rows(board):
    rejected,replacement,merge_task,manifest=_fixture(board)
    kb.add_comment(board,rejected,"operator","note")
    cid=board.execute("SELECT MAX(id) FROM task_comments").fetchone()[0]
    manifest["evidence_refs"][0]={"table":"comment","id":cid,"task_id":rejected}
    with pytest.raises(kva.VerifiedArchiveDenied,match="exact structured authority"):
        kva.verified_archive_superseded_gate(board,manifest)

def test_extra_blocked_ancestor_is_not_terminal(board):
    rejected,_,merge_task,manifest=_fixture(board)
    extra=kb.create_task(board,title="blocked upstream")
    _status(board,extra,"blocked");kb.link_tasks(board,extra,merge_task)
    manifest["required_child_ids"].append(extra)
    manifest["required_edges"].append({"parent_id":extra,"child_id":merge_task})
    with pytest.raises(kva.VerifiedArchiveDenied,match="successful"):
        kva.verified_archive_superseded_gate(board,manifest)

def test_duplicate_gate_event_blocks_ordinary_archive(board):
    task=kb.create_task(board,title="gate")
    kva.record_gate_verdict(board,task,gate_kind="security",verdict="APPROVE",candidate_sha="a"*40,reviewer="hermes:r",author="hermes:a")
    with kb.write_txn(board): kb._append_event(board,task,"gate_verdict",{"verdict":"APPROVE"})
    with pytest.raises(kva.VerifiedArchiveDenied,match="structured gate"):
        kb.archive_task(board,task)


def test_gate_verdict_rejects_display_name_identities(board):
    task=kb.create_task(board,title="gate")
    with pytest.raises(ValueError,match="principal"):
        kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha="a"*40,reviewer="alice@example.com",author="Alice")


def test_manifest_and_evidence_reference_schemas_are_closed(board):
    rejected,_,_,manifest=_fixture(board);manifest["unknown"]="nope"
    with pytest.raises(kva.VerifiedArchiveDenied,match="schema"):
        kva.verified_archive_superseded_gate(board,manifest)
    rejected,_,_,manifest=_fixture(board);manifest["evidence_refs"][0]["unknown"]="nope"
    with pytest.raises(kva.VerifiedArchiveDenied,match="reference schema"):
        kva.verified_archive_superseded_gate(board,manifest)

def test_evidence_references_are_exact_authority_set(board):
    rejected,_,_,manifest=_fixture(board)
    kb.add_comment(board,rejected,"operator","extra")
    row=board.execute("SELECT MAX(id) AS id FROM task_comments").fetchone()
    manifest["evidence_refs"].append({"table":"comment","id":row["id"],"task_id":rejected})
    with pytest.raises(kva.VerifiedArchiveDenied,match="exact structured authority"):
        kva.verified_archive_superseded_gate(board,manifest)


def test_gate_roles_must_directly_authorize_merge_even_if_nodes_match(board):
    rejected,replacement,merge_task,manifest=_fixture(board)
    with kb.write_txn(board):
        board.execute("DELETE FROM task_links WHERE parent_id=? AND child_id=?",(rejected,merge_task))
        board.execute("INSERT INTO task_links(parent_id,child_id) VALUES (?,?)",(rejected,replacement))
    manifest["required_edges"]=[{"parent_id":rejected,"child_id":replacement},{"parent_id":replacement,"child_id":merge_task}]
    with pytest.raises(kva.VerifiedArchiveDenied,match="direct"):
        kva.verified_archive_superseded_gate(board,manifest)


def test_verified_archive_authority_events_survive_gc(board):
    rejected,replacement,merge_task,manifest=_fixture(board)
    kva.verified_archive_superseded_gate(board,manifest)
    authority_ids=[ref["id"] for ref in manifest["evidence_refs"]]
    receipt=board.execute("SELECT id FROM task_events WHERE task_id=? AND kind='verified_superseded_archive'",(rejected,)).fetchone()["id"]
    with kb.write_txn(board): board.execute("UPDATE task_events SET created_at=1 WHERE id IN (?,?,?,?)",(*authority_ids,receipt))
    kb.gc_events(board,older_than_seconds=0)
    remaining={row["id"] for row in board.execute("SELECT id FROM task_events WHERE id IN (?,?,?,?)",(*authority_ids,receipt)).fetchall()}
    assert remaining==set(authority_ids+[receipt])


def test_numeric_sha_and_whitespace_principals_are_rejected(board):
    task=kb.create_task(board,title="gate")
    with pytest.raises(ValueError,match="candidate_sha"):
        kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha=int("1"*40),reviewer="hermes:reviewer",author="hermes:author")
    with pytest.raises(ValueError,match="principal"):
        kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha="a"*40,reviewer=" hermes:reviewer ",author="hermes:author")

def test_provider_scoped_oidc_and_basic_principals_are_accepted(board):
    task=kb.create_task(board,title="gate")
    kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha="a"*40,reviewer="oidc:oidc|abc123",author="basic:alice")

def test_archived_without_prior_success_is_not_successful_terminal(board):
    rejected,replacement,merge_task,manifest=_fixture(board)
    with kb.write_txn(board):
        board.execute("UPDATE tasks SET status='archived' WHERE id=?",(merge_task,))
        board.execute("DELETE FROM task_events WHERE task_id=? AND kind='completed'",(merge_task,))
    with pytest.raises(kva.VerifiedArchiveDenied,match="successful"):
        kva.verified_archive_superseded_gate(board,manifest)

def test_verified_archive_cannot_be_hard_deleted(board):
    rejected,_,_,manifest=_fixture(board);kva.verified_archive_superseded_gate(board,manifest)
    assert kb.delete_archived_task(board,rejected) is False
    assert kb.get_task(board,rejected) is not None


def test_malformed_persisted_principal_fails_closed(board):
    rejected,_,_,manifest=_fixture(board)
    row=board.execute("SELECT id,payload FROM task_events WHERE task_id=? AND kind='gate_verdict'",(rejected,)).fetchone();payload=json.loads(row["payload"]);payload["reviewer"]=7
    with kb.write_txn(board): board.execute("UPDATE task_events SET payload=? WHERE id=?",(json.dumps(payload),row["id"]))
    with pytest.raises(kva.VerifiedArchiveDenied,match="principal"):
        kva.verified_archive_superseded_gate(board,manifest)

def test_all_tasks_referenced_by_verified_archive_are_delete_protected(board):
    rejected,replacement,merge_task,manifest=_fixture(board);kva.verified_archive_superseded_gate(board,manifest)
    for task in (rejected,replacement,merge_task):
        assert kb.delete_task(board,task) is False
    with kb.write_txn(board):
        board.execute("UPDATE tasks SET status='archived' WHERE id IN (?,?)",(replacement,merge_task))
    for task in (replacement,merge_task): assert kb.delete_archived_task(board,task) is False


@pytest.mark.parametrize("mutation",[
    lambda payload: payload.pop("replacement_task_id"),
    lambda payload: payload.update(extra="x"),
    lambda payload: payload.update(merge_task_id=7),
    lambda payload: payload.update(evidence_refs={}),
    lambda payload: payload.update(evidence_refs=[{"table":"event","id":"1","task_id":"x"}]),
])
def test_malformed_verified_receipt_globally_fails_closed_for_deletion(board,mutation):
    rejected,_,_,manifest=_fixture(board);kva.verified_archive_superseded_gate(board,manifest)
    row=board.execute("SELECT id,payload FROM task_events WHERE task_id=? AND kind='verified_superseded_archive'",(rejected,)).fetchone();payload=json.loads(row["payload"]);mutation(payload)
    unrelated=kb.create_task(board,title="unrelated")
    with kb.write_txn(board): board.execute("UPDATE task_events SET payload=? WHERE id=?",(json.dumps(payload),row["id"]))
    assert kb.delete_task(board,unrelated) is False


def test_rejected_gate_cannot_be_deleted_before_verified_archive(board):
    task=kb.create_task(board,title="rejected gate")
    kva.record_gate_verdict(board,task,gate_kind="security",verdict="REJECT",candidate_sha="a"*40,reviewer="github:reviewer",author="github:author")
    assert kb.delete_task(board,task) is False
    assert kb.get_task(board,task) is not None


def test_malformed_gate_evidence_cannot_be_hard_deleted(board):
    task=kb.create_task(board,title="malformed gate")
    with kb.write_txn(board):
        kb._append_event(board,task,"gate_verdict",{"verdict":"REJECT"})
    assert kb.delete_task(board,task) is False
    assert kb.get_task(board,task) is not None


def test_approved_gate_requires_ordinary_archive_before_hard_delete(board):
    task=kb.create_task(board,title="approved gate")
    kva.record_gate_verdict(board,task,gate_kind="security",verdict="APPROVE",candidate_sha="a"*40,reviewer="github:reviewer",author="github:author")
    assert kb.delete_task(board,task) is False
    assert kb.archive_task(board,task) is True
    assert kb.delete_archived_task(board,task) is True


def test_manifest_builder_enumerates_all_ancestors_and_receipt(board):
    rejected, replacement, merge_task, _ = _fixture(board)
    extra = kb.create_task(board, title="publication", body="done")
    assert kb.complete_task(board, extra, result="published")
    with kb.write_txn(board):
        board.execute("INSERT INTO task_links(parent_id,child_id) VALUES (?,?)", (extra, replacement))
    _status(board, rejected, "blocked")
    manifest = kva.build_archive_manifest(board, rejected, replacement, merge_task)
    assert extra in manifest["required_child_ids"]
    assert {"parent_id": extra, "child_id": replacement} in manifest["required_edges"]
    receipt = kva.verified_archive_superseded_gate(board, manifest)
    assert receipt["archive_manifest_sha256"] == kva._digest(manifest)
    assert receipt["merge_receipt_sha256"] == manifest["merge_receipt_sha256"]


def test_archive_requires_authenticated_authorized_caller(board, monkeypatch):
    rejected, _, _, manifest = _fixture(board)
    monkeypatch.setenv("HERMES_KANBAN_ARCHIVE_AUTHORIZED_LOGINS", "another-operator")
    with pytest.raises(kva.VerifiedArchiveDenied, match="authorized archiver"):
        kva.verified_archive_superseded_gate(board, manifest)
    assert kb.get_task(board, rejected).status == "blocked"


def test_archiver_identity_cannot_be_substituted_in_manifest(board):
    rejected, _, _, manifest = _fixture(board)
    manifest["authorization"]["actor_login"] = "other"
    with pytest.raises(kva.VerifiedArchiveDenied, match="authorization"):
        kva.verified_archive_superseded_gate(board, manifest)
    assert kb.get_task(board, rejected).status == "blocked"


def test_claimed_human_name_does_not_impersonate_merged_by(board, monkeypatch):
    merge_task = kb.create_task(board, title="merge", body="x")
    monkeypatch.setattr(kva, "_gh_json", lambda endpoint: {"html_url": "https:" + "//github.com/example/repo/pull/1",
        "merged": True, "merged_at": "2026-09-30T00:00:00Z", "merged_by": {"login": "bot"},
        "head": {"sha": "a"*40}, "merge_commit_sha": "b"*40})
    with pytest.raises(kva.VerifiedArchiveDenied, match="configured human"):
        kva.record_merge_evidence(board, merge_task, candidate_sha="a"*40,
            pr_url="https:" + "//github.com/example/repo/pull/1")
    assert kva._event_payload(board, merge_task, "human_merge_verified") is None


def test_archive_rejects_tampered_digest_and_stale_merge(board, monkeypatch):
    rejected, _, _, manifest = _fixture(board)
    manifest["merge_receipt_sha256"] = "0"*64
    with pytest.raises(kva.VerifiedArchiveDenied, match="authenticated human merge"):
        kva.verified_archive_superseded_gate(board, manifest)
    assert kb.get_task(board, rejected).status == "blocked"
    monkeypatch.setattr(kva, "collect_human_merge", lambda *args: {"stale": True})
    with pytest.raises(kva.VerifiedArchiveDenied, match="authenticated human merge"):
        kva.verified_archive_superseded_gate(board, manifest)


def test_legacy_v1_archive_receipt_remains_delete_protected(board):
    rejected, replacement, merge_task, manifest = _fixture(board)
    kva.verified_archive_superseded_gate(board, manifest)
    row = board.execute("SELECT id,payload FROM task_events WHERE task_id=? AND kind='verified_superseded_archive'", (rejected,)).fetchone()
    payload = json.loads(row["payload"])
    payload["schema_version"] = kva.LEGACY_SCHEMA_VERSION
    for field in ("authorization", "merge_pr_url", "merge_receipt_sha256"):
        payload.pop(field)
    with kb.write_txn(board):
        board.execute("UPDATE task_events SET payload=? WHERE id=?", (json.dumps(payload), row["id"]))
    for task in (rejected, replacement, merge_task):
        assert kb.delete_task(board, task) is False


def test_merge_collector_cli_response_digest_and_worker_denial(board, monkeypatch, capsys):
    import argparse
    from contextlib import contextmanager
    from hermes_cli import kanban as cli
    task = kb.create_task(board, title="merge receipt", body="x")
    @contextmanager
    def connection():
        yield board
    monkeypatch.setattr(cli.kbc, "connect_closing", connection)
    args = argparse.Namespace(task_id=task, candidate_sha="a"*40,
        pr_url="https:" + "//github.com/example/repo/pull/1", json=True)
    assert cli._cmd_collect_human_merge(args) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["evidence_sha256"] == kva._digest(response["evidence"])
    assert response["evidence"]["merged_by"] == "bob"
    assert response["event_id"] == kva._event_payload(board, task, "human_merge_verified")[0]
    other = kb.create_task(board, title="another merge")
    args.task_id = other
    monkeypatch.setenv("HERMES_KANBAN_TASK", "worker")
    assert cli._cmd_collect_human_merge(args) == 2
    assert kva._event_payload(board, other, "human_merge_verified") is None
