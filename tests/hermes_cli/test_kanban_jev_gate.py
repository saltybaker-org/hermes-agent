from __future__ import annotations
import json,sys
from pathlib import Path
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_dispatch as kbd
from hermes_cli import kanban_jev_gate as gate

@pytest.fixture
def board(tmp_path):
    path=tmp_path/"kanban.db";kbc.init_db(path);conn=kbc.connect(path)
    yield conn,tmp_path
    conn.close()

def _enable(root, script, timeout=2):
    (root/"board.json").write_text(json.dumps({"jev_mutation_gate":{"enabled":True,"timeout_seconds":timeout}}))
    gate._trusted_command=lambda:[sys.executable,str(script)]
    gate._sandbox_argv=lambda command,args,directory:command+[str(directory/Path(a).name) if str(a).startswith("/work/") else a for a in args]

@pytest.fixture(autouse=True)
def _restore_sandbox_builder():
    original=gate._sandbox_argv
    yield
    gate._sandbox_argv=original

def _script(root,name,body):
    p=root/name;p.write_text(body);return p

def test_direct_create_denial_leaves_no_row(board):
    conn,root=board
    script=_script(root,"deny.py",'import json,sys; print(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":False,"mutate_board":False}));sys.exit(2)')
    _enable(root,script)
    with pytest.raises(gate.JevAuthorizationError):
        kb.create_task(conn,title="denied",body="invalid")
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0

def test_adapter_fails_closed_on_missing_timeout_and_malformed(board):
    conn,root=board
    (root/"board.json").write_text(json.dumps({"jev_mutation_gate":{"enabled":True,"timeout_seconds":1}}))
    gate._trusted_command=lambda:[str(root/"missing")]
    gate._sandbox_argv=lambda command,args,directory:command+[str(directory/Path(a).name) if str(a).startswith("/work/") else a for a in args]
    with pytest.raises(gate.JevAuthorizationError): gate.authorize_card(conn,{"id":"x"})
    slow=_script(root,"slow.py",'import time;time.sleep(2)')
    _enable(root,slow,timeout=.05)
    with pytest.raises(gate.JevAuthorizationError): gate.authorize_card(conn,{"id":"x"})
    bad=_script(root,"bad.py",'print("not-json")')
    _enable(root,bad)
    with pytest.raises(gate.JevAuthorizationError): gate.authorize_card(conn,{"id":"x"})


def test_direct_unblock_denial_preserves_blocked_state(board):
    conn,root=board
    task_id=kb.create_task(conn,title="blocked",body="card")
    with kb.write_txn(conn): conn.execute("UPDATE tasks SET status='blocked' WHERE id=?",(task_id,))
    script=_script(root,"deny-unblock.py",'import json,sys; print(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":False,"mutate_board":False}));sys.exit(2)')
    _enable(root,script)
    with pytest.raises(gate.JevAuthorizationError): kb.unblock_task(conn,task_id)
    assert kb.get_task(conn,task_id).status=="blocked"


def test_pipeline_denial_creates_zero_cards_or_edges(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,root=board
    script=_script(root,"deny-pipeline.py",'import json,sys; print(json.dumps({"schema_version":"fellowship-pipeline-preflight.v1","ok":False,"mutate_board":False}));sys.exit(2)')
    _enable(root,script)
    cards=[{"key":"one","stage":"requirements","title":"one","body":"body","assignee":"worker","parents":[]}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-999","cards":cards}
    with pytest.raises(gate.JevAuthorizationError): pipeline.create_pipeline(conn,manifest,cards)
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0
    assert conn.execute("SELECT COUNT(*) FROM task_links").fetchone()[0]==0


def test_direct_completion_cannot_publish_marked_closure(board):
    conn,_=board
    task_id=kb.create_task(conn,title="closure merge",body="body")
    with kb.write_txn(conn): kb._append_event(conn,task_id,"pipeline_stage",{"stage":"closure_merge","key":"closure"})
    with pytest.raises(gate.JevAuthorizationError,match="publish_closure"):
        kb.complete_task(conn,task_id,result="published")
    assert kb.get_task(conn,task_id).status!="done"


def test_dispatch_backstop_blocks_imported_card_before_spawn(board,all_assignees_spawnable):
    conn,root=board
    task_id=kb.create_task(conn,title="imported",body="body",assignee="worker")
    script=_script(root,"deny-dispatch.py",'import json,sys; print(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":False,"mutate_board":False}));sys.exit(2)')
    _enable(root,script)
    spawned=[]
    result=kbd.dispatch_once(conn,spawn_fn=lambda task,workspace,board=None: spawned.append(task.id) or 4)
    assert spawned==[]
    assert task_id in result.auto_blocked
    assert kb.get_task(conn,task_id).status=="blocked"


def test_closure_denial_leaves_task_unpublished(board):
    from hermes_cli.kanban_closure_mutation import publish_closure
    conn,root=board
    task_id=kb.create_task(conn,title="closure",body="body")
    with kb.write_txn(conn): kb._append_event(conn,task_id,"pipeline_stage",{"stage":"closure_merge","key":"closure"})
    script=_script(root,"deny-closure.py",'import json,sys; print(json.dumps({"schema_version":"fellowship-closure-preflight.v1","ok":False,"mutate_board":False}));sys.exit(2)')
    _enable(root,script)
    doc=root/"closure.md";doc.write_text("closure")
    with pytest.raises(gate.JevAuthorizationError):
        publish_closure(conn,task_id,evidence={},document=doc,result="published")
    assert kb.get_task(conn,task_id).status!="done"
    assert not [e for e in kb.list_events(conn,task_id) if e.kind=="jev_closure_authorized"]

def test_pipeline_card_denial_rolls_back_prior_cards(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,root=board
    script=_script(root,"mixed.py",'''import json,sys
if sys.argv[1]=="validate-pipeline":
 print(json.dumps({"schema_version":"fellowship-pipeline-preflight.v1","ok":True,"mutate_board":False}));sys.exit(0)
card=json.load(open(sys.argv[2]));allow=card["title"]!="deny"
print(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":allow,"mutate_board":False}));sys.exit(0 if allow else 2)
''')
    _enable(root,script)
    cards=[{"key":"one","stage":"requirements","title":"allow","body":"body","assignee":"worker","parents":[]},
      {"key":"two","stage":"architecture","title":"deny","body":"body","assignee":"worker","parents":["one"]}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-999","cards":cards}
    with pytest.raises(gate.JevAuthorizationError): pipeline.create_pipeline(conn,manifest,cards)
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0
    assert conn.execute("SELECT COUNT(*) FROM task_links").fetchone()[0]==0


def test_pipeline_manifest_must_match_constructed_graph(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,_=board
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-999","cards":[
      {"key":"one","stage":"requirements","assignee":"worker","parents":[]},
      {"key":"two","stage":"architecture","assignee":"architect","parents":["one"]}]}
    cards=[{"key":"one","stage":"requirements","title":"one","body":"body","assignee":"worker","parents":[]},
      {"key":"two","stage":"architecture","title":"two","body":"body","assignee":"architect","parents":[]}]
    with pytest.raises(pipeline.PipelineConstructionError,match="exactly match"):
        pipeline.create_pipeline(conn,manifest,cards)
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0


def test_pipeline_rejects_idempotency_keys_before_reusing_existing_task(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,_=board
    existing=kb.create_task(conn,title="preexisting",idempotency_key="shared")
    cards=[{"key":"one","stage":"requirements","title":"new one","body":"body","assignee":"worker","parents":[],"idempotency_key":"shared"}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-1","cards":cards}
    with pytest.raises(pipeline.PipelineConstructionError,match="idempotency"):
        pipeline.create_pipeline(conn,manifest,cards)
    assert kb.get_task(conn,existing).title=="preexisting"
    assert not [e for e in kb.list_events(conn,existing) if e.kind=="pipeline_stage"]


def test_explicitly_disabled_gate_denies_ordinary_mutation(board):
    conn,root=board
    (root/"board.json").write_text(json.dumps({"jev_mutation_gate":{"enabled":False}}))
    with pytest.raises(gate.JevAuthorizationError,match="disabled"):
        kb.create_task(conn,title="must not land")
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0


def test_evaluator_sandbox_unshares_pid_namespace(tmp_path):
    argv=gate._sandbox_argv(["/usr/local/bin/fellowship-jev"],["decide-policy","/work/card.json"],tmp_path)
    assert "--unshare-pid" in argv


def test_closure_publication_succeeds_and_retains_exact_bytes(board):
    from hermes_cli.kanban_closure_mutation import publish_closure
    conn,root=board
    task_id=kb.create_task(conn,title="closure",body="body")
    with kb.write_txn(conn): kb._append_event(conn,task_id,"pipeline_stage",{"stage":"closure_merge","key":"closure","feature_id":"F-1"})
    script=_script(root,"allow-closure.py",'import json;print(json.dumps({"schema_version":"fellowship-closure-preflight.v1","ok":True,"mutate_board":False}))')
    _enable(root,script)
    document=root/"closure.md";document.write_bytes(b"exact closure bytes")
    evidence={"feature_id":"F-1","closure_document":"closure.md","tests":["pass"]}
    assert publish_closure(conn,task_id,evidence=evidence,document=document,result="published")
    assert kb.get_task(conn,task_id).status=="done"
    row=conn.execute("SELECT evidence_json,document_bytes FROM task_closure_publications WHERE task_id=?",(task_id,)).fetchone()
    assert json.loads(row["evidence_json"])==evidence
    assert bytes(row["document_bytes"])==b"exact closure bytes"


def test_dispatch_preflight_uses_full_durable_card_payload(board,all_assignees_spawnable):
    conn,root=board
    task_id=kb.create_task(conn,title="full",body="body",assignee="worker",priority=7,created_by="operator")
    code="import json,sys;card=json.load(open(sys.argv[2]));allow=int(card.get('priority'))==7 and card.get('created_by')=='operator';print(json.dumps({'schema_version':'fellowship-authoritative-policy.v2','authoritative':True,'dispatch_allowed':allow,'mutate_board':False}));sys.exit(0 if allow else 2)"
    script=_script(root,"full-card.py",code)
    _enable(root,script)
    report=gate.authorize_existing_card(conn,task_id)
    assert report["dispatch_allowed"] is True


def test_create_runs_external_authorization_before_write_transaction(board,monkeypatch):
    conn,_=board;observed=[]
    def fake_authorize(active,payload):
        observed.append(active.in_transaction)
        return None
    monkeypatch.setattr(gate,"authorize_card",fake_authorize)
    kb.create_task(conn,title="outside lock")
    assert observed==[False]


def test_unblock_runs_external_authorization_before_write_transaction(board,monkeypatch):
    conn,_=board;task_id=kb.create_task(conn,title="blocked")
    with kb.write_txn(conn): conn.execute("UPDATE tasks SET status='blocked' WHERE id=?",(task_id,))
    observed=[]
    def fake(active,payload): observed.append(active.in_transaction);return None
    monkeypatch.setattr(gate,"authorize_card",fake)
    assert kb.unblock_task(conn,task_id)
    assert observed==[False]


def test_pipeline_external_evaluation_precedes_atomic_write(board,monkeypatch):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,_=board;observed=[]
    monkeypatch.setattr(pipeline,"authorize_pipeline",lambda active,manifest: observed.append(("pipeline",active.in_transaction)) or {"ok":True,"schema_version":"fellowship-pipeline-preflight.v1","mutate_board":False})
    monkeypatch.setattr(gate,"authorize_card",lambda active,card: observed.append(("card",active.in_transaction)) or {"authoritative":True,"dispatch_allowed":True,"mutate_board":False})
    cards=[{"key":"one","stage":"requirements","title":"one","body":"body","assignee":"worker","parents":[]}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-1","cards":cards}
    pipeline.create_pipeline(conn,manifest,cards)
    assert observed==[("pipeline",False),("card",False)]


def test_pipeline_exact_retry_returns_original_graph(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,root=board;script=_script(root,"allow_retry.py",'import json,sys;print(json.dumps({"schema_version":"fellowship-pipeline-preflight.v1","ok":True,"mutate_board":False}) if sys.argv[1]=="validate-pipeline" else json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":True,"mutate_board":False}))')
    _enable(root,script)
    cards=[{"key":"one","stage":"requirements","title":"one","body":"body","assignee":"worker","parents":[]}];manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-retry","cards":cards}
    first=pipeline.create_pipeline(conn,manifest,cards);second=pipeline.create_pipeline(conn,manifest,cards)
    assert second==first
    assert conn.execute("SELECT COUNT(*) AS n FROM tasks").fetchone()["n"]==1

def test_pipeline_card_gate_receives_exact_durable_payload(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,root=board;script=_script(root,"exact_card.py",'import json,sys\nif sys.argv[1]=="validate-pipeline": print(json.dumps({"schema_version":"fellowship-pipeline-preflight.v1","ok":True,"mutate_board":False}));sys.exit(0)\ncard=json.load(open(sys.argv[2]));allow=all(k in card for k in ("id","status","created_at","mutation_sha256","workspace_kind","parents"))\nprint(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":allow,"mutate_board":False}));sys.exit(0 if allow else 2)')
    _enable(root,script)
    cards=[{"key":"one","stage":"requirements","title":"one","body":"body","assignee":"worker","parents":[]}];manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-exact","cards":cards}
    assert pipeline.create_pipeline(conn,manifest,cards)["one"].startswith("t_")

def test_closure_artifact_hashes_revalidated_inside_transaction(board,monkeypatch,tmp_path):
    conn,root=board;script=_script(root,"closure_allow_hash.py",'import json,sys;print(json.dumps({"schema_version":"fellowship-closure-preflight.v1","ok":True,"mutate_board":False}) if sys.argv[1]=="validate-closure" else json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":True,"mutate_board":False}))');_enable(root,script)
    task=kb.create_task(conn,title="closure");kb._append_event(conn,task,"pipeline_stage",{"stage":"closure_merge","feature_id":"F-hash"});doc=tmp_path/"closure.md";doc.write_text("exact")
    from hermes_cli import kanban_closure_mutation as closure
    original=kb.complete_task
    def tamper(*args,**kwargs):
        kwargs["_closure_artifacts"]=dict(kwargs["_closure_artifacts"],document_bytes=b"tampered")
        return original(*args,**kwargs)
    monkeypatch.setattr(kb,"complete_task",tamper)
    with pytest.raises(gate.JevAuthorizationError,match="artifact"):
        closure.publish_closure(conn,task,evidence={"feature_id":"F-hash","closure_document":"closure.md"},document=doc)
    assert kb.get_task(conn,task).status=="ready"


def test_create_uses_preallocated_timestamp_and_canonical_numeric_payload(board,monkeypatch):
    conn,_=board;seen=[]
    monkeypatch.setattr(gate,"authorize_card",lambda active,payload: seen.append(payload) or None)
    task=kb.create_task(conn,title="canonical",max_runtime_seconds="2",max_retries="3",goal_max_turns="4",goal_mode=1,priority="5",_created_at=123456)
    row=conn.execute("SELECT created_at,max_runtime_seconds,max_retries,goal_max_turns,goal_mode,priority FROM tasks WHERE id=?",(task,)).fetchone()
    assert dict(row)=={"created_at":123456,"max_runtime_seconds":2,"max_retries":3,"goal_max_turns":4,"goal_mode":1,"priority":5}
    assert seen[0]["created_at"]==123456 and seen[0]["max_runtime_seconds"]==2 and seen[0]["max_retries"]==3 and seen[0]["goal_max_turns"]==4 and seen[0]["goal_mode"] is True and seen[0]["priority"]==5

def test_relative_age_default_clock_remains_usable():
    assert isinstance(kb._relative_age(0),str) and kb._relative_age(0)


def test_creator_session_is_bound_before_card_authorization(board,monkeypatch):
    conn,_=board;creator=kb.create_task(conn,title="creator",session_id="session-1");seen=[]
    monkeypatch.setattr(gate,"authorize_card",lambda active,payload: seen.append(payload) or None)
    child=kb.create_task(conn,title="child",creator_task_id=creator)
    assert seen[-1]["session_id"]=="session-1"
    assert kb.get_task(conn,child).session_id=="session-1"

def test_pipeline_blocked_status_precedes_triage(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,root=board;script=_script(root,"allow_both.py",'import json,sys;print(json.dumps({"schema_version":"fellowship-pipeline-preflight.v1","ok":True,"mutate_board":False}) if sys.argv[1]=="validate-pipeline" else json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":True,"mutate_board":False}))');_enable(root,script)
    cards=[{"key":"one","stage":"requirements","title":"one","triage":True,"initial_status":"blocked","parents":[]}];manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-both","cards":cards}
    task=pipeline.create_pipeline(conn,manifest,cards)["one"]
    assert kb.get_task(conn,task).status=="blocked"


def test_publish_closure_cli_completes_the_exact_live_worker_run(board,monkeypatch):
    import argparse,contextlib,os,time
    from hermes_cli import kanban as kc
    conn,root=board
    task_id=kb.create_task(conn,title="closure worker",body="body",assignee="worker")
    with kb.write_txn(conn):
        kb._append_event(conn,task_id,"pipeline_stage",{"stage":"closure_merge","feature_id":"F-cli"})
    claimed=kb.claim_task(conn,task_id,claimer="worker")
    assert claimed is not None
    kbd._set_worker_pid(conn,task_id,os.getpid())
    script=_script(root,"allow-cli-closure.py",'import json;print(json.dumps({"schema_version":"fellowship-closure-preflight.v1","ok":True,"mutate_board":False}))')
    _enable(root,script)
    evidence=root/"evidence.json";evidence.write_text(json.dumps({"feature_id":"F-cli","closure_document":"closure.md"}))
    document=root/"closure.md";document.write_bytes(b"exact cli closure")
    monkeypatch.setenv("HERMES_KANBAN_TASK",task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID",str(claimed.current_run_id))
    monkeypatch.setattr(kc.kbc,"connect_closing",lambda:contextlib.nullcontext(conn))
    args=argparse.Namespace(task_id=task_id,evidence=str(evidence),document=str(document),result="published",summary=None,json=False)

    assert kc._cmd_publish_closure(args)==0
    assert kb.get_task(conn,task_id).status=="done"
    row=conn.execute("SELECT evidence_json,document_bytes FROM task_closure_publications WHERE task_id=?",(task_id,)).fetchone()
    assert json.loads(row["evidence_json"])=={"feature_id":"F-cli","closure_document":"closure.md"}
    assert bytes(row["document_bytes"])==b"exact cli closure"


def test_sandbox_ignores_attacker_controlled_path(tmp_path, monkeypatch):
    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    argv = gate._sandbox_argv(["/usr/local/bin/fellowship-jev"], ["decide-policy"], tmp_path)
    assert argv[0] == "/usr/bin/bwrap"


def test_authoritative_policy_v2_accepts_current_jev(board):
    conn, root = board
    current = _script(root, "policy-v2.py", 'import json;print(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":True,"mutate_board":False}))')
    _enable(root, current)
    report = gate.authorize_card(conn, {"id": "current"})
    assert report["schema_version"] == "fellowship-authoritative-policy.v2"


def test_authoritative_policy_rejects_legacy_v1(board):
    conn, root = board
    legacy = _script(root, "policy-v1.py", 'import json;print(json.dumps({"schema_version":"fellowship-authoritative-policy.v1","authoritative":True,"dispatch_allowed":True,"mutate_board":False}))')
    _enable(root, legacy)
    with pytest.raises(gate.JevAuthorizationError, match="explicit non-mutating allow"):
        gate.authorize_card(conn, {"id": "legacy"})


def test_doc_budget_manifest_constructs_exact_atomic_graph_and_blocked_preflight(board):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    import hashlib
    conn,root=board
    script=_script(root,"budget-allow.py",'''import json,sys
if sys.argv[1]=="validate-pipeline":
 manifest=json.load(open(sys.argv[2])); cards=manifest["cards"]
 allow=(len(cards)==2 and cards[0]["doc_budget_bytes"]==20000 and
        cards[1]["stage"]=="operator_preflight" and cards[1]["initial_status"]=="blocked")
 print(json.dumps({"schema_version":"fellowship-pipeline-preflight.v1","ok":allow,"mutate_board":False}))
 sys.exit(0 if allow else 2)
card=json.load(open(sys.argv[2])); allow=card["status"] in ("ready","blocked")
print(json.dumps({"schema_version":"fellowship-authoritative-policy.v2","authoritative":True,"dispatch_allowed":allow,"mutate_board":False}))
sys.exit(0 if allow else 2)
''')
    _enable(root,script)
    cards=[{"key":"requirements","stage":"requirements","title":"requirements","body":"bounded","assignee":"worker","parents":[],"doc_budget_bytes":20000},
           {"key":"preflight","stage":"operator_preflight","title":"preflight","body":"stop","assignee":"operator","parents":["requirements"],"initial_status":"blocked"}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-budget","cards":cards}
    frozen=json.loads(json.dumps(manifest)); expected_sha=hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    mapping=pipeline.create_pipeline(conn,manifest,cards)
    assert manifest==frozen and cards==frozen["cards"]
    assert set(mapping)=={"requirements","preflight"}
    assert kb.get_task(conn,mapping["preflight"]).status=="blocked"
    assert tuple(conn.execute("SELECT parent_id,child_id FROM task_links").fetchone())==(mapping["requirements"],mapping["preflight"])
    row=conn.execute("SELECT manifest_sha256,mapping_json FROM jev_pipeline_publications WHERE feature_id=?",("F-budget",)).fetchone()
    assert row["manifest_sha256"]==expected_sha and json.loads(row["mapping_json"])==mapping
    assert pipeline.create_pipeline(conn,manifest,cards)==mapping
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==2



def test_pipeline_preserves_jev_only_implementation_metadata_without_task_kwargs(board, monkeypatch):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn, _ = board
    seen = []
    monkeypatch.setattr(pipeline, "authorize_pipeline", lambda _conn, manifest: seen.append(manifest) or {"ok": True})
    monkeypatch.setattr(gate, "authorize_card", lambda *_: {"dispatch_allowed": True})
    cards = [
        {"key": "requirements", "stage": "requirements", "title": "requirements", "body": "bounded", "parents": [], "doc_budget_bytes": 20000},
        {"key": "implementation", "stage": "implementation", "title": "implementation", "body": "test-first", "parents": ["requirements"],
         "functional_piece": "catalog persistence and administrator API", "required_tests": ["unique SKU and stock invariant"]},
    ]
    manifest = {"schema_version": "fellowship-pipeline.v1", "feature_id": "F-metadata", "cards": cards}
    mapping = pipeline.create_pipeline(conn, manifest, cards)
    assert seen == [manifest]
    assert set(mapping) == {"requirements", "implementation"}
    assert conn.execute("SELECT COUNT(*) FROM jev_pipeline_publications WHERE feature_id='F-metadata'").fetchone()[0] == 1
    assert kb.get_task(conn, mapping["implementation"]).title == "implementation"


def test_pipeline_rejects_unexpected_card_fields_before_jev_or_write(board,monkeypatch):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,_=board
    seen=[]
    monkeypatch.setattr(pipeline,"authorize_pipeline",lambda *args: seen.append("gate"))
    cards=[{"key":"one","stage":"requirements","title":"one","parents":[],"unexpected_policy_bypass":True}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-unknown","cards":cards}
    with pytest.raises(pipeline.PipelineConstructionError,match="unexpected"):
        pipeline.create_pipeline(conn,manifest,cards)
    assert not seen
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0
    assert conn.execute("SELECT COUNT(*) FROM jev_pipeline_publications").fetchone()[0]==0


def test_pipeline_rejects_changed_doc_budget_before_jev_or_write(board,monkeypatch):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,_=board;seen=[]
    monkeypatch.setattr(pipeline,"authorize_pipeline",lambda *args: seen.append("gate"))
    cards=[{"key":"one","stage":"requirements","title":"one","parents":[],"doc_budget_bytes":20000}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-budget-mismatch","cards":json.loads(json.dumps(cards))}
    cards[0]["doc_budget_bytes"]=19999
    with pytest.raises(pipeline.PipelineConstructionError,match="exactly match"):
        pipeline.create_pipeline(conn,manifest,cards)
    assert not seen
    assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]==0


def test_pipeline_failed_second_write_rolls_back_cards_edges_and_publication(board,monkeypatch):
    from hermes_cli import kanban_pipeline_mutation as pipeline
    conn,_=board
    monkeypatch.setattr(pipeline,"authorize_pipeline",lambda *args:{"ok":True})
    monkeypatch.setattr(gate,"authorize_card",lambda *args:{"dispatch_allowed":True})
    original=kb.create_task
    written=[]
    def fail_second(*args,**kwargs):
        if not kwargs.get("_preview_only"):
            written.append(kwargs["title"])
            if len(written)==2: raise RuntimeError("interrupted write")
        return original(*args,**kwargs)
    monkeypatch.setattr(kb,"create_task",fail_second)
    cards=[{"key":"one","stage":"requirements","title":"one","parents":[]},
           {"key":"two","stage":"architecture","title":"two","parents":["one"]}]
    manifest={"schema_version":"fellowship-pipeline.v1","feature_id":"F-rollback","cards":cards}
    with pytest.raises(RuntimeError,match="interrupted write"):
        pipeline.create_pipeline(conn,manifest,cards)
    assert written==["one","two"]
    for table in ("tasks","task_links","jev_pipeline_publications"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]==0


def _valid_jev_closure_evidence(name="closure.md"):
    candidate = "a" * 40
    merge = "b" * 40
    return {
        "schema_version": "fellowship-closure.v1", "feature_id": "F-123",
        "closure_document": name, "max_words": 100, "candidate_sha": candidate,
        "files": ["src/example.py"],
        "required_checks": [{"name": "test", "conclusion": "SUCCESS", "sha": candidate}],
        "reviews": [
            {"kind": kind, "verdict": verdict, "sha": candidate, "reviewer": kind, "author": "builder"}
            for kind, verdict in (("security", "APPROVE"), ("qa", "PASS"))
        ],
        "merge": {"head_sha": candidate, "merge_sha": merge, "verified_content_equal": True},
        "deployment": {"id": "deployment-1", "commit_sha": merge},
        "acceptance": [
            {"kind": kind, "verdict": "PASS", "deployment_id": "deployment-1", "commit_sha": merge}
            for kind in ("acceptance", "reliability")
        ],
        "findings": [],
    }


def test_real_jev_closure_publication_preserves_document_basename(board, monkeypatch):
    """Exercise the installed validator, not a canned allow report, on a disposable board."""
    from hermes_cli.kanban_closure_mutation import publish_closure
    conn, root = board
    evaluator = Path("/usr/local/bin/fellowship-jev")
    sandbox = Path("/usr/bin/bwrap")
    if not evaluator.is_file() or not sandbox.is_file():
        pytest.skip("trusted JEV evaluator and sandbox not installed")
    task = kb.create_task(conn, title="closure")
    with kb.write_txn(conn):
        kb._append_event(conn, task, "pipeline_stage", {"stage": "closure_merge", "feature_id": "F-123"})
    (root / "board.json").write_text(json.dumps({"jev_mutation_gate": {"enabled": True}}))
    monkeypatch.setattr(gate, "_trusted_command", lambda: [str(evaluator)])
    document = root / "closure.md"
    content = b"Slice: F-123\nPRD: product requirements\nClosure approved.\n"
    document.write_bytes(content)
    evidence = _valid_jev_closure_evidence()
    assert publish_closure(conn, task, evidence=evidence, document=document, result="published")
    row = conn.execute("SELECT evidence_json, document_bytes FROM task_closure_publications WHERE task_id=?", (task,)).fetchone()
    assert json.loads(row["evidence_json"]) == evidence
    assert bytes(row["document_bytes"]) == content
    assert kb.get_task(conn, task).status == "done"


@pytest.mark.parametrize("name", ["../escape.md", "/tmp/escape.md", "dir/closure.md", "dir\\closure.md", "..", ".", "evidence.json", "", None, 42, "bad\x00name.md", " a.md", "a.md "])
def test_closure_rejects_unsafe_evidence_document_name_before_staging(board, monkeypatch, name):
    conn, root = board
    (root / "board.json").write_text(json.dumps({"jev_mutation_gate": {"enabled": True}}))
    monkeypatch.setattr(gate, "_execute", lambda *_: pytest.fail("unsafe name reached filesystem staging"))
    with pytest.raises(gate.JevAuthorizationError, match="closure document name"):
        gate.authorize_closure(conn, {"closure_document": name}, b"content")


def test_closure_rejects_evidence_name_different_from_supplied_document(board, monkeypatch):
    from hermes_cli.kanban_closure_mutation import publish_closure
    conn, root = board
    task = kb.create_task(conn, title="closure")
    with kb.write_txn(conn):
        kb._append_event(conn, task, "pipeline_stage", {"stage": "closure_merge", "feature_id": "F-123"})
    document = root / "different.md"
    document.write_bytes(b"content")
    (root / "board.json").write_text(json.dumps({"jev_mutation_gate": {"enabled": True}}))
    monkeypatch.setattr(gate, "_execute", lambda *_: pytest.fail("mismatched name reached evaluator"))
    with pytest.raises(gate.JevAuthorizationError, match="closure document name"):
        publish_closure(conn, task, evidence={"feature_id": "F-123", "closure_document": "closure.md"}, document=document)
    assert kb.get_task(conn, task).status != "done"
