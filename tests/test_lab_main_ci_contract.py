"""The lab integration branch has a bounded CI gate, never a main-branch waiver."""
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / ".github" / "workflows"

@pytest.mark.parametrize("name", ["ci.yaml", "docker.yml", "nix.yml"])
def test_broad_workflows_exclude_only_lab_main_pull_requests(name):
    workflow = yaml.load((ROOT / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert workflow["on"]["pull_request"] == {"branches-ignore": ["lab/main"]}
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert "workflow_call" in workflow["on"] if name != "ci.yaml" else "workflow_dispatch" in workflow["on"]


def test_lab_main_controls_have_a_real_standard_runner_gate():
    path = ROOT / "lab-main-controls.yml"
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert workflow["on"]["pull_request"]["branches"] == ["lab/main"]
    assert len(workflow["jobs"]) == 1
    job = next(iter(workflow["jobs"].values()))
    assert job["runs-on"] == "ubuntu-latest"
    steps = job["steps"]
    assert any("setup-pm" in x.get("uses", "") and x.get("with", {}).get("test-environment") == "true" for x in steps)
    commands = "\n".join(x.get("run", "") for x in steps)
    for required in ("test_kanban_f003_preflight.py", "test_kanban_f003_operator_seam.py",
                     "test_kanban_triage_resolution.py", "test_kanban_verified_archive.py",
                     "test_kanban_jev_gate.py", "test_kanban_boards.py",
                     "test_kanban_tools.py", "test_managed_runtime_resolution.py",
                     "test_lab_main_ci_contract.py", "check-windows-footguns.py", "check_no_tmp_literals.py"):
        assert required in commands
    assert "continue-on-error" not in path.read_text(encoding="utf-8")
    assert "secrets:" not in path.read_text(encoding="utf-8")
