"""The lab integration branch has a bounded CI gate, never a main waiver."""
from pathlib import Path
import pytest
import hermes_yaml

ROOT = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _events(text: str) -> dict:
    workflow = hermes_yaml.safe_load(text)
    # The shared parser uses YAML 1.1, where a bare `on` is the key True.
    return workflow[True]


@pytest.mark.parametrize("name", ["ci.yaml", "docker.yml", "nix.yml"])
def test_broad_workflows_exclude_only_lab_main_pull_requests(name):
    events = _events((ROOT / name).read_text(encoding="utf-8"))
    assert events["pull_request"] == {"branches-ignore": ["lab/main"]}
    assert events["push"] == {"branches": ["main"]}
    assert "workflow_call" in events


@pytest.mark.parametrize("name", ["ci.yaml", "docker.yml", "nix.yml", "lab-main-controls.yml"])
def test_extra_pr_path_filter_would_be_rejected(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    marker = "    branches: [lab/main]" if name == "lab-main-controls.yml" else "    branches-ignore: [lab/main]"
    assert text.count(marker) == 1
    mutated = text.replace(marker, marker + "\n    paths: ['docs/**']", 1)
    expected = {"branches": ["lab/main"]} if name == "lab-main-controls.yml" else {"branches-ignore": ["lab/main"]}
    assert _events(mutated)["pull_request"] != expected


def test_lab_main_controls_have_a_real_standard_runner_gate():
    path = ROOT / "lab-main-controls.yml"
    text = path.read_text(encoding="utf-8")
    workflow = hermes_yaml.safe_load(text)
    assert _events(text) == {"pull_request": {"branches": ["lab/main"]}}
    assert workflow["permissions"] == {"contents": "read"}
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
    assert "continue-on-error" not in text
    assert "secrets:" not in text
