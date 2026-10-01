"""The lab integration branch has a bounded CI gate, never a main waiver."""
from pathlib import Path
import re
import pytest

ROOT = Path(__file__).resolve().parents[1] / ".github" / "workflows"

@pytest.mark.parametrize("name", ["ci.yaml", "docker.yml", "nix.yml"])
def test_broad_workflows_exclude_only_lab_main_pull_requests(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    assert re.search(r"(?m)^  pull_request:\n    branches-ignore: \[lab/main\]$", text)
    assert re.search(r"(?m)^  push:\n    branches: \[main\]$", text)
    assert re.search(r"(?m)^  workflow_call:$", text)


def test_lab_main_controls_have_a_real_standard_runner_gate():
    path = ROOT / "lab-main-controls.yml"
    text = path.read_text(encoding="utf-8")
    assert re.search(r"(?m)^  pull_request:\n    branches: \[lab/main\]$", text)
    assert text.count("\n  controls:\n") == 1
    assert re.search(r"(?m)^    runs-on: ubuntu-latest$", text)
    assert "uses: ./.github/actions/setup-pm" in text
    assert "test-environment: 'true'" in text
    for required in ("test_kanban_f003_preflight.py", "test_kanban_f003_operator_seam.py",
                     "test_kanban_triage_resolution.py", "test_kanban_verified_archive.py",
                     "test_kanban_jev_gate.py", "test_kanban_boards.py",
                     "test_kanban_tools.py", "test_managed_runtime_resolution.py",
                     "test_lab_main_ci_contract.py", "check-windows-footguns.py", "check_no_tmp_literals.py"):
        assert required in text
    assert "continue-on-error" not in text
    assert "secrets:" not in text
