"""The lab fork must not queue required CI forever on upstream-only runners."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1] / ".github" / "workflows"
FORK = "github.repository == 'saltybaker-org/hermes-agent'"
REQUIRED = (
    "tests.yml", "tests-os.yml", "js-tests.yml", "rust-tests.yml",
    "e2e-desktop.yml", "e2e-desktop-core.yml", "e2e-desktop-update.yml",
    "windows-install-update-e2e.yml", "nix.yml",
)


def test_required_workflows_have_fork_runner_fallback():
    for name in REQUIRED:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert FORK in text, name
        assert "runs-on: ubuntu-latest-32-core" not in text, name
        assert "runs-on: ubuntu-latest-96-core" not in text, name
        assert "runs-on: windows-latest-32-core" not in text, name


def test_fork_full_suite_is_sliced_and_bounded():
    text = (ROOT / "tests.yml").read_text(encoding="utf-8")
    assert "HERMES_TEST_SLICE: ${{ matrix.slice }}" in text
    assert "HERMES_TEST_WORKERS: ${{" in text
    match = re.search(r"slice: \$\{\{ fromJSON\(.*?&& '(\[[^']+\])' \|\|", text)
    assert match, "fork matrix must declare its slices"
    assert json.loads(match.group(1)) == [f"{i}/16" for i in range(1, 17)]
    assert "fail-fast: false" in text
