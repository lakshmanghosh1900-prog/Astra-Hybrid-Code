import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from astra_coder.runtime import Task
from astra_coder.tools import ToolError
from astra_coder.worker_main import configured_gates, main, structured_plan


def load_smoke_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "worker_smoke.py"
    spec = importlib.util.spec_from_file_location("worker_smoke", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_worker_refuses_implicit_enablement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASTRA_WORKER_ENABLED", raising=False)
    with pytest.raises(RuntimeError, match="disabled"):
        main()


def test_structured_plan_is_not_a_model_success_claim() -> None:
    task = Task(
        repo_path=".",
        prompt=json.dumps(
            {
                "goal": "write",
                "steps": [
                    {"tool": "write_patch", "payload": {"path": "file.py", "content": "x = 1\n"}}
                ],
            }
        ),
    )
    assert structured_plan(task, "").steps[0].tool == "write_patch"
    task.prompt = "I executed it successfully"
    with pytest.raises(ValueError):
        structured_plan(task, "")


def test_worker_rejects_unsafe_plan_paths() -> None:
    task = Task(
        repo_path=".",
        prompt=json.dumps(
            {
                "goal": "write",
                "steps": [
                    {"tool": "write_patch", "payload": {"path": "../escape.py", "content": "bad"}}
                ],
            }
        ),
    )
    with pytest.raises(ToolError, match="relative"):
        structured_plan(task, "")


def test_worker_never_accepts_an_empty_verification_profile() -> None:
    with pytest.raises(ValueError, match="nonempty"):
        configured_gates("[]")
    assert len(configured_gates(None)) == 5


def test_smoke_profiles_select_three_or_five_named_gates() -> None:
    smoke = load_smoke_module()
    assert [gate["name"] for gate in smoke.profile_gates("demo")] == [
        "tests",
        "lint",
        "typecheck",
    ]
    assert [gate["name"] for gate in smoke.profile_gates("full")] == [
        "tests",
        "lint",
        "typecheck",
        "semgrep",
        "gitleaks",
    ]


def test_demo_default_still_writes_protected_report_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    smoke = load_smoke_module()
    monkeypatch.setattr("sys.argv", ["worker_smoke.py"])
    assert smoke.parse_args().profile == "demo"
    assert smoke.report_path(tmp_path, "demo").name == "worker-smoke.json"
    assert smoke.report_path(tmp_path, "full").name == "worker-smoke-security.json"


def test_full_report_records_tool_versions_and_config_hashes(tmp_path: Path) -> None:
    smoke = load_smoke_module()
    for name in smoke.SCANNER_CONFIG_FILES:
        (tmp_path / name).write_text(name, encoding="utf-8")
    evidence = smoke.scanner_evidence(tmp_path, {"semgrep": "1.181.0", "gitleaks": "v8.30.1"})
    assert evidence["included"] is True
    assert evidence["gates"] == ["semgrep", "gitleaks"]
    assert evidence["tool_versions"] == {"semgrep": "1.181.0", "gitleaks": "v8.30.1"}
    assert (
        evidence["config_hashes"][".gitleaksignore"]
        == hashlib.sha256(b".gitleaksignore").hexdigest()
    )
