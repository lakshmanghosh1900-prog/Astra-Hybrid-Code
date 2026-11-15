import json

import pytest

from astra_coder.runtime import Task
from astra_coder.tools import ToolError
from astra_coder.worker_main import configured_gates, main, structured_plan


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
