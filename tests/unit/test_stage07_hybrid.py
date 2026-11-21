import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from astra_coder import hybrid_skill as skill
from astra_coder.hybrid_roles import HybridRoleAdapter


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "sample.txt").write_bytes(b"old\n")
    plan = skill.ExecutionPlan(
        plan_id="p1",
        role="GPT_BRAINING_PLANNER",
        read_only=True,
        requires_rea_gate=True,
        risk_checks=["bounded"],
        allowed_target_paths=["sample.txt"],
        excluded_paths=[],
        steps=[skill.Step(step_id="s1", description="edit", target_path="sample.txt")],
    )
    diff = "--- a/sample.txt\n+++ b/sample.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    request = skill.PatchRequest(
        role="CODEX_CODER",
        plan_id="p1",
        plan_sha256=skill.plan_digest(plan),
        step_id="s1",
        diff_sha256=hashlib.sha256(diff.encode()).hexdigest(),
        diff=diff,
        rea_skill_binding=skill.SkillBinding(skill=skill.SKILL, gate="rea-gate", fail_closed=True),
    )
    monkeypatch.setattr(skill, "require_stage05b_execution", Mock(return_value=Mock(allowed=True)))
    return dict(
        repo_root=root,
        plan=plan,
        request=request,
        approved_plan_sha256=skill.plan_digest(plan),
        actor_id="executor",
        approver_id="human",
        audit_log=tmp_path / "audit.json",
    )


def test_allowed(case: dict) -> None:
    skill.execute_patch(**case)
    assert (case["repo_root"] / "sample.txt").read_bytes() == b"new\n"
    events = json.loads(case["audit_log"].read_text())["events"]
    assert skill.append_audit_event is not None
    assert events[0]["event_type"] == "STAGE07_PATCH_INTENT"


@pytest.mark.parametrize("failure", ["approval", "hash", "gate", "audit", "diff", "step"])
def test_denies(case: dict, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    if failure == "approval":
        case["approved_plan_sha256"] = "0" * 64
    elif failure == "hash":
        case["request"] = case["request"].model_copy(update={"plan_sha256": "0" * 64})
    elif failure == "gate":
        monkeypatch.setattr(
            skill,
            "require_stage05b_execution",
            Mock(return_value=Mock(allowed=False, blocking_reasons=["denied"])),
        )
    elif failure == "audit":
        monkeypatch.setattr(skill, "append_audit_event", Mock(side_effect=OSError("disk")))
    elif failure == "diff":
        case["request"] = case["request"].model_copy(update={"diff_sha256": "0" * 64})
    else:
        case["request"] = case["request"].model_copy(update={"step_id": "unknown"})
    with pytest.raises((ValueError, PermissionError, OSError)):
        skill.execute_patch(**case)
    assert (case["repo_root"] / "sample.txt").read_bytes() == b"old\n"


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "C:\\astramind-dev\\x",
        "authorization.json",
        "src/astra_coder/rea/gate.py",
        "sample.txt",
    ],
)
def test_paths(case: dict, name: str) -> None:
    plan = case["plan"].model_copy(
        update={
            "allowed_target_paths": [name],
            "excluded_paths": ["sample.txt"],
            "steps": [skill.Step(step_id="s1", description="edit", target_path=name)],
        }
    )
    case["plan"] = plan
    case["approved_plan_sha256"] = skill.plan_digest(plan)
    case["request"] = case["request"].model_copy(update={"plan_sha256": skill.plan_digest(plan)})
    with pytest.raises(ValueError):
        skill.execute_patch(**case)


def test_role_adapter(case: dict) -> None:
    adapter = HybridRoleAdapter(
        lambda _: case["plan"].model_dump_json(), lambda _: case["request"].model_dump_json()
    )
    assert adapter.plan("plan") == case["plan"]
    assert adapter.patch("patch", "CODEX_CODER") == case["request"]
    with pytest.raises(ValueError):
        adapter.patch("patch", "CLAUDE_CODER")
