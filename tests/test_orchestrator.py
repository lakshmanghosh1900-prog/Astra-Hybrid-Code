from collections.abc import Sequence
from pathlib import Path

from astra_coder.agents import (
    ArchitectAgent,
    EditorAgent,
    IndependentReviewerAgent,
    Plan,
    PlanAction,
)
from astra_coder.orchestrator import OrchestrationBlocked, TaskOrchestrator
from astra_coder.runtime import Task, TaskLimits, TaskState
from astra_coder.verification import GateName, GateSpec, ProcessResult, VerificationEngine


class PassingRunner:
    def run(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ProcessResult:
        del argv, cwd, timeout_seconds
        return ProcessResult(exit_code=0, stdout="pass")


def orchestrator() -> TaskOrchestrator:
    architect = ArchitectAgent(
        lambda _task, _context: Plan(
            goal="write fixture",
            steps=(
                PlanAction(tool="write_patch", payload={"path": "generated.txt", "content": "ok"}),
            ),
        )
    )
    verifier = VerificationEngine(
        PassingRunner(), (GateSpec(name=GateName.TESTS, argv=("fixture",)),)
    )
    return TaskOrchestrator(architect, EditorAgent(), IndependentReviewerAgent(), verifier)


def test_orchestrator_requires_approval() -> None:
    task = Task(prompt="high risk", repo_path=".", state=TaskState.AWAITING_APPROVAL)
    try:
        orchestrator().run(task, "safe", Path.cwd())
    except OrchestrationBlocked as exc:
        assert "approval" in str(exc)
    else:
        raise AssertionError("approval gate was bypassed")


def test_orchestrator_rejects_unchecked_tasks(tmp_path: Path) -> None:
    for state in (TaskState.RECEIVED, TaskState.POLICY_CHECKED):
        task = Task(prompt="write", repo_path=str(tmp_path), state=state)
        try:
            orchestrator().run(task, "safe context", tmp_path)
        except OrchestrationBlocked as exc:
            assert "context-built" in str(exc)
        else:
            raise AssertionError(f"orchestrator accepted task in {state} state")


def test_orchestrator_completes_only_with_independent_evidence(tmp_path: Path) -> None:
    task = Task(
        prompt="write",
        repo_path=str(tmp_path),
        state=TaskState.CONTEXT_BUILT,
        limits=TaskLimits(max_repairs=0),
    )
    result = orchestrator().run(task, "safe context", tmp_path)
    assert result.task.state is TaskState.SUCCEEDED
    assert result.verification is not None and result.verification.passed
    assert result.review is not None and result.review.accepted
    assert (tmp_path / "generated.txt").read_text(encoding="utf-8") == "ok"


def test_orchestrator_never_succeeds_when_gate_unavailable(tmp_path: Path) -> None:
    architect = ArchitectAgent(
        lambda _task, _context: Plan(
            goal="write",
            steps=(PlanAction(tool="write_patch", payload={"path": "a.txt", "content": "a"}),),
        )
    )
    verifier = VerificationEngine(gates=(GateSpec(name=GateName.TESTS, argv=("test",)),))
    task = Task(
        prompt="write",
        repo_path=str(tmp_path),
        state=TaskState.CONTEXT_BUILT,
        limits=TaskLimits(max_repairs=0),
    )
    result = TaskOrchestrator(architect, EditorAgent(), IndependentReviewerAgent(), verifier).run(
        task, "safe", tmp_path
    )
    assert result.task.state is TaskState.FAILED
    assert result.verification is not None and not result.verification.passed


def test_orchestrator_rejects_workspace_outside_task_scope(tmp_path: Path) -> None:
    task_root = tmp_path / "repo"
    task_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    task = Task(prompt="write", repo_path=str(task_root), state=TaskState.CONTEXT_BUILT)
    try:
        orchestrator().run(task, "safe", outside)
    except OrchestrationBlocked as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("orchestrator accepted an outside workspace")
