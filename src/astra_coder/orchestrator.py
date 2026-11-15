"""End-to-end bounded Plan → Act → Observe → Verify → Review orchestration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel

from .agents import (
    ArchitectAgent,
    EditorAgent,
    IndependentReviewerAgent,
    Plan,
    ReviewResult,
    VerificationEvidence,
)
from .runtime import TERMINAL_STATES, Task, TaskState, TaskStateMachine
from .tools import ToolMesh
from .verification import VerificationEngine, VerificationSummary


class OrchestrationBlocked(RuntimeError):
    """The orchestrator refused to run without required approval/evidence."""


class OrchestrationResult(BaseModel):
    task: Task
    plan: Plan | None = None
    verification: VerificationSummary | None = None
    review: ReviewResult | None = None


RepairHook = Callable[[Task, VerificationSummary], bool]
ToolMeshFactory = Callable[[Path], ToolMesh]
WorkspaceGuard = Callable[[Task, Path], None]
BoundaryGuard = Callable[[Task], None]


class TaskOrchestrator:
    """Single-writer orchestration with no model-controlled success transition."""

    def __init__(
        self,
        architect: ArchitectAgent,
        editor: EditorAgent,
        reviewer: IndependentReviewerAgent,
        verifier: VerificationEngine,
        *,
        repair_hook: RepairHook | None = None,
        tool_mesh_factory: ToolMeshFactory | None = None,
        workspace_guard: WorkspaceGuard | None = None,
        boundary_guard: BoundaryGuard | None = None,
    ) -> None:
        self.architect = architect
        self.editor = editor
        self.reviewer = reviewer
        self.verifier = verifier
        self.repair_hook = repair_hook
        self._tool_mesh_factory = tool_mesh_factory or ToolMesh
        self._workspace_guard = workspace_guard
        self._boundary_guard = boundary_guard

    def run(
        self, task: Task, context: str, workspace: str | Path | None = None
    ) -> OrchestrationResult:
        if task.state in TERMINAL_STATES:
            return OrchestrationResult(task=task)
        if task.state is TaskState.AWAITING_APPROVAL:
            raise OrchestrationBlocked("task requires human approval before execution")
        if task.state is not TaskState.CONTEXT_BUILT:
            raise OrchestrationBlocked(
                "task must be policy-checked, approved, and context-built before execution"
            )
        root = Path(workspace or task.repo_path).resolve()
        if self._workspace_guard is not None:
            self._workspace_guard(task, root)
        else:
            approved_root = Path(task.repo_path).resolve()
            try:
                root.relative_to(approved_root)
            except ValueError as exc:
                raise OrchestrationBlocked(
                    "execution workspace is outside the task repository scope"
                ) from exc
        plan: Plan | None = None
        summary: VerificationSummary | None = None
        review: ReviewResult | None = None
        try:
            if self._boundary_guard is not None:
                self._boundary_guard(task)
            plan = self.architect.plan(task, context)
            TaskStateMachine.transition(task, TaskState.PLANNED)
            if plan.requires_approval:
                raise OrchestrationBlocked("plan requires approval before edits")
            TaskStateMachine.transition(task, TaskState.EDITING)
            while True:
                if self._boundary_guard is not None:
                    self._boundary_guard(task)
                edit = self.editor.apply(plan, self._tool_mesh_factory(root))
                if not edit.ok:
                    return OrchestrationResult(
                        task=TaskStateMachine.fail(task, edit.error or "edit failed"), plan=plan
                    )
                TaskStateMachine.transition(task, TaskState.OBSERVING)
                TaskStateMachine.transition(task, TaskState.VERIFYING)
                if self._boundary_guard is not None:
                    self._boundary_guard(task)
                summary = self.verifier.run(root)
                if self._boundary_guard is not None:
                    self._boundary_guard(task)
                if summary.passed:
                    break
                if task.repairs >= task.limits.max_repairs or self.repair_hook is None:
                    return OrchestrationResult(
                        task=TaskStateMachine.fail(task, "independent verification failed"),
                        plan=plan,
                        verification=summary,
                    )
                TaskStateMachine.transition(task, TaskState.REPAIRING)
                task.repairs += 1
                if not self.repair_hook(task, summary):
                    return OrchestrationResult(
                        task=TaskStateMachine.fail(task, "bounded repair failed"),
                        plan=plan,
                        verification=summary,
                    )
                TaskStateMachine.transition(task, TaskState.EDITING)
            TaskStateMachine.transition(task, TaskState.REVIEWING)
            review = self.reviewer.review(
                VerificationEvidence(
                    required_gates_run=True,
                    all_gates_passed=summary.passed,
                    diff_within_workspace=True,
                    evidence_hash=summary.evidence_hash,
                )
            )
            if not review.accepted:
                return OrchestrationResult(
                    task=TaskStateMachine.fail(task, review.reason),
                    plan=plan,
                    verification=summary,
                    review=review,
                )
            if self._boundary_guard is not None:
                self._boundary_guard(task)
            TaskStateMachine.transition(task, TaskState.SUCCEEDED)
            return OrchestrationResult(task=task, plan=plan, verification=summary, review=review)
        except OrchestrationBlocked:
            raise
        except Exception as exc:
            TaskStateMachine.fail(task, f"orchestration failed closed: {exc}")
            return OrchestrationResult(task=task, plan=plan, verification=summary, review=review)
