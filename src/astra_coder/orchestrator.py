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
    ) -> None:
        self.architect = architect
        self.editor = editor
        self.reviewer = reviewer
        self.verifier = verifier
        self.repair_hook = repair_hook

    def run(
        self, task: Task, context: str, workspace: str | Path | None = None
    ) -> OrchestrationResult:
        if task.state in TERMINAL_STATES:
            return OrchestrationResult(task=task)
        if task.state is TaskState.AWAITING_APPROVAL:
            raise OrchestrationBlocked("task requires human approval before execution")
        root = Path(workspace or task.repo_path).resolve()
        plan: Plan | None = None
        summary: VerificationSummary | None = None
        review: ReviewResult | None = None
        try:
            if task.state is TaskState.RECEIVED:
                TaskStateMachine.transition(task, TaskState.POLICY_CHECKED)
            if task.state is TaskState.POLICY_CHECKED:
                TaskStateMachine.transition(task, TaskState.CONTEXT_BUILT)
            plan = self.architect.plan(task, context)
            TaskStateMachine.transition(task, TaskState.PLANNED)
            if plan.requires_approval:
                raise OrchestrationBlocked("plan requires approval before edits")
            TaskStateMachine.transition(task, TaskState.EDITING)
            while True:
                edit = self.editor.apply(plan, ToolMesh(root))
                if not edit.ok:
                    return OrchestrationResult(
                        task=TaskStateMachine.fail(task, edit.error or "edit failed"), plan=plan
                    )
                TaskStateMachine.transition(task, TaskState.OBSERVING)
                TaskStateMachine.transition(task, TaskState.VERIFYING)
                summary = self.verifier.run(root)
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
            TaskStateMachine.transition(task, TaskState.SUCCEEDED)
            return OrchestrationResult(task=task, plan=plan, verification=summary, review=review)
        except OrchestrationBlocked:
            raise
        except Exception as exc:
            TaskStateMachine.fail(task, f"orchestration failed closed: {exc}")
            return OrchestrationResult(task=task, plan=plan, verification=summary, review=review)
