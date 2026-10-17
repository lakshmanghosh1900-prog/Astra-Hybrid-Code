"""Application service coordinating task intake, policy, state, and audit."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from .git_safety import GitSafety, GitSafetyError
from .persistence import AuditEvent, AuditLog, StateStore
from .policy import Action, Actor, PolicyDenied, PolicyEngine
from .runtime import RiskTier, Task, TaskState, TaskStateMachine


class ServiceError(RuntimeError):
    """A user-visible service operation failed."""


class SubmitRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=100_000)
    repo_path: str = Field(min_length=1, max_length=4_096)
    risk: RiskTier = RiskTier.T1


class TaskService:
    def __init__(
        self,
        store: StateStore,
        policy: PolicyEngine,
        audit: AuditLog | None = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.audit = audit or AuditLog(store)

    def submit(self, actor: Actor, request: SubmitRequest) -> Task:
        task = Task(prompt=request.prompt, repo_path=request.repo_path, risk=request.risk)
        decision = self.policy.evaluate(
            actor, Action.EDIT, request.risk, str(task.id), touched_paths=[request.repo_path]
        )
        if not decision.allowed and not decision.approval_required:
            raise ServiceError(decision.reason)
        TaskStateMachine.transition(task, TaskState.POLICY_CHECKED)
        if decision.approval_required:
            TaskStateMachine.transition(task, TaskState.AWAITING_APPROVAL)
        self.store.save_task(task)
        self.audit.append(
            actor=actor.actor_id,
            action="submit",
            target=str(task.id),
            decision="approval_required" if decision.approval_required else "accepted",
            metadata={"risk": task.risk.value, "repo_path": task.repo_path},
        )
        return task

    def list(self) -> tuple[Task, ...]:
        return self.store.list_tasks()

    def get(self, task_id: UUID | str) -> Task:
        task = self.store.get_task(task_id)
        if task is None:
            raise ServiceError("task not found")
        return task

    def approve(self, actor: Actor, task_id: UUID | str) -> Task:
        task = self.get(task_id)
        try:
            self.policy.approve(str(task.id), actor)
            decision = self.policy.evaluate(actor, Action.APPROVE, task.risk, str(task.id))
            if not decision.allowed:
                raise ServiceError(decision.reason)
            if task.state is TaskState.AWAITING_APPROVAL:
                TaskStateMachine.transition(task, TaskState.CONTEXT_BUILT)
            self.store.save_task(task)
            self.audit.append(actor.actor_id, "approve", str(task.id), "accepted")
            return task
        except PolicyDenied as exc:
            raise ServiceError(str(exc)) from exc

    def deny(self, actor: Actor, task_id: UUID | str, reason: str) -> Task:
        task = self.get(task_id)
        try:
            self.policy.deny(str(task.id), actor)
        except PolicyDenied as exc:
            raise ServiceError(str(exc)) from exc
        if task.state not in {
            TaskState.SUCCEEDED,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.BLOCKED,
        }:
            TaskStateMachine.transition(task, TaskState.BLOCKED)
        task.failure_reason = reason[:2_000]
        self.store.save_task(task)
        self.audit.append(actor.actor_id, "deny", str(task.id), "blocked", {"reason": reason[:500]})
        return task

    def cancel(self, actor: Actor, task_id: UUID | str) -> Task:
        task = self.get(task_id)
        decision = self.policy.evaluate(actor, Action.CANCEL, task.risk, str(task.id))
        if not decision.allowed:
            raise ServiceError(decision.reason)
        if task.state not in {
            TaskState.SUCCEEDED,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.BLOCKED,
        }:
            TaskStateMachine.transition(task, TaskState.CANCELLED)
        task.failure_reason = "cancelled by operator"
        self.store.save_task(task)
        self.audit.append(actor.actor_id, "cancel", str(task.id), "cancelled")
        return task

    def diff(self, task_id: UUID | str) -> str:
        task = self.get(task_id)
        try:
            return GitSafety(task.repo_path).status_porcelain()
        except (GitSafetyError, OSError):
            return ""

    def events(self, task_id: UUID | str) -> tuple[AuditEvent, ...]:
        self.get(task_id)
        return self.audit.replay(str(task_id))
