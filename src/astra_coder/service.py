"""Application service coordinating task intake, policy, state, and audit."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import BaseModel, Field

from .git_safety import GitSafety, GitSafetyError
from .persistence import AuditEvent, AuditLog, PersistenceError, StateStore, TaskScope
from .policy import Action, Actor, PolicyDenied, PolicyEngine, Role
from .runtime import TERMINAL_STATES, RiskTier, Task, TaskState, TaskStateMachine

if TYPE_CHECKING:
    from .gateway import ModelGateway


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
        gateway: ModelGateway | None = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.audit = audit or AuditLog(store)
        self.gateway = gateway
        self._sync_kill_switch()
        for approval in store.approvals():
            task = store.get_task(approval.task_id)
            scope = store.get_scope(approval.task_id)
            if (
                approval.active
                and task is not None
                and task.state not in TERMINAL_STATES
                and scope is not None
                and approval.spec_hash == scope.spec_hash
                and approval.scope_hash == scope.scope_hash
                and approval.policy_version == scope.policy_version
            ):
                try:
                    self._validated_scope(task)
                except ServiceError:
                    continue
                self.policy.restore_approval(
                    str(approval.task_id),
                    approval.approver,
                    approval.spec_hash,
                    approval.scope_hash,
                )

    @staticmethod
    def _spec_hash(task: Task) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "prompt": task.prompt,
                    "risk": task.risk.value,
                    "limits": task.limits.model_dump(mode="json"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    @staticmethod
    def _scope_hash(task: Task, base_revision: str) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "repo_path": str(Path(task.repo_path).resolve()),
                    "base_revision": base_revision,
                    "risk": task.risk.value,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def _validated_scope(self, task: Task) -> TaskScope:
        scope = self.store.get_scope(task.id)
        if scope is None:
            raise ServiceError("task execution scope is unavailable")
        try:
            repo_path = str(Path(task.repo_path).resolve())
            base_revision = GitSafety(repo_path).current_revision()
        except (GitSafetyError, OSError, RuntimeError) as exc:
            raise ServiceError("task repository scope is unavailable") from exc
        if (
            self._spec_hash(task) != scope.spec_hash
            or repo_path != scope.repo_path
            or base_revision != scope.base_revision
            or task.risk != scope.risk
            or self._scope_hash(task, base_revision) != scope.scope_hash
        ):
            raise ServiceError(
                "task specification or execution scope does not match persisted scope"
            )
        return scope

    def _sync_kill_switch(self) -> bool:
        enabled = self.store.get_kill_switch()
        self.policy.set_kill_switch(Actor(actor_id="state-store", role=Role.ADMIN), enabled)
        return enabled

    def get_kill_switch(self, actor: Actor) -> bool:
        if actor.role != Role.ADMIN:
            raise ServiceError("only an admin can read the kill switch")
        return self._sync_kill_switch()

    def set_kill_switch(self, actor: Actor, enabled: bool) -> bool:
        if actor.role != Role.ADMIN:
            raise ServiceError("only an admin can change the kill switch")
        self.store.set_kill_switch(enabled)
        self.policy.set_kill_switch(actor, enabled)
        self.audit.append(
            actor.actor_id, "set_kill_switch", "kill_switch", "enabled" if enabled else "disabled"
        )
        return enabled

    def submit(self, actor: Actor, request: SubmitRequest) -> Task:
        self._sync_kill_switch()
        task = Task(prompt=request.prompt, repo_path=request.repo_path, risk=request.risk)
        if not Path(request.repo_path).is_dir():
            raise ServiceError("repository root must be an existing directory")
        try:
            base_revision = GitSafety(request.repo_path).current_revision()
        except GitSafetyError as exc:
            raise ServiceError("repository root must be a Git repository with a HEAD") from exc
        decision = self.policy.evaluate(
            actor, Action.EDIT, request.risk, str(task.id), touched_paths=[request.repo_path]
        )
        if not decision.allowed and not decision.approval_required:
            raise ServiceError(decision.reason)
        TaskStateMachine.transition(task, TaskState.POLICY_CHECKED)
        if decision.approval_required:
            TaskStateMachine.transition(task, TaskState.AWAITING_APPROVAL)
        self.store.save_scope(
            TaskScope(
                task_id=task.id,
                spec_hash=self._spec_hash(task),
                scope_hash=self._scope_hash(task, base_revision),
                repo_path=str(Path(task.repo_path).resolve()),
                base_revision=base_revision,
                risk=task.risk,
                created_at=datetime.now(UTC),
            )
        )
        self.store.save_task(task)
        self.audit.append(
            actor=actor.actor_id,
            action="submit",
            target=str(task.id),
            decision="approval_required" if decision.approval_required else "accepted",
            metadata={"risk": task.risk.value, "repo_path": task.repo_path},
        )
        return task

    def list(self, actor: Actor) -> tuple[Task, ...]:
        tasks = self.store.list_tasks()
        for task in tasks:
            self._read_decision(actor, task)
        return tasks

    def _get(self, task_id: UUID | str) -> Task:
        task = self.store.get_task(task_id)
        if task is None:
            raise ServiceError("task not found")
        return task

    def get(self, actor: Actor, task_id: UUID | str) -> Task:
        task = self._get(task_id)
        self._read_decision(actor, task)
        return task

    def _read_decision(self, actor: Actor, task: Task) -> None:
        decision = self.policy.evaluate(
            actor,
            Action.READ,
            task.risk,
            str(task.id),
            touched_paths=[task.repo_path],
        )
        if not decision.allowed:
            raise ServiceError(decision.reason)

    def approve(self, actor: Actor, task_id: UUID | str) -> Task:
        task = self._get(task_id)
        if task.state is not TaskState.AWAITING_APPROVAL:
            raise ServiceError("task is not awaiting approval")
        if actor.role not in {Role.REVIEWER, Role.ADMIN}:
            raise ServiceError("only a reviewer or admin can approve tasks")
        submitter = next(
            (event.actor for event in self.audit.events(str(task.id)) if event.action == "submit"),
            None,
        )
        if submitter == actor.actor_id:
            raise ServiceError("submitter cannot approve their own task")
        scope = self._validated_scope(task)
        try:
            self.policy.approve(str(task.id), actor, scope.spec_hash, scope.scope_hash)
            decision = self.policy.evaluate(actor, Action.APPROVE, task.risk, str(task.id))
            if not decision.allowed:
                raise ServiceError(decision.reason)
            if task.state is TaskState.AWAITING_APPROVAL:
                TaskStateMachine.transition(task, TaskState.CONTEXT_BUILT)
            self.store.save_approval(
                task.id,
                actor.actor_id,
                "",
                scope.spec_hash,
                scope.scope_hash,
                scope.policy_version,
            )
            self.store.save_task(task)
            self.audit.append(actor.actor_id, "approve", str(task.id), "accepted")
            return task
        except PolicyDenied as exc:
            raise ServiceError(str(exc)) from exc

    def deny(self, actor: Actor, task_id: UUID | str, reason: str) -> Task:
        task = self._get(task_id)
        try:
            self.policy.deny(str(task.id), actor)
        except PolicyDenied as exc:
            raise ServiceError(str(exc)) from exc
        self.store.revoke_approval(task.id)
        if task.state not in {
            TaskState.SUCCEEDED,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.BLOCKED,
        }:
            task.state = TaskState.BLOCKED
        task.failure_reason = reason[:2_000]
        self.store.save_task(task)
        self.audit.append(actor.actor_id, "deny", str(task.id), "blocked", {"reason": reason[:500]})
        return task

    def request_execution(self, actor: Actor, task_id: UUID | str) -> Task:
        """Authorize and queue execution for the dedicated worker."""
        self._sync_kill_switch()
        task = self._get(task_id)
        scope = self._validated_scope(task)
        approval = self.store.get_approval(task.id)
        # Drop cached evidence so revocation, expiry, and changes in another process
        # cannot be masked by the PolicyEngine's in-memory approval cache.
        self.policy.deny(str(task.id), Actor(actor_id="state-store", role=Role.ADMIN))
        if approval is not None:
            if (
                not approval.active
                or approval.spec_hash != scope.spec_hash
                or approval.scope_hash != scope.scope_hash
                or approval.policy_version != scope.policy_version
            ):
                raise ServiceError("task approval is inactive or does not match persisted scope")
            self.policy.restore_approval(
                str(task.id), approval.approver, approval.spec_hash, approval.scope_hash
            )
        decision = self.policy.evaluate(
            actor,
            Action.EXECUTE,
            task.risk,
            str(task.id),
            touched_paths=[scope.repo_path],
            spec_hash=scope.spec_hash,
            scope_hash=scope.scope_hash,
        )
        if not decision.allowed:
            raise ServiceError(decision.reason)
        if task.state is TaskState.POLICY_CHECKED:
            TaskStateMachine.transition(task, TaskState.CONTEXT_BUILT)
        elif task.state is not TaskState.CONTEXT_BUILT:
            raise ServiceError("task must be policy-checked or context-built before execution")
        self.store.save_task(task)
        try:
            self.store.enqueue_execution(task.id, actor.actor_id)
        except PersistenceError as exc:
            raise ServiceError(str(exc)) from exc
        self.audit.append(actor.actor_id, "execute_requested", str(task.id), "queued")
        return task

    def cancel(self, actor: Actor, task_id: UUID | str) -> Task:
        task = self._get(task_id)
        self._read_decision(actor, task)
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
        self.store.cancel_execution(task.id)
        task.failure_reason = "cancelled by operator"
        self.store.save_task(task)
        self.audit.append(actor.actor_id, "cancel", str(task.id), "cancelled")
        return task

    def diff(self, actor: Actor, task_id: UUID | str) -> str:
        task = self.get(actor, task_id)
        try:
            return GitSafety(task.repo_path).status_porcelain()
        except (GitSafetyError, OSError):
            return ""

    def events(self, actor: Actor, task_id: UUID | str) -> tuple[AuditEvent, ...]:
        self.get(actor, task_id)
        return self.audit.replay(str(task_id))

    def execution_result(self, actor: Actor, task_id: UUID | str) -> dict[str, object]:
        task = self.get(actor, task_id)
        request = self.store.get_execution_request(task.id)
        return {
            "request": request.model_dump(mode="json") if request is not None else None,
            "result": self.store.get_execution_result(task.id),
        }
