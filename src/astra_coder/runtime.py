"""Bounded task runtime and explicit state machine."""

from __future__ import annotations

import time
from collections.abc import Callable
from enum import StrEnum
from threading import Event, Lock
from typing import Final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class TaskState(StrEnum):
    RECEIVED = "received"
    POLICY_CHECKED = "policy_checked"
    AWAITING_APPROVAL = "awaiting_approval"
    CONTEXT_BUILT = "context_built"
    PLANNED = "planned"
    EDITING = "editing"
    OBSERVING = "observing"
    VERIFYING = "verifying"
    REVIEWING = "reviewing"
    REPAIRING = "repairing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


TERMINAL_STATES: Final[frozenset[TaskState]] = frozenset(
    {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED, TaskState.BLOCKED}
)


class RiskTier(StrEnum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"


class TaskLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_steps: int = Field(default=32, gt=0, le=1000)
    max_seconds: float = Field(default=900.0, gt=0, le=86_400)
    max_tokens: int = Field(default=100_000, gt=0, le=10_000_000)
    max_repairs: int = Field(default=3, ge=0, le=20)


class Task(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: UUID = Field(default_factory=uuid4)
    prompt: str = Field(min_length=1, max_length=100_000)
    repo_path: str = Field(min_length=1, max_length=4_096)
    state: TaskState = TaskState.RECEIVED
    risk: RiskTier = RiskTier.T1
    limits: TaskLimits = Field(default_factory=TaskLimits)
    steps: int = Field(default=0, ge=0)
    tokens: int = Field(default=0, ge=0)
    repairs: int = Field(default=0, ge=0)
    failure_reason: str | None = None


_ALLOWED: Final[dict[TaskState, frozenset[TaskState]]] = {
    TaskState.RECEIVED: frozenset({TaskState.POLICY_CHECKED, TaskState.CANCELLED}),
    TaskState.POLICY_CHECKED: frozenset(
        {
            TaskState.AWAITING_APPROVAL,
            TaskState.CONTEXT_BUILT,
            TaskState.BLOCKED,
            TaskState.CANCELLED,
        }
    ),
    TaskState.AWAITING_APPROVAL: frozenset(
        {TaskState.CONTEXT_BUILT, TaskState.BLOCKED, TaskState.CANCELLED}
    ),
    TaskState.CONTEXT_BUILT: frozenset({TaskState.PLANNED, TaskState.CANCELLED}),
    TaskState.PLANNED: frozenset(
        {TaskState.EDITING, TaskState.AWAITING_APPROVAL, TaskState.BLOCKED, TaskState.CANCELLED}
    ),
    TaskState.EDITING: frozenset({TaskState.OBSERVING, TaskState.FAILED, TaskState.CANCELLED}),
    TaskState.OBSERVING: frozenset(
        {TaskState.VERIFYING, TaskState.REPAIRING, TaskState.FAILED, TaskState.CANCELLED}
    ),
    TaskState.VERIFYING: frozenset(
        {TaskState.REVIEWING, TaskState.REPAIRING, TaskState.FAILED, TaskState.CANCELLED}
    ),
    TaskState.REVIEWING: frozenset(
        {TaskState.SUCCEEDED, TaskState.REPAIRING, TaskState.FAILED, TaskState.CANCELLED}
    ),
    TaskState.REPAIRING: frozenset({TaskState.EDITING, TaskState.FAILED, TaskState.CANCELLED}),
}


class InvalidTransition(ValueError):
    """Raised when a task attempts an unapproved state transition."""


class TaskStateMachine:
    """Apply only transitions declared by the runtime contract."""

    @staticmethod
    def transition(task: Task, target: TaskState) -> Task:
        current = task.state
        if current in TERMINAL_STATES:
            raise InvalidTransition(f"terminal task cannot transition: {current} -> {target}")
        if target not in _ALLOWED.get(current, frozenset()):
            raise InvalidTransition(f"invalid transition: {current} -> {target}")
        task.state = target
        return task

    @staticmethod
    def fail(task: Task, reason: str) -> Task:
        if task.state not in TERMINAL_STATES:
            task.state = TaskState.FAILED
        task.failure_reason = reason[:2_000]
        return task


class CancellationToken:
    """Thread-safe cooperative cancellation signal."""

    def __init__(self) -> None:
        self._event = Event()
        self._lock = Lock()
        self._reason: str | None = None

    def cancel(self, reason: str = "cancelled by caller") -> None:
        with self._lock:
            self._reason = reason[:500]
            self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason or "cancelled"


class StepResult(BaseModel):
    """The only result an agent-loop step may return."""

    next_state: TaskState
    tokens: int = Field(default=0, ge=0)
    done: bool = False
    failure_reason: str | None = None


StepHandler = Callable[[Task, CancellationToken], StepResult]


class AgentLoop:
    """Run a handler under hard step, time, token, and cancellation limits."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock

    def run(self, task: Task, handler: StepHandler, token: CancellationToken | None = None) -> Task:
        cancellation = token or CancellationToken()
        started = self._clock()
        while task.state not in TERMINAL_STATES:
            if cancellation.cancelled:
                TaskStateMachine.transition(task, TaskState.CANCELLED)
                task.failure_reason = cancellation.reason
                return task
            if self._clock() - started >= task.limits.max_seconds:
                return TaskStateMachine.fail(task, "wall-clock budget exceeded")
            if task.steps >= task.limits.max_steps:
                return TaskStateMachine.fail(task, "step budget exceeded")
            result = handler(task, cancellation)
            task.steps += 1
            if task.tokens + result.tokens > task.limits.max_tokens:
                return TaskStateMachine.fail(task, "token budget exceeded")
            task.tokens += result.tokens
            try:
                TaskStateMachine.transition(task, result.next_state)
            except InvalidTransition as exc:
                return TaskStateMachine.fail(task, str(exc))
            if result.failure_reason:
                return TaskStateMachine.fail(task, result.failure_reason)
            if result.done:
                if task.state not in TERMINAL_STATES:
                    return TaskStateMachine.fail(
                        task, "step declared completion before a terminal state"
                    )
                return task
        return task
