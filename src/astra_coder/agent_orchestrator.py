"""Bounded multi-agent fan-out with isolation, retries, and deadlines.

This module complements :mod:`astra_coder.orchestrator`: the task orchestrator
owns the single-writer Plan/Act/Observe/Verify flow, while this fan-out layer
runs independent, named agents (tests, debug probes, reviewers) concurrently
under hard worker, retry, and timeout bounds. A failing agent never corrupts a
sibling result, and no unbounded thread is ever spawned.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Any, Final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .redaction import SecretRedactor

MAX_AGENTS: Final[int] = 64
MAX_TASKS: Final[int] = 1_000
MAX_WORKERS: Final[int] = 32
MAX_ATTEMPTS: Final[int] = 10
_AGENT_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class AgentRole(StrEnum):
    PLANNER = "planner"
    ARCHITECT = "architect"
    CODER = "coder"
    TESTER = "tester"
    REVIEWER = "reviewer"
    REPAIR = "repair"
    DEBUGGER = "debugger"


class AgentStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class OrchestrationError(RuntimeError):
    """The fan-out request violated a bound or had no runnable agents."""


class AgentTask(BaseModel):
    """Immutable unit of work handed to exactly one agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    description: str = Field(min_length=1, max_length=4_000)
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)

    @field_validator("description")
    @classmethod
    def _stripped(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("description must not be blank")
        return stripped


class AgentResult(BaseModel):
    """Terminal result for one task; failures are values, never exceptions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: UUID
    agent_name: str
    role: AgentRole
    status: AgentStatus
    output: str | None = None
    error: str | None = None
    attempts: int = Field(default=1, ge=0)
    started_at: datetime
    finished_at: datetime

    @property
    def succeeded(self) -> bool:
        return self.status is AgentStatus.SUCCEEDED

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds())


class AgentExecutionError(RuntimeError):
    """A direct ``execute_task`` call did not succeed."""

    def __init__(self, result: AgentResult) -> None:
        super().__init__(f"agent '{result.agent_name}' ended with {result.status.value}")
        self.result = result


class OrchestrationReport(BaseModel):
    """Aggregate, immutable outcome of one parallel fan-out."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    started_at: datetime
    finished_at: datetime
    timeout_seconds: float = Field(gt=0.0)
    results: tuple[AgentResult, ...] = ()

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def succeeded(self) -> int:
        return sum(1 for result in self.results if result.succeeded)

    @property
    def failed(self) -> int:
        return sum(1 for result in self.results if result.status is AgentStatus.FAILED)

    @property
    def cancelled(self) -> int:
        return sum(1 for result in self.results if result.status is AgentStatus.CANCELLED)

    @property
    def timed_out(self) -> int:
        return sum(1 for result in self.results if result.status is AgentStatus.TIMED_OUT)

    @property
    def all_succeeded(self) -> bool:
        return self.total > 0 and self.succeeded == self.total

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds())


AgentHandler = Callable[[AgentTask], str]
Clock = Callable[[], datetime]
Sleeper = Callable[[float], None]


class AstraAgent:
    """One bounded, retrying agent with a stable name and role."""

    def __init__(
        self,
        name: str,
        role: AgentRole | str,
        handler: AgentHandler | None = None,
        *,
        max_attempts: int = 1,
        retry_backoff_seconds: float = 0.0,
        redactor: SecretRedactor | None = None,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        if not _AGENT_NAME_PATTERN.fullmatch(name):
            raise ValueError("agent name must match [A-Za-z0-9_.:-] and be 1-64 characters")
        if not 1 <= max_attempts <= MAX_ATTEMPTS:
            raise ValueError(f"max_attempts must be between 1 and {MAX_ATTEMPTS}")
        if not 0.0 <= retry_backoff_seconds <= 60.0:
            raise ValueError("retry_backoff_seconds must be between 0 and 60")
        self.name = name
        self.role = role if isinstance(role, AgentRole) else AgentRole(str(role))
        self._handler = handler or self._default_handler
        self.max_attempts = max_attempts
        self.retry_backoff_seconds = retry_backoff_seconds
        self._redactor = redactor or SecretRedactor()
        self._clock = clock or _utcnow
        self._sleeper = sleeper or _sleep

    def _default_handler(self, task: AgentTask) -> str:
        return f"{self.name} ({self.role.value}) completed: {task.description}"

    def execute(self, task: AgentTask) -> AgentResult:
        started_at = self._clock()
        last_error: str | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                output = self._handler(task)
            except Exception as exc:
                last_error = self._redactor.redact(f"{type(exc).__name__}: {exc}")[:2_000]
                if attempt < self.max_attempts and self.retry_backoff_seconds > 0:
                    self._sleeper(self.retry_backoff_seconds * (2 ** (attempt - 1)))
                continue
            return AgentResult(
                task_id=task.id,
                agent_name=self.name,
                role=self.role,
                status=AgentStatus.SUCCEEDED,
                output=output,
                attempts=attempt,
                started_at=started_at,
                finished_at=self._clock(),
            )
        return AgentResult(
            task_id=task.id,
            agent_name=self.name,
            role=self.role,
            status=AgentStatus.FAILED,
            error=last_error or "agent handler failed",
            attempts=self.max_attempts,
            started_at=started_at,
            finished_at=self._clock(),
        )

    def execute_task(self, task_description: str) -> str:
        """Backward-compatible string API that raises on failure."""
        result = self.execute(AgentTask(description=task_description))
        if not result.succeeded:
            raise AgentExecutionError(result)
        return result.output or ""


class AstraOrchestrator:
    """Fan tasks out across registered agents under a bounded thread pool."""

    def __init__(
        self,
        agents: Iterable[AstraAgent] = (),
        *,
        max_workers: int | None = None,
        default_timeout_seconds: float = 60.0,
        fail_fast: bool = False,
        clock: Clock | None = None,
    ) -> None:
        if max_workers is not None and not 1 <= max_workers <= MAX_WORKERS:
            raise ValueError(f"max_workers must be between 1 and {MAX_WORKERS}")
        if not 0.001 <= default_timeout_seconds <= 86_400.0:
            raise ValueError("default_timeout_seconds must be between 0.001 and 86400")
        self._agents: dict[str, AstraAgent] = {}
        self._lock = RLock()
        self._max_workers = max_workers
        self.default_timeout_seconds = default_timeout_seconds
        self.fail_fast = fail_fast
        self._clock = clock or _utcnow
        for agent in agents:
            self.register_agent(agent)

    @property
    def agents(self) -> tuple[AstraAgent, ...]:
        with self._lock:
            return tuple(self._agents.values())

    def agent_names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._agents)

    def register_agent(self, agent: AstraAgent) -> None:
        with self._lock:
            if agent.name in self._agents:
                raise OrchestrationError(f"agent '{agent.name}' is already registered")
            if len(self._agents) >= MAX_AGENTS:
                raise OrchestrationError(f"agent limit of {MAX_AGENTS} reached")
            self._agents[agent.name] = agent

    def get_agent(self, name: str) -> AstraAgent | None:
        with self._lock:
            return self._agents.get(name)

    def run_parallel_tasks(
        self,
        task_list: Sequence[str | AgentTask],
        *,
        timeout_seconds: float | None = None,
    ) -> OrchestrationReport:
        """Run every task on a round-robin agent and return ordered results."""
        if len(task_list) > MAX_TASKS:
            raise OrchestrationError(f"task limit of {MAX_TASKS} exceeded")
        tasks = [
            item if isinstance(item, AgentTask) else AgentTask(description=item)
            for item in task_list
        ]
        timeout = self.default_timeout_seconds if timeout_seconds is None else timeout_seconds
        if not 0.001 <= timeout <= 86_400.0:
            raise ValueError("timeout_seconds must be between 0.001 and 86400")
        agents = self.agents
        if tasks and not agents:
            raise OrchestrationError("no agents are registered")
        started_at = self._clock()
        if not tasks:
            return OrchestrationReport(
                started_at=started_at,
                finished_at=started_at,
                timeout_seconds=timeout,
            )
        workers = min(self._max_workers or len(agents), len(tasks), MAX_WORKERS, len(agents))
        futures: list[tuple[AgentTask, AstraAgent, Future[AgentResult]]] = []
        results: list[AgentResult] = []
        with ThreadPoolExecutor(
            max_workers=max(1, workers), thread_name_prefix="astra-agent"
        ) as executor:
            for index, task in enumerate(tasks):
                agent = agents[index % len(agents)]
                futures.append((task, agent, executor.submit(agent.execute, task)))
            failed_seen = False
            for task, agent, future in futures:
                if self.fail_fast and failed_seen:
                    future.cancel()
                    now = self._clock()
                    results.append(
                        AgentResult(
                            task_id=task.id,
                            agent_name=agent.name,
                            role=agent.role,
                            status=AgentStatus.CANCELLED,
                            error="cancelled by fail_fast policy",
                            attempts=0,
                            started_at=now,
                            finished_at=now,
                        )
                    )
                    continue
                try:
                    result = future.result(timeout=timeout)
                except TimeoutError:
                    future.cancel()
                    now = self._clock()
                    result = AgentResult(
                        task_id=task.id,
                        agent_name=agent.name,
                        role=agent.role,
                        status=AgentStatus.TIMED_OUT,
                        error=f"task exceeded {timeout:.3f}s deadline",
                        attempts=1,
                        started_at=now,
                        finished_at=now,
                    )
                results.append(result)
                if not result.succeeded and result.status is not AgentStatus.CANCELLED:
                    failed_seen = True
        return OrchestrationReport(
            started_at=started_at,
            finished_at=self._clock(),
            timeout_seconds=timeout,
            results=tuple(results),
        )


__all__ = [
    "AgentExecutionError",
    "AgentResult",
    "AgentRole",
    "AgentStatus",
    "AgentTask",
    "AstraAgent",
    "AstraOrchestrator",
    "MAX_AGENTS",
    "MAX_TASKS",
    "MAX_WORKERS",
    "OrchestrationError",
    "OrchestrationReport",
]
