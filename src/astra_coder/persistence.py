"""SQLite task persistence and hash-chained append-only audit evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal, cast
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, create_engine, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from .runtime import TERMINAL_STATES, RiskTier, Task, TaskLimits, TaskState


class PersistenceError(RuntimeError):
    """A durable state or audit operation failed."""


class Base(DeclarativeBase):
    pass


class TaskRecord(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    prompt: Mapped[str] = mapped_column(Text)
    repo_path: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(32))
    risk: Mapped[str] = mapped_column(String(2))
    limits: Mapped[dict[str, Any]] = mapped_column(JSON)
    steps: Mapped[int] = mapped_column(Integer, default=0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    repairs: Mapped[int] = mapped_column(Integer, default=0)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TaskScopeRecord(Base):
    __tablename__ = "task_scopes"

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    spec_hash: Mapped[str] = mapped_column(String(64))
    scope_hash: Mapped[str] = mapped_column(String(64))
    repo_path: Mapped[str] = mapped_column(Text)
    base_revision: Mapped[str] = mapped_column(String(128), default="")
    risk: Mapped[str] = mapped_column(String(2))
    policy_version: Mapped[str] = mapped_column(String(64), default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApprovalRecord(Base):
    __tablename__ = "task_approvals"

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    approver: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text, default="")
    spec_hash: Mapped[str] = mapped_column(String(64))
    scope_hash: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExecutionRequestRecord(Base):
    __tablename__ = "task_execution_requests"

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requested_by: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(16))
    worker_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ExecutionResultRecord(Base):
    __tablename__ = "task_execution_results"

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ControlRecord(Base):
    __tablename__ = "runtime_controls"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TransitionRecord(Base):
    __tablename__ = "task_transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(36), index=True)
    from_state: Mapped[str] = mapped_column(String(32))
    to_state: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(128))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditHeadRecord(Base):
    __tablename__ = "audit_head"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_hash: Mapped[str] = mapped_column(String(64))


class AuditRecord(Base):
    __tablename__ = "audit_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True)
    occurred_at: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(256))
    decision: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))


class AuditEvent(BaseModel):
    sequence: int
    event_id: UUID
    occurred_at: datetime
    actor: str
    action: str
    target: str
    decision: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    event_hash: str


class TaskScope(BaseModel):
    task_id: UUID
    spec_hash: str = Field(min_length=64, max_length=64)
    scope_hash: str = Field(min_length=64, max_length=64)
    repo_path: str
    base_revision: str = ""
    risk: RiskTier
    policy_version: str = "1"
    created_at: datetime


class Approval(BaseModel):
    task_id: UUID
    approver: str
    reason: str = ""
    spec_hash: str
    scope_hash: str
    policy_version: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    @property
    def active(self) -> bool:
        now = datetime.now(UTC)
        expires_at = self.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return self.revoked_at is None and (expires_at is None or expires_at > now)


class ExecutionRequest(BaseModel):
    task_id: UUID
    requested_by: str
    status: Literal["queued", "running", "succeeded", "failed", "cancelled"]
    worker_id: str | None = None
    requested_at: datetime
    claimed_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class StateStore:
    def __init__(self, database_url: str = "sqlite:///./astra.db") -> None:
        engine_options: dict[str, Any] = {"future": True}
        if database_url == "sqlite:///:memory:":
            engine_options["connect_args"] = {"check_same_thread": False}
            engine_options["poolclass"] = StaticPool
        self.engine = create_engine(database_url, **engine_options)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def set_kill_switch(self, enabled: bool) -> None:
        values = {"enabled": enabled, "updated_at": datetime.now(UTC)}
        with self.sessions.begin() as session:
            session.execute(
                insert(ControlRecord)
                .values(name="kill_switch", **values)
                .on_conflict_do_update(index_elements=[ControlRecord.name], set_=values)
            )

    def get_kill_switch(self) -> bool:
        with self.sessions() as session:
            record = session.get(ControlRecord, "kill_switch")
            return record.enabled if record is not None else False

    def save_task(self, task: Task) -> None:
        with self.sessions.begin() as session:
            record = session.get(TaskRecord, str(task.id))
            values = self._task_values(task)
            if record is None:
                session.add(TaskRecord(**values))
            else:
                for key, value in values.items():
                    setattr(record, key, value)

    def save_scope(self, scope: TaskScope) -> None:
        with self.sessions.begin() as session:
            record = session.get(TaskScopeRecord, str(scope.task_id))
            values = {
                "task_id": str(scope.task_id),
                "spec_hash": scope.spec_hash,
                "scope_hash": scope.scope_hash,
                "repo_path": scope.repo_path,
                "base_revision": scope.base_revision,
                "risk": scope.risk.value,
                "policy_version": scope.policy_version,
                "created_at": scope.created_at,
            }
            if record is None:
                session.add(TaskScopeRecord(**values))
            else:
                for key, value in values.items():
                    setattr(record, key, value)

    def get_scope(self, task_id: UUID | str) -> TaskScope | None:
        with self.sessions() as session:
            record = session.get(TaskScopeRecord, str(task_id))
            if record is None:
                return None
            return TaskScope(
                task_id=UUID(record.task_id),
                spec_hash=record.spec_hash,
                scope_hash=record.scope_hash,
                repo_path=record.repo_path,
                base_revision=record.base_revision,
                risk=RiskTier(record.risk),
                policy_version=record.policy_version,
                created_at=record.created_at,
            )

    def save_approval(
        self,
        task_id: UUID | str,
        approver: str,
        reason: str,
        spec_hash: str,
        scope_hash: str,
        policy_version: str,
        expires_at: datetime | None = None,
    ) -> Approval:
        now = datetime.now(UTC)
        with self.sessions.begin() as session:
            record = session.get(ApprovalRecord, str(task_id))
            values = {
                "task_id": str(task_id),
                "approver": approver,
                "reason": reason[:2_000],
                "spec_hash": spec_hash,
                "scope_hash": scope_hash,
                "policy_version": policy_version,
                "created_at": now,
                "expires_at": expires_at,
                "revoked_at": None,
            }
            if record is None:
                session.add(ApprovalRecord(**values))
            else:
                for key, value in values.items():
                    setattr(record, key, value)
        return Approval(
            task_id=UUID(str(task_id)),
            approver=approver,
            reason=reason[:2_000],
            spec_hash=spec_hash,
            scope_hash=scope_hash,
            policy_version=policy_version,
            created_at=now,
            expires_at=expires_at,
            revoked_at=None,
        )

    def get_approval(self, task_id: UUID | str) -> Approval | None:
        with self.sessions() as session:
            record = session.get(ApprovalRecord, str(task_id))
            if record is None:
                return None
            return Approval(
                task_id=UUID(record.task_id),
                approver=record.approver,
                reason=record.reason,
                spec_hash=record.spec_hash,
                scope_hash=record.scope_hash,
                policy_version=record.policy_version,
                created_at=record.created_at,
                expires_at=record.expires_at,
                revoked_at=record.revoked_at,
            )

    def approvals(self) -> tuple[Approval, ...]:
        with self.sessions() as session:
            records = session.scalars(select(ApprovalRecord)).all()
            return tuple(
                Approval(
                    task_id=UUID(record.task_id),
                    approver=record.approver,
                    reason=record.reason,
                    spec_hash=record.spec_hash,
                    scope_hash=record.scope_hash,
                    policy_version=record.policy_version,
                    created_at=record.created_at,
                    expires_at=record.expires_at,
                    revoked_at=record.revoked_at,
                )
                for record in records
            )

    def revoke_approval(self, task_id: UUID | str) -> None:
        with self.sessions.begin() as session:
            record = session.get(ApprovalRecord, str(task_id))
            if record is not None and record.revoked_at is None:
                record.revoked_at = datetime.now(UTC)

    def enqueue_execution(self, task_id: UUID | str, requested_by: str) -> ExecutionRequest:
        now = datetime.now(UTC)
        with self.sessions.begin() as session:
            record = session.get(ExecutionRequestRecord, str(task_id))
            if record is not None and record.status in {"queued", "running"}:
                raise PersistenceError("task execution is already queued or running")
            values = {
                "task_id": str(task_id),
                "requested_by": requested_by,
                "status": "queued",
                "worker_id": None,
                "requested_at": now,
                "claimed_at": None,
                "completed_at": None,
                "error": None,
            }
            if record is None:
                session.add(ExecutionRequestRecord(**values))
            else:
                for key, value in values.items():
                    setattr(record, key, value)
        request = self.get_execution_request(task_id)
        if request is None:
            raise PersistenceError("execution request could not be persisted")
        return request

    def get_execution_request(self, task_id: UUID | str) -> ExecutionRequest | None:
        with self.sessions() as session:
            record = session.get(ExecutionRequestRecord, str(task_id))
            return self._to_execution_request(record) if record else None

    def claim_next_execution(self, worker_id: str) -> ExecutionRequest | None:
        """Atomically select and claim one queued request across store instances."""
        now = datetime.now(UTC)
        candidate = (
            select(ExecutionRequestRecord.task_id)
            .where(ExecutionRequestRecord.status == "queued")
            .order_by(ExecutionRequestRecord.requested_at, ExecutionRequestRecord.task_id)
            .limit(1)
            .scalar_subquery()
        )
        with self.sessions.begin() as session:
            record = session.scalars(
                update(ExecutionRequestRecord)
                .where(
                    ExecutionRequestRecord.task_id == candidate,
                    ExecutionRequestRecord.status == "queued",
                )
                .values(status="running", worker_id=worker_id, claimed_at=now, error=None)
                .returning(ExecutionRequestRecord)
            ).one_or_none()
            return self._to_execution_request(record) if record is not None else None

    def save_execution_result(self, task_id: UUID | str, result_json: dict[str, Any] | str) -> None:
        """Persist a validated OrchestrationResult JSON object in the results table."""
        payload = self._execution_result_json(task_id, result_json)
        with self.sessions.begin() as session:
            self._save_execution_result(session, task_id, payload)

    def get_execution_result(self, task_id: UUID | str) -> dict[str, Any] | None:
        with self.sessions() as session:
            record = session.get(ExecutionResultRecord, str(task_id))
            return record.result_json if record is not None else None

    def finalize_execution(
        self, task: Task, worker_id: str, result_json: dict[str, Any] | str
    ) -> Task:
        """Commit an owner's terminal task, queue status, and result together.

        An operator's persisted terminal state wins over a stale worker snapshot.
        The returned task and the stored result both reflect that effective state.
        """
        payload = self._execution_result_json(task.id, result_json)
        if task.state not in TERMINAL_STATES:
            raise PersistenceError("execution result task must be terminal")
        if payload["task"] != task.model_dump(mode="json"):
            raise PersistenceError("execution result does not match the task snapshot")
        now = datetime.now(UTC)
        with self.sessions.begin() as session:
            request = session.scalars(
                update(ExecutionRequestRecord)
                .where(
                    ExecutionRequestRecord.task_id == str(task.id),
                    ExecutionRequestRecord.status == "running",
                    ExecutionRequestRecord.worker_id == worker_id,
                )
                .values(completed_at=now)
                .returning(ExecutionRequestRecord)
            ).one_or_none()
            if request is None:
                raise PersistenceError("running execution request is not owned by this worker")
            record = session.scalars(
                update(TaskRecord)
                .where(
                    TaskRecord.id == str(task.id),
                    TaskRecord.state.not_in([state.value for state in TERMINAL_STATES]),
                )
                .values(**self._task_values(task))
                .returning(TaskRecord)
            ).one_or_none()
            if record is None:
                record = session.get(TaskRecord, str(task.id))
            if record is None:
                raise PersistenceError("task not found")
            effective_task = self._to_task(record)
            request.status = self._execution_status(effective_task)
            request.error = (
                effective_task.failure_reason[:2_000] if effective_task.failure_reason else None
            )
            payload["task"] = effective_task.model_dump(mode="json")
            self._save_execution_result(session, task.id, payload)
            return effective_task

    def complete_execution(
        self,
        task_id: UUID | str,
        status: Literal["succeeded", "failed", "cancelled"],
        error: str | None = None,
    ) -> ExecutionRequest:
        now = datetime.now(UTC)
        with self.sessions.begin() as session:
            record = session.get(ExecutionRequestRecord, str(task_id))
            if record is None:
                raise PersistenceError("task execution request not found")
            if record.status != "running":
                raise PersistenceError("task execution request is not running")
            record.status = status
            record.completed_at = now
            record.error = error[:2_000] if error else None
            return self._to_execution_request(record)

    def cancel_execution(self, task_id: UUID | str) -> ExecutionRequest | None:
        now = datetime.now(UTC)
        with self.sessions.begin() as session:
            record = session.scalars(
                update(ExecutionRequestRecord)
                .where(
                    ExecutionRequestRecord.task_id == str(task_id),
                    ExecutionRequestRecord.status == "queued",
                )
                .values(status="cancelled", completed_at=now, error="cancelled by operator")
                .returning(ExecutionRequestRecord)
            ).one_or_none()
            if record is None:
                record = session.get(ExecutionRequestRecord, str(task_id))
            return self._to_execution_request(record) if record is not None else None

    def record_transition(
        self,
        task: Task,
        previous_state: TaskState,
        actor: str,
        action: str,
    ) -> None:
        with self.sessions.begin() as session:
            session.add(
                TransitionRecord(
                    task_id=str(task.id),
                    from_state=previous_state.value,
                    to_state=task.state.value,
                    actor=actor,
                    action=action,
                    occurred_at=datetime.now(UTC),
                )
            )

    def transitions(self, task_id: UUID | str) -> tuple[dict[str, str], ...]:
        with self.sessions() as session:
            records = session.scalars(
                select(TransitionRecord)
                .where(TransitionRecord.task_id == str(task_id))
                .order_by(TransitionRecord.id)
            ).all()
            return tuple(
                {
                    "from": record.from_state,
                    "to": record.to_state,
                    "actor": record.actor,
                    "action": record.action,
                }
                for record in records
            )

    def get_task(self, task_id: UUID | str) -> Task | None:
        with self.sessions() as session:
            record = session.get(TaskRecord, str(task_id))
            return self._to_task(record) if record else None

    def list_tasks(self) -> tuple[Task, ...]:
        with self.sessions() as session:
            records = session.scalars(
                select(TaskRecord).order_by(TaskRecord.updated_at.desc())
            ).all()
            return tuple(self._to_task(record) for record in records)

    def incomplete_tasks(self) -> tuple[Task, ...]:
        with self.sessions() as session:
            records = session.scalars(
                select(TaskRecord).where(
                    TaskRecord.state.not_in([state.value for state in TERMINAL_STATES])
                )
            ).all()
            return tuple(self._to_task(record) for record in records)

    def recover_after_restart(self, audit: AuditLog, actor: str = "system") -> tuple[Task, ...]:
        """Recover standalone tasks; API restarts do not own worker requests."""
        recovered: list[Task] = []
        for task in self.incomplete_tasks():
            active_execution = select(ExecutionRequestRecord.task_id).where(
                ExecutionRequestRecord.task_id == str(task.id),
                ExecutionRequestRecord.status.in_(["queued", "running"]),
            )
            with self.sessions.begin() as session:
                record = session.scalars(
                    update(TaskRecord)
                    .where(
                        TaskRecord.id == str(task.id),
                        TaskRecord.state.not_in([state.value for state in TERMINAL_STATES]),
                        ~active_execution.exists(),
                    )
                    .values(
                        state=TaskState.FAILED.value,
                        failure_reason="interrupted by process restart; re-verification required",
                        updated_at=datetime.now(UTC),
                    )
                    .returning(TaskRecord)
                ).one_or_none()
                if record is not None:
                    session.execute(
                        update(ApprovalRecord)
                        .where(
                            ApprovalRecord.task_id == str(task.id),
                            ApprovalRecord.revoked_at.is_(None),
                        )
                        .values(revoked_at=datetime.now(UTC))
                    )
                    task = self._to_task(record)
            if record is None:
                continue
            audit.append(
                actor=actor,
                action="restart_recovery",
                target=str(task.id),
                decision="failed_closed",
                metadata={"state": task.state.value},
            )
            recovered.append(task)
        return tuple(recovered)

    def recover_worker_after_restart(self, audit: AuditLog, worker_id: str) -> tuple[Task, ...]:
        """Fail interrupted runs owned by one worker ID, without replaying them.

        Call once before claiming work, with exactly one live worker per ID.
        Unclaimed requests and requests owned by other worker IDs are retained.
        """
        now = datetime.now(UTC)
        reason = "interrupted by worker restart; re-verification required"
        recovered: list[Task] = []
        with self.sessions.begin() as session:
            requests = session.scalars(
                update(ExecutionRequestRecord)
                .where(
                    ExecutionRequestRecord.status == "running",
                    ExecutionRequestRecord.worker_id == worker_id,
                )
                .values(status="failed", completed_at=now, error=reason)
                .returning(ExecutionRequestRecord)
            ).all()
            for request in requests:
                record = session.scalars(
                    update(TaskRecord)
                    .where(
                        TaskRecord.id == request.task_id,
                        TaskRecord.state.not_in([state.value for state in TERMINAL_STATES]),
                    )
                    .values(state=TaskState.FAILED.value, failure_reason=reason, updated_at=now)
                    .returning(TaskRecord)
                ).one_or_none()
                if record is None:
                    record = session.get(TaskRecord, request.task_id)
                if record is None:
                    continue
                task = self._to_task(record)
                request.status = self._execution_status(task)
                request.error = task.failure_reason
                session.execute(
                    update(ApprovalRecord)
                    .where(
                        ApprovalRecord.task_id == request.task_id,
                        ApprovalRecord.revoked_at.is_(None),
                    )
                    .values(revoked_at=now)
                )
                recovered.append(task)
        for task in recovered:
            audit.append(
                actor=worker_id,
                action="worker_restart_recovery",
                target=str(task.id),
                decision="failed_closed",
                metadata={"state": task.state.value},
            )
        return tuple(recovered)

    @staticmethod
    def _execution_status(task: Task) -> Literal["succeeded", "failed", "cancelled"]:
        if task.state is TaskState.SUCCEEDED:
            return "succeeded"
        if task.state is TaskState.CANCELLED:
            return "cancelled"
        return "failed"

    @staticmethod
    def _execution_result_json(
        task_id: UUID | str, result_json: dict[str, Any] | str
    ) -> dict[str, Any]:
        from .orchestrator import OrchestrationResult

        try:
            result = (
                OrchestrationResult.model_validate_json(result_json)
                if isinstance(result_json, str)
                else OrchestrationResult.model_validate(result_json)
            )
        except ValueError as exc:
            raise PersistenceError("invalid orchestration result JSON") from exc
        if str(result.task.id) != str(task_id):
            raise PersistenceError("execution result belongs to a different task")
        return result.model_dump(mode="json")

    @staticmethod
    def _save_execution_result(
        session: Session, task_id: UUID | str, result_json: dict[str, Any]
    ) -> None:
        values = {"result_json": result_json, "updated_at": datetime.now(UTC)}
        session.execute(
            insert(ExecutionResultRecord)
            .values(task_id=str(task_id), **values)
            .on_conflict_do_update(index_elements=[ExecutionResultRecord.task_id], set_=values)
        )

    @staticmethod
    def _task_values(task: Task) -> dict[str, Any]:
        return {
            "id": str(task.id),
            "prompt": task.prompt,
            "repo_path": task.repo_path,
            "state": task.state.value,
            "risk": task.risk.value,
            "limits": task.limits.model_dump(mode="json"),
            "steps": task.steps,
            "tokens": task.tokens,
            "repairs": task.repairs,
            "failure_reason": task.failure_reason,
            "updated_at": datetime.now(UTC),
        }

    @staticmethod
    def _to_task(record: TaskRecord) -> Task:
        return Task(
            id=UUID(record.id),
            prompt=record.prompt,
            repo_path=record.repo_path,
            state=TaskState(record.state),
            risk=RiskTier(record.risk),
            limits=TaskLimits.model_validate(record.limits),
            steps=record.steps,
            tokens=record.tokens,
            repairs=record.repairs,
            failure_reason=record.failure_reason,
        )

    @staticmethod
    def _to_execution_request(record: ExecutionRequestRecord) -> ExecutionRequest:
        return ExecutionRequest(
            task_id=UUID(record.task_id),
            requested_by=record.requested_by,
            status=cast(
                Literal["queued", "running", "succeeded", "failed", "cancelled"],
                record.status,
            ),
            worker_id=record.worker_id,
            requested_at=record.requested_at,
            claimed_at=record.claimed_at,
            completed_at=record.completed_at,
            error=record.error,
        )


class AuditLog:
    _REDACT_KEYS = frozenset(
        {
            "secret",
            "token",
            "api_key",
            "apikey",
            "password",
            "credential",
            "authorization",
            "access_token",
            "refresh_token",
            "bearer_token",
            "client_secret",
            "private_key",
            "ssh_key",
            "cookie",
        }
    )

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = Lock()

    def append(
        self,
        actor: str,
        action: str,
        target: str,
        decision: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        safe_metadata = self._redact(metadata or {})
        occurred_at = datetime.now(UTC)
        with self.store.sessions.begin() as session:
            # Obtain the SQLite writer lock before reading the chain tail; API and
            # worker appenders live in separate processes, not under one Python lock.
            if self.store.engine.dialect.name == "sqlite":
                session.execute(
                    insert(AuditHeadRecord)
                    .values(id="global", sequence=0, event_hash="0" * 64)
                    .on_conflict_do_nothing(index_elements=["id"])
                )
                session.execute(
                    update(AuditHeadRecord)
                    .where(AuditHeadRecord.id == "global")
                    .values(sequence=AuditHeadRecord.sequence)
                )
            previous = session.scalars(
                select(AuditRecord).order_by(AuditRecord.sequence.desc())
            ).first()
            previous_hash = previous.event_hash if previous else "0" * 64
            event_id = hashlib.sha256(
                f"{occurred_at.isoformat()}\0{actor}\0{action}\0{target}".encode()
            ).hexdigest()[:32]
            payload = {
                "event_id": event_id,
                "occurred_at": occurred_at.isoformat(),
                "actor": actor,
                "action": action,
                "target": target,
                "decision": decision,
                "metadata": safe_metadata,
                "previous_hash": previous_hash,
            }
            event_hash = self._hash(payload)
            record = AuditRecord(
                event_id=event_id,
                occurred_at=occurred_at.isoformat(),
                actor=actor,
                action=action,
                target=target,
                decision=decision,
                metadata_json=safe_metadata,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
            session.add(record)
            session.flush()
            return AuditEvent(
                sequence=record.sequence,
                event_id=UUID(event_id),
                occurred_at=occurred_at,
                actor=actor,
                action=action,
                target=target,
                decision=decision,
                metadata=safe_metadata,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )

    def events(self, target: str | None = None) -> tuple[AuditEvent, ...]:
        with self.store.sessions() as session:
            statement = select(AuditRecord).order_by(AuditRecord.sequence)
            if target is not None:
                statement = statement.where(AuditRecord.target == target)
            return tuple(self._event(record) for record in session.scalars(statement).all())

    def verify_chain(self) -> bool:
        previous_hash = "0" * 64
        for event in self.events():
            if event.previous_hash != previous_hash:
                return False
            payload = {
                "event_id": str(event.event_id).replace("-", ""),
                "occurred_at": event.occurred_at.isoformat(),
                "actor": event.actor,
                "action": event.action,
                "target": event.target,
                "decision": event.decision,
                "metadata": event.metadata,
                "previous_hash": event.previous_hash,
            }
            if self._hash(payload) != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    def replay(self, target: str) -> tuple[AuditEvent, ...]:
        return self.events(target)

    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (
                    "[REDACTED]"
                    if key.lower().replace("-", "_") in cls._REDACT_KEYS
                    else cls._redact(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        return value

    @staticmethod
    def _hash(value: object) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _event(record: AuditRecord) -> AuditEvent:
        return AuditEvent(
            sequence=record.sequence,
            event_id=UUID(record.event_id),
            occurred_at=datetime.fromisoformat(record.occurred_at),
            actor=record.actor,
            action=record.action,
            target=record.target,
            decision=record.decision,
            metadata=record.metadata_json,
            previous_hash=record.previous_hash,
            event_hash=record.event_hash,
        )
