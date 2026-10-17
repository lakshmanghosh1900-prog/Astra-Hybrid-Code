"""SQLite task persistence and hash-chained append-only audit evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from threading import Lock
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
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


class StateStore:
    def __init__(self, database_url: str = "sqlite:///./astra.db") -> None:
        engine_options: dict[str, Any] = {"future": True}
        if database_url == "sqlite:///:memory:":
            engine_options["connect_args"] = {"check_same_thread": False}
            engine_options["poolclass"] = StaticPool
        self.engine = create_engine(database_url, **engine_options)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def save_task(self, task: Task) -> None:
        with self.sessions.begin() as session:
            record = session.get(TaskRecord, str(task.id))
            values = self._task_values(task)
            if record is None:
                session.add(TaskRecord(**values))
            else:
                for key, value in values.items():
                    setattr(record, key, value)

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
        recovered: list[Task] = []
        for task in self.incomplete_tasks():
            task.state = TaskState.FAILED
            task.failure_reason = "interrupted by process restart; re-verification required"
            self.save_task(task)
            audit.append(
                actor=actor,
                action="restart_recovery",
                target=str(task.id),
                decision="failed_closed",
                metadata={"state": task.state.value},
            )
            recovered.append(task)
        return tuple(recovered)

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


class AuditLog:
    _REDACT_KEYS = frozenset({"secret", "token", "api_key", "password", "credential"})

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
                key: ("[REDACTED]" if key.lower() in cls._REDACT_KEYS else cls._redact(item))
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
