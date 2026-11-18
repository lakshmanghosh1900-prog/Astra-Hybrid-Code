"""Durable long-term memory for coding agents.

The engine keeps bounded, redacted memories in SQLite so an agent can recall
previous successes and failures instead of repeating work. It is intentionally
dependency-free beyond the standard library and the project redactor:

* one serialized connection per engine, safe for multi-threaded callers;
* WAL + busy timeout for cross-process read/write coordination;
* content-hash deduplication scoped by namespace;
* TTL expiry, bounded retention, and deterministic keyword ranking;
* credential redaction before any text is persisted.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, Final, Protocol, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .redaction import SecretRedactor

SCHEMA_VERSION: Final[int] = 1
DEFAULT_DATABASE_PATH: Final[str] = "astramind_memory.db"
DEFAULT_NAMESPACE: Final[str] = "default"
DEFAULT_AUDIT_ACTOR: Final[str] = "memory-engine"
MAX_QUERY_LIMIT: Final[int] = 100
MAX_EXPORT_LIMIT: Final[int] = 100_000
_NAMESPACE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\w+", re.UNICODE)


class MemoryAuditSink(Protocol):
    """Durable audit boundary used by the memory engine."""

    def append(
        self,
        actor: str,
        action: str,
        target: str,
        decision: str,
        metadata: dict[str, Any] | None = None,
    ) -> object: ...


_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    context TEXT NOT NULL,
    solution TEXT NOT NULL,
    status TEXT NOT NULL,
    tags TEXT NOT NULL,
    importance REAL NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    hits INTEGER NOT NULL DEFAULT 0,
    UNIQUE (namespace, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_memories_namespace_updated
    ON memories (namespace, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_memories_expires
    ON memories (expires_at);
"""


class MemoryEngineError(RuntimeError):
    """The memory store could not complete an operation."""


class MemoryStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"
    INFO = "INFO"


class MemoryEntry(BaseModel):
    """One immutable, redacted long-term memory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    namespace: str
    context: str
    solution: str
    status: MemoryStatus
    tags: tuple[str, ...] = ()
    importance: float = Field(ge=0.0, le=1.0)
    content_hash: str = Field(min_length=64, max_length=64)
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    hits: int = Field(default=0, ge=0)


class MemoryMatch(BaseModel):
    """A ranked recall result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry: MemoryEntry
    score: float = Field(ge=0.0, le=1.0)
    matched_terms: tuple[str, ...] = ()


class MemoryStats(BaseModel):
    """Bounded store statistics for operators."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    database_path: str
    schema_version: int
    max_entries: int
    total: int
    active: int
    expired: int
    namespaces: tuple[str, ...] = ()
    oldest: datetime | None = None
    newest: datetime | None = None


class MemoryEngineConfig(BaseModel):
    """Validated limits for one memory engine instance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    database_path: str = DEFAULT_DATABASE_PATH
    namespace: str = DEFAULT_NAMESPACE
    max_entries: int = Field(default=10_000, ge=1, le=1_000_000)
    max_context_chars: int = Field(default=4_000, ge=16, le=100_000)
    max_solution_chars: int = Field(default=8_000, ge=16, le=100_000)
    max_tags: int = Field(default=32, ge=0, le=128)
    default_ttl_seconds: float | None = Field(default=None, gt=0.0, le=31_536_000.0)
    candidate_limit: int = Field(default=2_000, ge=1, le=10_000)
    busy_timeout_ms: int = Field(default=5_000, ge=100, le=60_000)

    @field_validator("namespace")
    @classmethod
    def _valid_namespace(cls, value: str) -> str:
        return _require_namespace(value)

    @field_validator("database_path")
    @classmethod
    def _valid_path(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("database_path must not be empty")
        return value


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require_namespace(value: str) -> str:
    if not _NAMESPACE_PATTERN.fullmatch(value):
        raise ValueError("namespace must match [A-Za-z0-9_.:-] and be 1-64 characters")
    return value


def _tokens(text: str) -> frozenset[str]:
    return frozenset(match.casefold() for match in _TOKEN_PATTERN.findall(text))


def _clean_text(value: str, limit: int, redactor: SecretRedactor) -> str:
    if not value.strip():
        raise ValueError("memory text must not be empty")
    cleaned = value.replace("\x00", "")
    redacted = redactor.redact(cleaned)
    return redacted[:limit]


def _tags(values: Iterable[str], limit: int) -> tuple[str, ...]:
    tags: list[str] = []
    seen: set[str] = set()
    for value in values:
        tag = value.strip()
        if not tag:
            continue
        key = tag.casefold()
        if key in seen:
            continue
        seen.add(key)
        tags.append(tag[:64])
        if len(tags) >= limit:
            break
    return tuple(tags)


class AstraMemoryEngine:
    """Thread-safe, bounded, long-term memory with deterministic recall."""

    def __init__(
        self,
        database_path: str | Path = DEFAULT_DATABASE_PATH,
        *,
        namespace: str = DEFAULT_NAMESPACE,
        max_entries: int = 10_000,
        default_ttl_seconds: float | None = None,
        candidate_limit: int = 2_000,
        busy_timeout_ms: int = 5_000,
        max_context_chars: int = 4_000,
        max_solution_chars: int = 8_000,
        max_tags: int = 32,
        secret_values: Iterable[str] = (),
        redactor: SecretRedactor | None = None,
        clock: Callable[[], datetime] | None = None,
        audit: MemoryAuditSink | None = None,
        audit_actor: str = DEFAULT_AUDIT_ACTOR,
        config: MemoryEngineConfig | None = None,
    ) -> None:
        if not audit_actor.strip():
            raise ValueError("audit_actor must not be empty")
        if config is None:
            config = MemoryEngineConfig(
                database_path=str(database_path),
                namespace=namespace,
                max_entries=max_entries,
                default_ttl_seconds=default_ttl_seconds,
                candidate_limit=candidate_limit,
                busy_timeout_ms=busy_timeout_ms,
                max_context_chars=max_context_chars,
                max_solution_chars=max_solution_chars,
                max_tags=max_tags,
            )
        self.config = config
        self._clock = clock or _utcnow
        self._redactor = redactor or SecretRedactor(secret_values)
        self._audit = audit
        self._audit_actor = audit_actor
        self._lock = RLock()
        self._connection: sqlite3.Connection | None = None
        self._closed = False
        if self.config.database_path != ":memory:":
            parent = Path(self.config.database_path).expanduser().parent
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise MemoryEngineError("memory database directory is not writable") from exc
        self._connection = self._open()
        try:
            self._migrate()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> AstraMemoryEngine:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def _open(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.config.database_path,
                timeout=self.config.busy_timeout_ms / 1_000,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise MemoryEngineError("memory database could not be opened") from exc
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {self.config.busy_timeout_ms}")
            if self.config.database_path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error as exc:
            connection.close()
            raise MemoryEngineError("memory database could not be configured") from exc
        return connection

    def _db(self) -> sqlite3.Connection:
        if self._closed or self._connection is None:
            raise MemoryEngineError("memory engine is closed")
        return self._connection

    def _append_audit(
        self,
        action: str,
        target: str,
        decision: str,
        metadata: dict[str, Any],
    ) -> None:
        if self._audit is None:
            return
        try:
            self._audit.append(
                self._audit_actor,
                action,
                target,
                decision,
                metadata,
            )
        except Exception as exc:
            raise MemoryEngineError("memory audit sink failed") from exc

    def _migrate(self) -> None:
        with self._lock, self._db() as connection:
            row = connection.execute("PRAGMA user_version").fetchone()
            version = int(row[0]) if row is not None else 0
            if version not in (0, SCHEMA_VERSION):
                raise MemoryEngineError(
                    f"unsupported memory schema version {version}; expected {SCHEMA_VERSION}"
                )
            if version == 0:
                connection.executescript(_SCHEMA)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def remember(
        self,
        context: str,
        solution: str,
        *,
        status: MemoryStatus | str = MemoryStatus.SUCCESS,
        namespace: str | None = None,
        tags: Iterable[str] = (),
        importance: float = 0.5,
        ttl_seconds: float | None = None,
    ) -> MemoryEntry:
        """Persist one memory, updating a duplicate instead of growing forever."""
        if not 0.0 <= importance <= 1.0:
            raise ValueError("importance must be between 0 and 1")
        memory_status = (
            status if isinstance(status, MemoryStatus) else MemoryStatus(str(status).upper())
        )
        target_namespace = _require_namespace(namespace or self.config.namespace)
        clean_context = _clean_text(context, self.config.max_context_chars, self._redactor)
        clean_solution = _clean_text(solution, self.config.max_solution_chars, self._redactor)
        clean_tags = _tags(tags, self.config.max_tags)
        now = _as_utc(self._clock())
        ttl = self.config.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if ttl is not None and ttl <= 0:
            raise ValueError("ttl_seconds must be positive")
        expires_at = now + timedelta(seconds=ttl) if ttl is not None else None
        content_hash = hashlib.sha256(
            f"{target_namespace}\0{clean_context}\0{clean_solution}".encode()
        ).hexdigest()
        values = {
            "id": str(uuid4()),
            "namespace": target_namespace,
            "context": clean_context,
            "solution": clean_solution,
            "status": memory_status.value,
            "tags": json.dumps(clean_tags, ensure_ascii=False),
            "importance": importance,
            "content_hash": content_hash,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
        }
        with self._lock, self._db() as connection:
            connection.execute(
                """
                INSERT INTO memories (
                    id, namespace, context, solution, status, tags,
                    importance, content_hash, created_at, updated_at, expires_at
                ) VALUES (
                    :id, :namespace, :context, :solution, :status, :tags,
                    :importance, :content_hash, :created_at, :updated_at, :expires_at
                )
                ON CONFLICT (namespace, content_hash) DO UPDATE SET
                    solution = excluded.solution,
                    status = excluded.status,
                    tags = excluded.tags,
                    importance = MAX(memories.importance, excluded.importance),
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at,
                    hits = memories.hits + 1
                """,
                values,
            )
            row = connection.execute(
                "SELECT * FROM memories WHERE namespace = ? AND content_hash = ?",
                (target_namespace, content_hash),
            ).fetchone()
        if row is None:
            raise MemoryEngineError("memory could not be read back after save")
        entry = self._row_to_entry(row)
        self._enforce_retention(namespace=target_namespace)
        self._append_audit(
            "memory_remember",
            f"memory:{entry.id}",
            "stored",
            {
                "memory_id": str(entry.id),
                "namespace": entry.namespace,
                "content_hash": entry.content_hash,
                "status": entry.status.value,
                "tags": list(entry.tags),
                "importance": entry.importance,
                "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            },
        )
        return entry

    def save_memory(self, context: str, solution: str, status: str = "SUCCESS") -> MemoryEntry:
        """Backward-compatible single-memory save."""
        return self.remember(context, solution, status=status)

    def search(
        self,
        keyword: str,
        *,
        limit: int = 5,
        namespace: str | None = None,
        status: MemoryStatus | str | None = None,
        tags: Sequence[str] = (),
        include_expired: bool = False,
    ) -> tuple[MemoryMatch, ...]:
        """Recall memories ranked by token overlap, phrase, tags, and recency."""
        if not 1 <= limit <= MAX_QUERY_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_QUERY_LIMIT}")
        query = keyword.strip()
        if not query:
            return ()
        query_tokens = _tokens(query)
        if not query_tokens:
            return ()
        target_namespace = _require_namespace(namespace) if namespace is not None else None
        target_status = (
            None
            if status is None
            else (status if isinstance(status, MemoryStatus) else MemoryStatus(str(status).upper()))
        )
        requested_tags = _tags(tags, self.config.max_tags)
        now = _as_utc(self._clock())
        with self._lock:
            connection = self._db()
            rows = connection.execute(
                """
                SELECT * FROM memories
                WHERE (:namespace IS NULL OR namespace = :namespace)
                  AND (:status IS NULL OR status = :status)
                  AND (:include_expired = 1 OR expires_at IS NULL OR expires_at > :now)
                ORDER BY importance DESC, updated_at DESC
                LIMIT :candidate_limit
                """,
                {
                    "namespace": target_namespace,
                    "status": target_status.value if target_status is not None else None,
                    "include_expired": 1 if include_expired else 0,
                    "now": now.isoformat(),
                    "candidate_limit": self.config.candidate_limit,
                },
            ).fetchall()
        phrase = query.casefold()
        matches: list[MemoryMatch] = []
        for row in rows:
            entry = self._row_to_entry(row)
            if requested_tags and not set(requested_tags).issubset(entry.tags):
                continue
            entry_tokens = _tokens(f"{entry.context}\n{entry.solution}\n{' '.join(entry.tags)}")
            overlap_terms = query_tokens & entry_tokens
            if not overlap_terms and phrase not in f"{entry.context}\n{entry.solution}".casefold():
                continue
            overlap = len(overlap_terms) / len(query_tokens)
            phrase_bonus = 1.0 if phrase in f"{entry.context}\n{entry.solution}".casefold() else 0.0
            tag_bonus = 1.0 if requested_tags else 0.0
            age_days = max(0.0, (now - entry.created_at).total_seconds() / 86_400)
            recency = max(0.0, 1.0 - age_days / 365.0)
            score = (
                0.55 * overlap
                + 0.20 * phrase_bonus
                + 0.10 * tag_bonus
                + 0.10 * entry.importance
                + 0.05 * recency
            )
            matches.append(
                MemoryMatch(
                    entry=entry,
                    score=min(1.0, max(0.0, score)),
                    matched_terms=tuple(sorted(overlap_terms)),
                )
            )
        matches.sort(key=lambda match: (-match.score, -match.entry.updated_at.timestamp()))
        selected = tuple(matches[:limit])
        if selected:
            with self._lock, self._db() as connection:
                connection.executemany(
                    "UPDATE memories SET hits = hits + 1 WHERE id = ?",
                    [(str(match.entry.id),) for match in selected],
                )
        return selected

    def recall_relevant_memories(
        self, keyword: str, *, limit: int = 5, namespace: str | None = None
    ) -> list[dict[str, Any]]:
        """Backward-compatible dictionary recall API."""
        return [
            match.entry.model_dump(mode="json")
            for match in self.search(keyword, limit=limit, namespace=namespace)
        ]

    def forget(self, memory_id: UUID | str) -> bool:
        with self._lock, self._db() as connection:
            cursor = connection.execute("DELETE FROM memories WHERE id = ?", (str(memory_id),))
            deleted = cursor.rowcount > 0
        if deleted:
            self._append_audit(
                "memory_forget",
                f"memory:{memory_id}",
                "deleted",
                {"memory_id": str(memory_id)},
            )
        return deleted

    def forget_namespace(self, namespace: str) -> int:
        target = _require_namespace(namespace)
        with self._lock, self._db() as connection:
            cursor = connection.execute("DELETE FROM memories WHERE namespace = ?", (target,))
            deleted = cursor.rowcount
        if deleted:
            self._append_audit(
                "memory_forget_namespace",
                f"memory_namespace:{target}",
                "deleted",
                {"namespace": target, "deleted": deleted},
            )
        return deleted

    def prune(self) -> int:
        """Delete expired memories and then the lowest-value excess entries."""
        now = _as_utc(self._clock())
        with self._lock, self._db() as connection:
            expired = connection.execute(
                "DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now.isoformat(),),
            ).rowcount
            excess = connection.execute(
                "DELETE FROM memories WHERE id IN ("
                "SELECT id FROM memories "
                "ORDER BY importance DESC, updated_at DESC "
                "LIMIT -1 OFFSET ?)",
                (self.config.max_entries,),
            ).rowcount
        removed = max(0, expired) + max(0, excess)
        if removed:
            self._append_audit(
                "memory_prune",
                "memory_store",
                "deleted",
                {"expired": max(0, expired), "excess": max(0, excess), "removed": removed},
            )
        return removed

    def export(self, *, namespace: str | None = None) -> tuple[MemoryEntry, ...]:
        target = _require_namespace(namespace) if namespace is not None else None
        with self._lock:
            rows = (
                self._db()
                .execute(
                    """
                SELECT * FROM memories
                WHERE (:namespace IS NULL OR namespace = :namespace)
                ORDER BY created_at, id
                LIMIT :limit
                """,
                    {"namespace": target, "limit": MAX_EXPORT_LIMIT},
                )
                .fetchall()
            )
        return tuple(self._row_to_entry(row) for row in rows)

    def stats(self) -> MemoryStats:
        now = _as_utc(self._clock()).isoformat()
        with self._lock:
            connection = self._db()
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN expires_at IS NOT NULL AND expires_at <= :now
                        THEN 1 ELSE 0 END) AS expired,
                    MIN(created_at) AS oldest,
                    MAX(created_at) AS newest
                FROM memories
                """,
                {"now": now},
            ).fetchone()
            namespace_rows = connection.execute(
                "SELECT DISTINCT namespace FROM memories ORDER BY namespace"
            ).fetchall()
            version_row = connection.execute("PRAGMA user_version").fetchone()
        if row is None:
            raise MemoryEngineError("memory statistics could not be read")
        total = int(row["total"])
        expired = int(row["expired"] or 0)
        oldest = datetime.fromisoformat(str(row["oldest"])) if row["oldest"] else None
        newest = datetime.fromisoformat(str(row["newest"])) if row["newest"] else None
        return MemoryStats(
            database_path=self.config.database_path,
            schema_version=int(version_row[0]) if version_row is not None else SCHEMA_VERSION,
            max_entries=self.config.max_entries,
            total=total,
            active=total - expired,
            expired=expired,
            namespaces=tuple(str(namespace_row[0]) for namespace_row in namespace_rows),
            oldest=oldest,
            newest=newest,
        )

    def _enforce_retention(self, *, namespace: str) -> None:
        with self._lock, self._db() as connection:
            count_row = connection.execute(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?", (namespace,)
            ).fetchone()
            if count_row is None or int(count_row[0]) <= self.config.max_entries:
                return
            connection.execute(
                "DELETE FROM memories WHERE id IN ("
                "SELECT id FROM memories WHERE namespace = ? "
                "ORDER BY importance DESC, updated_at DESC "
                "LIMIT -1 OFFSET ?)",
                (namespace, self.config.max_entries),
            )

    def _row_to_entry(self, row: sqlite3.Row) -> MemoryEntry:
        tags_value = cast(str, row["tags"])
        try:
            decoded: Any = json.loads(tags_value)
        except json.JSONDecodeError:
            decoded = ()
        tags = (
            tuple(str(tag) for tag in decoded if isinstance(tag, str))
            if isinstance(decoded, list)
            else ()
        )
        expires_raw = row["expires_at"]
        expires_at = datetime.fromisoformat(str(expires_raw)) if expires_raw else None
        return MemoryEntry(
            id=UUID(str(row["id"])),
            namespace=str(row["namespace"]),
            context=str(row["context"]),
            solution=str(row["solution"]),
            status=MemoryStatus(str(row["status"])),
            tags=tags,
            importance=float(row["importance"]),
            content_hash=str(row["content_hash"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
            expires_at=expires_at,
            hits=int(row["hits"]),
        )


__all__ = [
    "AstraMemoryEngine",
    "DEFAULT_AUDIT_ACTOR",
    "DEFAULT_DATABASE_PATH",
    "DEFAULT_NAMESPACE",
    "MemoryAuditSink",
    "MemoryEngineConfig",
    "MemoryEngineError",
    "MemoryEntry",
    "MemoryMatch",
    "MemoryStats",
    "MemoryStatus",
    "SCHEMA_VERSION",
]
