"""Bounded failure detection and self-healing orchestration.

The proxy wraps an operation, classifies failures, redacts evidence, consults
long-term memory, and asks an injected healer for a patch. It never edits code
itself and never retries forever:

* only ``Exception`` subclasses are handled; ``KeyboardInterrupt`` propagates;
* identical failures are capped to break runaway healing loops;
* every patch must be explicitly ``applied`` and can be independently verified;
* successes and unresolved failures are recorded in the memory engine;
* transient failures may be retried without a healer using bounded backoff.
"""

from __future__ import annotations

import hashlib
import re
import time
import traceback
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Any, Final, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from .memory_engine import AstraMemoryEngine, MemoryStatus
from .redaction import SecretRedactor

T = TypeVar("T")

MAX_ATTEMPTS: Final[int] = 3
MAX_HISTORY: Final[int] = 1_000
_HEX_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
_HEX_LITERAL_PATTERN: Final[re.Pattern[str]] = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)
_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-f]{12,}\b", re.IGNORECASE)
_DIGITS_PATTERN: Final[re.Pattern[str]] = re.compile(r"\d+")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class FailureCategory(StrEnum):
    TRANSIENT = "transient"
    TIMEOUT = "timeout"
    PERMISSION = "permission"
    VALIDATION = "validation"
    UNKNOWN = "unknown"


class HealingStatus(StrEnum):
    SUCCEEDED = "succeeded"
    HEALED = "healed"
    FAILED = "failed"
    EXHAUSTED = "exhausted"
    BLOCKED = "blocked"


class FailureReport(BaseModel):
    """Redacted, deterministic failure evidence safe to persist or share."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint: str = Field(min_length=64, max_length=64)
    error_type: str = Field(min_length=1, max_length=256)
    message: str = Field(min_length=1, max_length=2_000)
    traceback: str = Field(default="", max_length=8_000)
    category: FailureCategory
    attempt: int = Field(ge=1, le=MAX_ATTEMPTS)
    occurred_at: datetime
    recalled_solutions: tuple[str, ...] = ()


class HealingAction(BaseModel):
    """A healer-proposed patch, not an automatically executed edit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    patch: str = Field(min_length=1, max_length=8_000)
    applied: bool = True
    rationale: str = Field(default="", max_length=2_000)


class HealingOutcome(BaseModel):
    """Terminal outcome of one guarded execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: HealingStatus
    value: Any = None
    attempts: int = Field(ge=0)
    failures: tuple[FailureReport, ...] = ()
    patch_applied: str | None = None

    @property
    def healed(self) -> bool:
        return self.status in {HealingStatus.SUCCEEDED, HealingStatus.HEALED}

    @property
    def last_failure(self) -> FailureReport | None:
        return self.failures[-1] if self.failures else None


class SelfHealingError(RuntimeError):
    """A guarded call did not succeed; the full outcome is attached."""

    def __init__(self, outcome: HealingOutcome) -> None:
        super().__init__(f"self-healing ended with {outcome.status.value}")
        self.outcome = outcome


Healer = Callable[[FailureReport], HealingAction | None]
Preflight = Callable[[], None]
PatchVerifier = Callable[[HealingAction], bool]
FailureCallback = Callable[[FailureReport], None]
Clock = Callable[[], datetime]
Sleeper = Callable[[float], None]


class AstraSelfHealingProxy:
    """Execute one operation under a bounded, evidence-first healing loop."""

    def __init__(
        self,
        agent_studio_callback: FailureCallback | None = None,
        *,
        healer: Healer | None = None,
        preflight: Preflight | None = None,
        verifier: PatchVerifier | None = None,
        memory: AstraMemoryEngine | None = None,
        max_attempts: int = 3,
        backoff_seconds: float = 0.1,
        max_identical_failures: int = 2,
        retry_transient: bool = True,
        redactor: SecretRedactor | None = None,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        if not 1 <= max_attempts <= MAX_ATTEMPTS:
            raise ValueError(f"max_attempts must be between 1 and {MAX_ATTEMPTS}")
        if not 0.0 <= backoff_seconds <= 60.0:
            raise ValueError("backoff_seconds must be between 0 and 60")
        if not 1 <= max_identical_failures <= 10:
            raise ValueError("max_identical_failures must be between 1 and 10")
        self.callback = agent_studio_callback
        self.healer = healer
        self.preflight = preflight
        self.verifier = verifier
        self.memory = memory
        self.max_attempts = max_attempts
        self.backoff_seconds = backoff_seconds
        self.max_identical_failures = max_identical_failures
        self.retry_transient = retry_transient
        self._redactor = redactor or SecretRedactor()
        self._clock = clock or _utcnow
        self._sleeper = sleeper or _sleep
        self._history: deque[FailureReport] = deque(maxlen=MAX_HISTORY)
        self._lock = RLock()
        self._callback_errors = 0
        self._memory_errors = 0

    @property
    def failure_history(self) -> tuple[FailureReport, ...]:
        with self._lock:
            return tuple(self._history)

    @property
    def callback_errors(self) -> int:
        with self._lock:
            return self._callback_errors

    @property
    def memory_errors(self) -> int:
        with self._lock:
            return self._memory_errors

    def reset_history(self) -> None:
        with self._lock:
            self._history.clear()

    def execute(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> HealingOutcome:
        """Run ``func`` with bounded healing and return an immutable outcome."""
        failures: list[FailureReport] = []
        last_patch: str | None = None
        attempted = 0
        for attempt in range(1, self.max_attempts + 1):
            attempted = attempt
            try:
                if self.preflight is not None:
                    self.preflight()
                value = func(*args, **kwargs)
            except Exception as exc:
                report = self._capture(exc, attempt)
                failures.append(report)
                self._notify(report)
                occurrences = self._record_occurrence(report)
                if occurrences > self.max_identical_failures:
                    return self._finish(HealingStatus.BLOCKED, failures, attempted, last_patch)
                if self.healer is not None:
                    try:
                        action = self.healer(report)
                    except Exception:
                        return self._finish(HealingStatus.FAILED, failures, attempted, last_patch)
                    if action is None or not action.applied:
                        return self._finish(HealingStatus.FAILED, failures, attempted, last_patch)
                    if self.verifier is not None and not self.verifier(action):
                        return self._finish(HealingStatus.FAILED, failures, attempted, last_patch)
                    last_patch = self._redactor.redact(action.patch)[:8_000]
                    self._remember_success(report, last_patch)
                    if attempt >= self.max_attempts:
                        return self._finish(
                            HealingStatus.EXHAUSTED, failures, attempted, last_patch
                        )
                    self._backoff(attempt)
                    continue
                if (
                    self.retry_transient
                    and report.category in {FailureCategory.TRANSIENT, FailureCategory.TIMEOUT}
                    and attempt < self.max_attempts
                ):
                    self._backoff(attempt)
                    continue
                return self._finish(HealingStatus.FAILED, failures, attempted, last_patch)
            else:
                status = HealingStatus.HEALED if failures else HealingStatus.SUCCEEDED
                return HealingOutcome(
                    status=status,
                    value=value,
                    attempts=attempt,
                    failures=tuple(failures),
                    patch_applied=last_patch,
                )
        return self._finish(HealingStatus.EXHAUSTED, failures, attempted, last_patch)

    def execute_with_guardrail(
        self, func: Callable[..., T], *args: Any, **kwargs: Any
    ) -> HealingOutcome:
        """Backward-compatible name for :meth:`execute`."""
        return self.execute(func, *args, **kwargs)

    def execute_or_raise(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Return the raw value or raise :class:`SelfHealingError`."""
        outcome = self.execute(func, *args, **kwargs)
        if not outcome.healed:
            raise SelfHealingError(outcome)
        return cast(T, outcome.value)

    def trigger_self_healing(self, error: str, trace: str) -> dict[str, object]:
        """Backward-compatible one-shot healing trigger used by older callers."""
        safe_error = self._redactor.redact(error)[:2_000] or "unknown error"
        report = FailureReport(
            fingerprint=self.fingerprint("UnhandledError", safe_error),
            error_type="UnhandledError",
            message=safe_error,
            traceback=self._redactor.redact(trace)[:8_000],
            category=FailureCategory.UNKNOWN,
            attempt=1,
            occurred_at=self._clock(),
        )
        if self.healer is None:
            return {"status": "UNRESOLVED", "patch_applied": None}
        try:
            action = self.healer(report)
        except Exception:
            return {"status": "FAILED", "patch_applied": None}
        if action is None or not action.applied:
            return {"status": "FAILED", "patch_applied": None}
        if self.verifier is not None and not self.verifier(action):
            return {"status": "FAILED", "patch_applied": None}
        patch = self._redactor.redact(action.patch)[:8_000]
        return {"status": "HEALED", "patch_applied": patch}

    @staticmethod
    def fingerprint(error_type: str, message: str) -> str:
        normalized = _HEX_ID_PATTERN.sub("#", message.casefold())
        normalized = _HEX_LITERAL_PATTERN.sub("#", normalized)
        normalized = _HEX_PATTERN.sub("#", normalized)
        normalized = _DIGITS_PATTERN.sub("#", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()[:500]
        return hashlib.sha256(f"{error_type}\0{normalized}".encode()).hexdigest()

    @staticmethod
    def classify(exc: BaseException) -> FailureCategory:
        if isinstance(exc, TimeoutError):
            return FailureCategory.TIMEOUT
        if isinstance(exc, PermissionError):
            return FailureCategory.PERMISSION
        if isinstance(exc, ConnectionError | OSError):
            return FailureCategory.TRANSIENT
        if isinstance(exc, AssertionError | KeyError | IndexError | TypeError | ValueError):
            return FailureCategory.VALIDATION
        return FailureCategory.UNKNOWN

    def _capture(self, exc: Exception, attempt: int) -> FailureReport:
        error_type = type(exc).__name__[:256]
        message = self._redactor.redact(f"{error_type}: {exc}")[:2_000]
        if not message:
            message = error_type
        trace = self._redactor.redact(traceback.format_exc())[:8_000]
        recalled = self._recall(f"{error_type} {message}")
        return FailureReport(
            fingerprint=self.fingerprint(error_type, message),
            error_type=error_type,
            message=message,
            traceback=trace,
            category=self.classify(exc),
            attempt=attempt,
            occurred_at=self._clock(),
            recalled_solutions=recalled,
        )

    def _recall(self, query: str) -> tuple[str, ...]:
        if self.memory is None:
            return ()
        try:
            matches = self.memory.search(query, limit=3)
        except Exception:
            with self._lock:
                self._memory_errors += 1
            return ()
        return tuple(match.entry.solution for match in matches)

    def _notify(self, report: FailureReport) -> None:
        if self.callback is None:
            return
        try:
            self.callback(report)
        except Exception:
            with self._lock:
                self._callback_errors += 1

    def _record_occurrence(self, report: FailureReport) -> int:
        with self._lock:
            self._history.append(report)
            return sum(1 for entry in self._history if entry.fingerprint == report.fingerprint)

    def _remember_success(self, report: FailureReport, patch: str) -> None:
        if self.memory is None:
            return
        try:
            self.memory.remember(
                f"{report.error_type}: {report.message}",
                patch,
                status=MemoryStatus.SUCCESS,
                tags=("self-healing", report.category.value),
                importance=0.7,
            )
        except Exception:
            with self._lock:
                self._memory_errors += 1

    def _remember_failure(self, failures: list[FailureReport], attempts: int) -> None:
        if self.memory is None or not failures:
            return
        last = failures[-1]
        try:
            self.memory.remember(
                f"{last.error_type}: {last.message}",
                f"unresolved after {attempts} attempt(s): {last.message}",
                status=MemoryStatus.FAILURE,
                tags=("self-healing", "unresolved", last.category.value),
                importance=0.4,
            )
        except Exception:
            with self._lock:
                self._memory_errors += 1

    def _finish(
        self,
        status: HealingStatus,
        failures: list[FailureReport],
        attempts: int,
        patch: str | None,
    ) -> HealingOutcome:
        self._remember_failure(failures, attempts)
        return HealingOutcome(
            status=status,
            attempts=attempts,
            failures=tuple(failures),
            patch_applied=patch,
        )

    def _backoff(self, attempt: int) -> None:
        if self.backoff_seconds > 0:
            self._sleeper(self.backoff_seconds * (2 ** (attempt - 1)))


__all__ = [
    "AstraSelfHealingProxy",
    "FailureCategory",
    "FailureReport",
    "HealingAction",
    "HealingOutcome",
    "HealingStatus",
    "MAX_ATTEMPTS",
    "SelfHealingError",
]
