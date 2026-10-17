"""Independent verification gates and machine-readable evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class GateName(StrEnum):
    TESTS = "tests"
    LINT = "lint"
    TYPECHECK = "typecheck"
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"


class GateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"


class GateSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: GateName
    argv: tuple[str, ...] = Field(min_length=1)
    timeout_seconds: float = Field(default=600.0, gt=0, le=3_600)


class ProcessResult(BaseModel):
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    unavailable: bool = False
    timed_out: bool = False


class GateResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: GateName
    status: GateStatus
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float = Field(ge=0)
    findings: tuple[str, ...] = ()
    evidence_hash: str


class VerificationSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    workspace: str
    gates: tuple[GateResult, ...]
    evidence_hash: str

    @property
    def passed(self) -> bool:
        return bool(self.gates) and all(gate.status is GateStatus.PASSED for gate in self.gates)

    @property
    def failed_or_unavailable(self) -> tuple[GateResult, ...]:
        return tuple(gate for gate in self.gates if gate.status is not GateStatus.PASSED)


class VerificationRunner(Protocol):
    def run(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ProcessResult: ...


class UnavailableRunner:
    """Default runner; verification never silently executes on the host."""

    def run(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ProcessResult:
        del argv, cwd, timeout_seconds
        return ProcessResult(unavailable=True, stderr="sandbox verification runner unavailable")


class SubprocessVerificationRunner:
    """Explicit local runner for CI/development; production should inject a sandbox runner."""

    def run(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ProcessResult:
        try:
            completed = subprocess.run(  # noqa: S603
                list(argv),
                cwd=cwd,
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return ProcessResult(
                stdout=str(exc.stdout or ""), stderr=str(exc.stderr or ""), timed_out=True
            )
        except OSError as exc:
            return ProcessResult(unavailable=True, stderr=str(exc))
        return ProcessResult(
            exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
        )


def default_gates() -> tuple[GateSpec, ...]:
    return (
        GateSpec(name=GateName.TESTS, argv=("python", "-m", "pytest")),
        GateSpec(name=GateName.LINT, argv=("ruff", "check", "src", "tests")),
        GateSpec(name=GateName.TYPECHECK, argv=("mypy", "src")),
        GateSpec(name=GateName.SEMGREP, argv=("semgrep", "--config", "semgrep.yml", "--error")),
        GateSpec(name=GateName.GITLEAKS, argv=("gitleaks", "detect", "--no-banner", "--redact")),
    )


class VerificationIncomplete(RuntimeError):
    """Raised when callers try to claim success without passing all gates."""


class VerificationEngine:
    def __init__(
        self, runner: VerificationRunner | None = None, gates: tuple[GateSpec, ...] | None = None
    ) -> None:
        self.runner = runner or UnavailableRunner()
        self.gates = gates or default_gates()

    def run(self, workspace: str | Path) -> VerificationSummary:
        root = Path(workspace).resolve()
        if not root.is_dir():
            raise ValueError("verification workspace must be a directory")
        results: list[GateResult] = []
        for spec in self.gates:
            started = time.monotonic()
            process = self.runner.run(spec.argv, root, spec.timeout_seconds)
            duration = max(0.0, time.monotonic() - started)
            status = self._status(process)
            findings = self._findings(process)
            evidence_hash = self._hash(
                {
                    "name": spec.name,
                    "argv": spec.argv,
                    "status": status,
                    "exit_code": process.exit_code,
                    "stdout": process.stdout[:100_000],
                    "stderr": process.stderr[:100_000],
                }
            )
            results.append(
                GateResult(
                    name=spec.name,
                    status=status,
                    argv=spec.argv,
                    exit_code=process.exit_code,
                    stdout=process.stdout[:100_000],
                    stderr=process.stderr[:100_000],
                    duration_seconds=duration,
                    findings=findings,
                    evidence_hash=evidence_hash,
                )
            )
        overall = self._hash([result.model_dump(mode="json") for result in results])
        return VerificationSummary(workspace=str(root), gates=tuple(results), evidence_hash=overall)

    def require_success(self, summary: VerificationSummary) -> None:
        if not summary.passed:
            detail = ", ".join(
                f"{gate.name}={gate.status}" for gate in summary.failed_or_unavailable
            )
            raise VerificationIncomplete(f"verification did not pass: {detail}")

    @staticmethod
    def _status(process: ProcessResult) -> GateStatus:
        if process.unavailable:
            return GateStatus.UNAVAILABLE
        if process.timed_out:
            return GateStatus.TIMED_OUT
        return GateStatus.PASSED if process.exit_code == 0 else GateStatus.FAILED

    @staticmethod
    def _findings(process: ProcessResult) -> tuple[str, ...]:
        if process.exit_code in (None, 0):
            return ()
        lines = (process.stdout + "\n" + process.stderr).splitlines()
        return tuple(line.strip()[:500] for line in lines if line.strip())[:50]

    @staticmethod
    def _hash(value: object) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
