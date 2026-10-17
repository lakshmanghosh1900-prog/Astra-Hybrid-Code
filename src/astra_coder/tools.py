"""Typed, policy-friendly tool mesh with no implicit host shell execution."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from threading import Lock
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .intelligence import RepositoryIndexer, SearchMatch


class ToolError(RuntimeError):
    """A tool rejected input or could not complete safely."""


class ReadFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4_096)


class WritePatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4_096)
    content: str = Field(max_length=10_000_000)
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


ALLOWED_EXECUTABLES = frozenset({"pytest", "ruff", "mypy", "git", "rg", "python", "python3"})


class RunCommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    argv: list[str] = Field(min_length=1, max_length=32)
    cwd: str = "."
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not part or "\x00" in part for part in value):
            raise ValueError("command arguments must be non-empty and NUL-free")
        if value[0] not in ALLOWED_EXECUTABLES:
            raise ValueError("executable is not allowed by the tool mesh")
        if value[0] in {"python", "python3"} and any(
            arg in {"-c", "--command"} for arg in value[1:]
        ):
            raise ValueError("inline code execution is not accepted by the tool mesh")
        return value


class SearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern: str = Field(min_length=1, max_length=1_000)
    max_results: int = Field(default=100, gt=0, le=1_000)


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    output: str = ""
    error: str | None = None
    exit_code: int | None = None
    matches: tuple[SearchMatch, ...] = ()


class CommandExecutor(Protocol):
    def execute(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ToolResult: ...


class NoHostExecutor:
    """Default executor: forces callers to provide a sandbox-backed implementation."""

    def execute(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ToolResult:
        del argv, cwd, timeout_seconds
        return ToolResult(ok=False, error="no sandbox executor configured")


class SubprocessExecutor:
    """Explicit test/development executor; production calls should use DockerSandbox."""

    def execute(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ToolResult:
        try:
            completed = subprocess.run(  # noqa: S603
                list(argv),
                cwd=cwd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, error="command timed out", exit_code=124)
        except OSError as exc:
            return ToolResult(ok=False, error=f"command could not start: {exc}")
        output = (completed.stdout + completed.stderr)[:100_000]
        return ToolResult(
            ok=completed.returncode == 0, output=output, exit_code=completed.returncode
        )


class PathGuard:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ToolError("tool root must be an existing directory")

    def resolve(self, raw_path: str, *, allow_missing: bool = False) -> Path:
        candidate = Path(raw_path)
        if candidate.is_absolute():
            raise ToolError("absolute paths are not accepted")
        if "\x00" in raw_path:
            raise ToolError("NUL bytes are not accepted in paths")
        joined = self.root / candidate
        resolved = joined.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise ToolError("path escapes the tool root") from exc
        if not allow_missing and not resolved.exists():
            raise ToolError("path does not exist")
        self._reject_symlink_components(joined)
        return resolved

    def _reject_symlink_components(self, joined: Path) -> None:
        current = self.root
        relative = joined.relative_to(self.root)
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ToolError("symlink paths are not accepted")


class ToolMesh:
    """Single-writer typed tools; command execution is delegated to an executor."""

    def __init__(self, root: str | Path, executor: CommandExecutor | None = None) -> None:
        self.guard = PathGuard(root)
        self.executor = executor or NoHostExecutor()
        self._write_lock = Lock()

    def read_file(self, request: ReadFileInput) -> ToolResult:
        path = self.guard.resolve(request.path)
        try:
            return ToolResult(ok=True, output=path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            return ToolResult(ok=False, error=f"file could not be read: {exc}")

    def write_patch(self, request: WritePatchInput) -> ToolResult:
        with self._write_lock:
            path = self.guard.resolve(request.path, allow_missing=True)
            if request.expected_sha256 is not None:
                current = path.read_bytes() if path.exists() else b""
                digest = hashlib.sha256(current).hexdigest()
                if digest != request.expected_sha256:
                    return ToolResult(ok=False, error="expected base hash does not match")
            parent = path.parent
            parent.mkdir(parents=True, exist_ok=True)
            fd, temporary_name = tempfile.mkstemp(prefix=".astra-", dir=parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(request.content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                return ToolResult(ok=False, error=f"file could not be written: {exc}")
            return ToolResult(ok=True, output=str(path.relative_to(self.guard.root)))

    def run_command(self, request: RunCommandInput) -> ToolResult:
        cwd = self.guard.resolve(request.cwd)
        return self.executor.execute(request.argv, cwd, request.timeout_seconds)

    def run_tests(self, request: RunCommandInput) -> ToolResult:
        return self.run_command(request)

    def search(self, request: SearchInput) -> ToolResult:
        matches = RepositoryIndexer(self.guard.root).search(request.pattern, request.max_results)
        return ToolResult(ok=True, matches=matches, output=f"{len(matches)} matches")

    def git_diff(self) -> ToolResult:
        return self.run_command(RunCommandInput(argv=["git", "diff", "--", "."]))
