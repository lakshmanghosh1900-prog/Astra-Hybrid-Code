"""Git worktree and rollback safety that never mutates the user's worktree."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class GitSafetyError(RuntimeError):
    """A Git safety operation failed or would be unsafe."""


class GitResult(BaseModel):
    returncode: int
    stdout: str = ""
    stderr: str = ""


class TaskWorkspace(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_id: str
    path: Path
    base_revision: str = Field(min_length=1)


class Checkpoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_id: str
    revision: str
    message: str


class GitRunner(Protocol):
    def run(self, argv: Sequence[str], cwd: Path) -> GitResult: ...


class SubprocessGitRunner:
    def run(self, argv: Sequence[str], cwd: Path) -> GitResult:
        git_binary = shutil.which("git")
        if git_binary is None:
            raise GitSafetyError("git executable is unavailable")
        try:
            completed = subprocess.run(  # noqa: S603
                [git_binary, *argv],
                cwd=cwd,
                capture_output=True,
                text=True,
                shell=False,
                check=False,
            )
        except OSError as exc:
            raise GitSafetyError(f"git could not start: {exc}") from exc
        return GitResult(
            returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
        )


class GitSafety:
    _TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

    def __init__(
        self,
        root: str | Path,
        *,
        worktree_parent: str | Path | None = None,
        runner: GitRunner | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise GitSafetyError("repository root must be a directory")
        self.runner = runner or SubprocessGitRunner()
        self.worktree_parent = (
            Path(worktree_parent).resolve()
            if worktree_parent is not None
            else self.root.parent / f".{self.root.name}.astra-worktrees"
        )
        self._workspaces: dict[str, TaskWorkspace] = {}
        self._ensure_repo()

    def create_worktree(self, task_id: str, base_revision: str | None = None) -> TaskWorkspace:
        self._validate_task_id(task_id)
        if task_id in self._workspaces:
            raise GitSafetyError("task worktree already exists")
        base = base_revision or self._git_text(["rev-parse", "HEAD"])
        self.worktree_parent.mkdir(parents=True, exist_ok=True)
        path = self.worktree_parent / task_id
        if path.exists():
            raise GitSafetyError("task worktree path already exists")
        self._git(["worktree", "add", "--detach", str(path), base])
        workspace = TaskWorkspace(task_id=task_id, path=path, base_revision=base)
        self._workspaces[task_id] = workspace
        return workspace

    def current_revision(self) -> str:
        """Return the repository revision that a task approval must bind to."""
        return self._git_text(["rev-parse", "HEAD"])

    def checkpoint(self, task_id: str, message: str) -> Checkpoint:
        workspace = self._workspace(task_id)
        if not message.strip() or "\n" in message:
            raise GitSafetyError("checkpoint message must be a single non-empty line")
        self._git(["add", "--all"], cwd=workspace.path)
        self._git(
            [
                "-c",
                "user.name=Astra Coder",
                "-c",
                "user.email=astra@localhost",
                "commit",
                "-m",
                message,
            ],
            cwd=workspace.path,
        )
        revision = self._git_text(["rev-parse", "HEAD"], cwd=workspace.path)
        return Checkpoint(task_id=task_id, revision=revision, message=message)

    def diff(self, task_id: str) -> str:
        workspace = self._workspace(task_id)
        return self._git_text(
            ["diff", f"{workspace.base_revision}..HEAD", "--"], cwd=workspace.path
        )

    def rollback(self, task_id: str) -> None:
        workspace = self._workspace(task_id)
        if workspace.path.resolve() == self.root:
            raise GitSafetyError("refusing to rollback the user's root worktree")
        self._git(["worktree", "remove", "--force", str(workspace.path)])
        self._git(["worktree", "prune"])
        self._workspaces.pop(task_id, None)

    def status_porcelain(self) -> str:
        return self._git_text(["status", "--porcelain=v1", "-z"])

    def task_status_porcelain(self, task_id: str) -> str:
        self._validate_task_id(task_id)
        path = self.worktree_parent / task_id
        if path.resolve() != path or path == self.root:
            raise GitSafetyError("refusing to read root status as task status")
        registered = self._git_text(["worktree", "list", "--porcelain", "-z"]).split("\x00")
        if not path.is_dir() or not any(
            entry.startswith("worktree ") and Path(entry[9:]) == path for entry in registered
        ):
            raise GitSafetyError("unknown task workspace")
        common_dir = ["rev-parse", "--path-format=absolute", "--git-common-dir"]
        if Path(self._git_text(common_dir, cwd=path)) != Path(self._git_text(common_dir)):
            raise GitSafetyError("task workspace belongs to another repository")
        if Path(self._git_text(["rev-parse", "--show-toplevel"], cwd=path)) != path:
            raise GitSafetyError("task workspace is not a worktree root")
        return self._git_text(["status", "--porcelain=v1", "-z"], cwd=path)

    def _workspace(self, task_id: str) -> TaskWorkspace:
        try:
            return self._workspaces[task_id]
        except KeyError as exc:
            raise GitSafetyError("unknown task workspace") from exc

    def _ensure_repo(self) -> None:
        self._git(["rev-parse", "--show-toplevel"])

    def _validate_task_id(self, task_id: str) -> None:
        if not self._TASK_ID.fullmatch(task_id):
            raise GitSafetyError("task id contains unsafe path characters")

    def _git_text(self, argv: Sequence[str], cwd: Path | None = None) -> str:
        result = self._git(argv, cwd=cwd)
        return result.stdout.strip()

    def _git(self, argv: Sequence[str], cwd: Path | None = None) -> GitResult:
        result = self.runner.run(argv, cwd or self.root)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:2_000]
            raise GitSafetyError(f"git command failed: {detail}")
        return result
