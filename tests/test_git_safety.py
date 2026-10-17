import shutil
import subprocess
from pathlib import Path

import pytest

from astra_coder.git_safety import GitSafety, GitSafetyError


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603, S607
        [shutil.which("git") or "git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "tests@example.invalid")
    git(root, "config", "user.name", "Astra Tests")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-qm", "initial")
    return root


def test_rollback_does_not_destroy_user_dirty_work(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "tracked.txt").write_text("user uncommitted work\n", encoding="utf-8")
    manager = GitSafety(root, worktree_parent=tmp_path / "worktrees")
    workspace = manager.create_worktree("task-1")
    (workspace.path / "agent.txt").write_text("agent change\n", encoding="utf-8")
    manager.rollback("task-1")
    assert (root / "tracked.txt").read_text(encoding="utf-8") == "user uncommitted work\n"
    assert not (root / "agent.txt").exists()
    assert not workspace.path.exists()


def test_checkpoint_is_scoped_to_task_worktree(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    manager = GitSafety(root, worktree_parent=tmp_path / "worktrees")
    workspace = manager.create_worktree("task-2")
    (workspace.path / "new.txt").write_text("new\n", encoding="utf-8")
    checkpoint = manager.checkpoint("task-2", "agent checkpoint")
    assert len(checkpoint.revision) == 40
    assert "new.txt" in manager.diff("task-2")
    assert not (root / "new.txt").exists()
    manager.rollback("task-2")


def test_unsafe_task_id_and_root_rollback_are_rejected(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    manager = GitSafety(root, worktree_parent=tmp_path / "worktrees")
    with pytest.raises(GitSafetyError):
        manager.create_worktree("../escape")
    workspace = manager.create_worktree("task-3")
    manager._workspaces["task-3"] = workspace.model_copy(update={"path": root})
    with pytest.raises(GitSafetyError, match="root worktree"):
        manager.rollback("task-3")
    # Clean up the actual task worktree after the safety assertion.
    manager._workspaces["task-3"] = workspace
    manager.rollback("task-3")
