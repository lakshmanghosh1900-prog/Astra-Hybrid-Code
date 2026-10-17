from pathlib import Path

import pytest

from astra_coder.tools import (
    NoHostExecutor,
    PathGuard,
    ReadFileInput,
    RunCommandInput,
    ToolError,
    ToolMesh,
    ToolResult,
    WritePatchInput,
)


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], Path, float]] = []

    def execute(self, argv: list[str], cwd: Path, timeout_seconds: float) -> ToolResult:
        self.calls.append((argv, cwd, timeout_seconds))
        return ToolResult(ok=True, output="sandboxed")


def test_read_write_and_expected_hash(tmp_path: Path) -> None:
    mesh = ToolMesh(tmp_path)
    assert mesh.write_patch(WritePatchInput(path="a.txt", content="hello")).ok
    assert mesh.read_file(ReadFileInput(path="a.txt")).output == "hello"
    denied = mesh.write_patch(
        WritePatchInput(path="a.txt", content="new", expected_sha256="0" * 64)
    )
    assert not denied.ok
    assert mesh.read_file(ReadFileInput(path="a.txt")).output == "hello"


def test_path_traversal_and_absolute_path_are_rejected(tmp_path: Path) -> None:
    guard = PathGuard(tmp_path)
    with pytest.raises(ToolError):
        guard.resolve("../outside.txt", allow_missing=True)
    with pytest.raises(ToolError):
        guard.resolve(str(tmp_path / "outside.txt"), allow_missing=True)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "astra-outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable on this filesystem")
    with pytest.raises(ToolError):
        ToolMesh(tmp_path).read_file(ReadFileInput(path="link.txt"))


def test_command_schema_rejects_shell_injection_shape() -> None:
    with pytest.raises(ValueError):
        RunCommandInput(argv=["sh", "-c", "touch compromised"])
    with pytest.raises(ValueError):
        RunCommandInput(argv=["python", "-c", "a\x00b"])
    with pytest.raises(ValueError):
        RunCommandInput(argv=["curl", "https://example.test"])


def test_commands_are_delegated_and_never_host_run_by_default(tmp_path: Path) -> None:
    mesh = ToolMesh(tmp_path)
    result = mesh.run_command(RunCommandInput(argv=["pytest", "-q"]))
    assert not result.ok
    assert "sandbox executor" in (result.error or "")

    executor = FakeExecutor()
    mesh = ToolMesh(tmp_path, executor=executor)
    result = mesh.run_command(RunCommandInput(argv=["pytest", "-q"]))
    assert result.ok
    assert executor.calls[0][0] == ["pytest", "-q"]


def test_git_diff_uses_argv_and_no_host_executor(tmp_path: Path) -> None:
    result = ToolMesh(tmp_path, executor=NoHostExecutor()).git_diff()
    assert not result.ok
