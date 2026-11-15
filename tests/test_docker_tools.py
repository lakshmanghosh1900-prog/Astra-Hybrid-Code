from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from astra_coder.docker_tools import DockerToolMesh
from astra_coder.sandbox import (
    DockerSandbox,
    SandboxRequest,
    SandboxResult,
    SubprocessDockerRunner,
)
from astra_coder.sandbox_tools import dispatch_tool
from astra_coder.tools import (
    ReadFileInput,
    RunCommandInput,
    SearchInput,
    ToolMesh,
    ToolResult,
    WritePatchInput,
)


class FakeSandbox(DockerSandbox):
    def __init__(self, result: SandboxResult | None = None) -> None:
        super().__init__(detect_docker=False)
        self.requests: list[SandboxRequest] = []
        self.result = result or SandboxResult(
            ok=True, output=ToolResult(ok=True, output="container evidence").model_dump_json()
        )

    def run(self, request: SandboxRequest) -> SandboxResult:
        self.requests.append(request)
        return self.result


def tool_payload(tool: str, **arguments: object) -> str:
    return json.dumps({"tool": tool, "arguments": arguments})


def test_write_patch_never_changes_host_repository(tmp_path: Path) -> None:
    existing = tmp_path / "existing.txt"
    existing.write_text("host original", encoding="utf-8")
    sandbox = FakeSandbox()
    mesh = DockerToolMesh(tmp_path, "astra:test", sandbox=sandbox)

    assert mesh.write_patch(WritePatchInput(path="existing.txt", content="secret payload")).ok
    assert mesh.write_patch(WritePatchInput(path="new/nested.txt", content="new file")).ok

    assert existing.read_text(encoding="utf-8") == "host original"
    assert not (tmp_path / "new").exists()
    request = sandbox.requests[0]
    assert request.argv == ["python", "-I", "-m", "astra_coder.sandbox_tools"]
    assert "secret payload" not in " ".join(request.argv)
    assert json.loads(request.stdin or "")["arguments"]["content"] == "secret payload"
    assert not request.read_only_workspace


@pytest.mark.parametrize(
    ("tool", "invoke"),
    [
        ("read_file", lambda mesh: mesh.read_file(ReadFileInput(path="missing-on-host.txt"))),
        ("write_patch", lambda mesh: mesh.write_patch(WritePatchInput(path="a", content="b"))),
        ("search", lambda mesh: mesh.search(SearchInput(pattern="needle"))),
        ("run_command", lambda mesh: mesh.run_command(RunCommandInput(argv=["python", "task.py"]))),
        ("run_tests", lambda mesh: mesh.run_tests(RunCommandInput(argv=["pytest", "-q"]))),
        ("git_diff", lambda mesh: mesh.git_diff()),
    ],
)
def test_every_tool_dispatches_without_host_tool_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    invoke: Callable[[DockerToolMesh], ToolResult],
) -> None:
    def reject_host_tool(*args: object, **kwargs: object) -> ToolResult:
        pytest.fail("host ToolMesh operation was used")

    for name in ("read_file", "write_patch", "search", "run_command", "run_tests", "git_diff"):
        monkeypatch.setattr(ToolMesh, name, reject_host_tool)
    sandbox = FakeSandbox()
    boundaries: list[str] = []
    mesh = DockerToolMesh(
        tmp_path,
        "astra:test",
        sandbox=sandbox,
        boundary_guard=lambda: boundaries.append(tool),
        workspace_volume="astra_repos",
        volume_subpath=".repo.astra-worktrees/task-123",
    )
    result = invoke(mesh)
    assert result.ok
    assert result.output == "container evidence"
    assert boundaries == [tool]
    assert len(sandbox.requests) == 1
    request = sandbox.requests[0]
    assert json.loads(request.stdin or "")["tool"] == tool
    assert request.workspace_volume == "astra_repos"
    assert request.volume_subpath == ".repo.astra-worktrees/task-123"
    assert request.read_only_workspace == (tool in {"read_file", "search", "git_diff"})


@pytest.mark.parametrize(
    "path",
    ["../outside", "/etc/passwd", "C:/outside", "a\\b", "a/../../b", "a\x00b", "."],
)
def test_invalid_paths_fail_before_sandbox_dispatch(tmp_path: Path, path: str) -> None:
    sandbox = FakeSandbox()
    mesh = DockerToolMesh(tmp_path, "astra:test", sandbox=sandbox)
    assert not mesh.read_file(ReadFileInput(path=path)).ok
    assert not mesh.write_patch(WritePatchInput(path=path, content="denied")).ok
    assert not sandbox.requests
    assert not dispatch_tool(tool_payload("read_file", path=path), root=tmp_path).ok
    assert not dispatch_tool(
        tool_payload("write_patch", path=path, content="denied"), root=tmp_path
    ).ok


@pytest.mark.parametrize("path", [".git", ".git/config", "a/.git/HEAD", ".GIT/config", ".git./x"])
def test_git_metadata_is_rejected_on_both_sides(tmp_path: Path, path: str) -> None:
    sandbox = FakeSandbox()
    mesh = DockerToolMesh(tmp_path, "astra:test", sandbox=sandbox)
    for tool, arguments in (
        ("read_file", {"path": path}),
        ("write_patch", {"path": path, "content": "denied"}),
        ("run_command", {"argv": ["pytest"], "cwd": path}),
    ):
        result = dispatch_tool(tool_payload(tool, **arguments), root=tmp_path)
        assert not result.ok
        assert ".git" in (result.error or "")
    assert not mesh.read_file(ReadFileInput(path=path)).ok
    assert not mesh.write_patch(WritePatchInput(path=path, content="denied")).ok
    assert not mesh.run_command(RunCommandInput(argv=["pytest"], cwd=path)).ok
    assert not sandbox.requests


def test_default_adapter_refuses_host_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("astra_coder.sandbox.shutil.which", lambda _name: None)
    mesh = DockerToolMesh(tmp_path, "astra:test")
    result = mesh.write_patch(WritePatchInput(path="never-created.txt", content="denied"))
    assert not result.ok
    assert "refusing host execution" in (result.error or "")
    assert not (tmp_path / "never-created.txt").exists()


def test_boundary_failure_prevents_dispatch(tmp_path: Path) -> None:
    def blocked() -> None:
        raise RuntimeError("approval revoked")

    sandbox = FakeSandbox()
    mesh = DockerToolMesh(tmp_path, "astra:test", sandbox=sandbox, boundary_guard=blocked)
    with pytest.raises(RuntimeError, match="approval revoked"):
        mesh.git_diff()
    assert not sandbox.requests


@pytest.mark.parametrize("output", ["not JSON", '{"ok": "true"}', '{"output": "missing status"}'])
def test_malformed_helper_result_cannot_report_success(tmp_path: Path, output: str) -> None:
    sandbox = FakeSandbox(SandboxResult(ok=True, output=output))
    result = DockerToolMesh(tmp_path, "astra:test", sandbox=sandbox).git_diff()
    assert not result.ok
    assert result.error == "invalid sandbox tool response"


def test_container_failure_cannot_be_overridden_by_json_success(tmp_path: Path) -> None:
    sandbox = FakeSandbox(
        SandboxResult(ok=False, output=ToolResult(ok=True).model_dump_json(), exit_code=124)
    )
    result = DockerToolMesh(tmp_path, "astra:test", sandbox=sandbox).git_diff()
    assert not result.ok
    assert result.exit_code == 124


@pytest.mark.parametrize("read_only", [False, True])
def test_named_volume_exposes_only_task_subpath(tmp_path: Path, read_only: bool) -> None:
    sandbox = DockerSandbox(docker_binary="docker")
    request = SandboxRequest(
        image="astra:test",
        argv=["python", "-I", "-m", "astra_coder.sandbox_tools"],
        workspace=tmp_path,
        workspace_volume="astra_repos",
        volume_subpath=".repo.astra-worktrees/task-123",
        read_only_workspace=read_only,
        stdin="sensitive stdin payload",
    )
    command = sandbox.command(request)
    mounts = [part for part in command if part.startswith("--mount=")]
    access = ",readonly" if read_only else ""
    assert mounts == [
        "--mount=type=volume,src=astra_repos,dst=/workspace,"
        f"volume-subpath=.repo.astra-worktrees/task-123,volume-nocopy{access}"
    ]
    for flag in (
        "--pull=never",
        "-i",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=10001:10001",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=128m",
    ):
        assert flag in command
    assert str(tmp_path) not in " ".join(command)
    assert "sensitive stdin payload" not in " ".join(command)
    with pytest.raises(ValueError, match="existing directory"):
        sandbox.command(request.model_copy(update={"workspace": tmp_path / "missing"}))


@pytest.mark.parametrize("read_only", [False, True])
def test_bind_mount_retains_workspace_and_requested_access(tmp_path: Path, read_only: bool) -> None:
    request = SandboxRequest(
        image="astra:test", argv=["pytest"], workspace=tmp_path, read_only_workspace=read_only
    )
    command = DockerSandbox(docker_binary="docker").command(request)
    access = ",readonly" if read_only else ""
    assert f"--mount=type=bind,src={tmp_path.resolve()},dst=/workspace{access}" in command
    assert "-i" not in command


@pytest.mark.parametrize(
    "subpath", ["", ".", "..", "a/../b", "/repo/task", "a//b", "a/", "a\\b", "C:/a", "a,b", "a\n"]
)
def test_unsafe_volume_subpaths_are_rejected(tmp_path: Path, subpath: str) -> None:
    with pytest.raises(ValidationError):
        SandboxRequest(
            image="astra:test",
            argv=["pytest"],
            workspace=tmp_path,
            workspace_volume="astra_repos",
            volume_subpath=subpath,
        )


@pytest.mark.parametrize(
    "volume", ["x", "../repos", "/repos", "repos,readonly", "repos volume", "-x"]
)
def test_unsafe_volume_names_are_rejected(tmp_path: Path, volume: str) -> None:
    with pytest.raises(ValidationError):
        SandboxRequest(
            image="astra:test",
            argv=["pytest"],
            workspace=tmp_path,
            workspace_volume=volume,
            volume_subpath="tasks/123",
        )


@pytest.mark.parametrize("scope", [{"workspace_volume": "astra_repos"}, {"volume_subpath": "task"}])
def test_volume_and_subpath_are_required_together(tmp_path: Path, scope: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        SandboxRequest.model_validate(
            {"image": "astra:test", "argv": ["pytest"], "workspace": tmp_path, **scope}
        )


def test_docker_sandbox_passes_stdin_to_runner(tmp_path: Path) -> None:
    calls: list[tuple[Sequence[str], float, str | None]] = []

    class Runner:
        def run(
            self, argv: Sequence[str], timeout_seconds: float, stdin: str | None = None
        ) -> SandboxResult:
            calls.append((argv, timeout_seconds, stdin))
            return SandboxResult(ok=True)

    request = SandboxRequest(
        image="astra:test", argv=["python"], workspace=tmp_path, stdin="private JSON"
    )
    assert DockerSandbox(runner=Runner(), docker_binary="docker").run(request).ok
    assert calls[0][2] == "private JSON"
    assert "private JSON" not in calls[0][0]


@pytest.mark.parametrize("timed_out", [False, True])
def test_runner_cleans_up_only_its_unique_container(
    monkeypatch: pytest.MonkeyPatch, timed_out: bool
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        if argv[1] == "run" and timed_out:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, stdout="container output", stderr="")

    monkeypatch.setattr("astra_coder.sandbox.subprocess.run", run)
    runner = SubprocessDockerRunner()
    names: list[str] = []
    for _ in range(2):
        result = runner.run(["docker", "run", "--rm", "astra:test"], 0.1, stdin="private JSON")
        assert result.ok == (not timed_out)
        assert result.timed_out == timed_out
        if timed_out:
            assert result.exit_code == 124
        launched, options = calls[-2]
        name = launched[2].removeprefix("--name=")
        assert name.startswith("astra-sandbox-")
        names.append(name)
        assert options["input"] == "private JSON"
        assert "private JSON" not in launched
        assert calls[-1][0] == ["docker", "rm", "--force", name]
        assert calls[-1][1]["timeout"] == 10
    assert names[0] != names[1]


def test_cleanup_failure_preserves_timeout_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        raise OSError("daemon unavailable during cleanup")

    monkeypatch.setattr("astra_coder.sandbox.subprocess.run", run)
    result = SubprocessDockerRunner().run(["docker", "run", "astra:test"], 0.1)
    assert result.timed_out
    assert result.exit_code == 124


@pytest.mark.parametrize(
    "payload",
    [
        "not JSON",
        tool_payload("unknown"),
        '{"tool":"git_diff","ok":true}',
        tool_payload("git_diff", ok=True),
        tool_payload("read_file", path="a", ok=True),
        tool_payload("write_patch", path="a", content=42),
        tool_payload("run_command", argv=["sh", "-c", "echo bypass"]),
        tool_payload("run_tests", argv=["python", "-c", "print('bypass')"]),
        tool_payload("run_command", argv=["pytest"], cwd="../outside"),
    ],
)
def test_helper_rejects_invalid_payloads_and_model_chosen_success(
    tmp_path: Path, payload: str
) -> None:
    assert not dispatch_tool(payload, root=tmp_path).ok
    assert not (tmp_path / "a").exists()


def test_helper_roundtrip_hash_and_search_exclude_git_metadata(tmp_path: Path) -> None:
    written = dispatch_tool(
        tool_payload("write_patch", path="file.txt", content="needle"), root=tmp_path
    )
    assert written.ok
    read = dispatch_tool(tool_payload("read_file", path="file.txt"), root=tmp_path)
    assert read.output == "needle"
    stale = dispatch_tool(
        tool_payload("write_patch", path="file.txt", content="changed", expected_sha256="0" * 64),
        root=tmp_path,
    )
    assert not stale.ok
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("needle hidden", encoding="utf-8")
    found = dispatch_tool(tool_payload("search", pattern="needle"), root=tmp_path)
    assert found.ok
    assert len(found.matches) == 1
    assert Path(found.matches[0].path) == Path("file.txt")


def test_helper_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("private", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        (workspace / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable on this filesystem")
    assert not dispatch_tool(tool_payload("read_file", path="link/secret"), root=workspace).ok
    assert not dispatch_tool(
        tool_payload("write_patch", path="link/secret", content="overwrite"), root=workspace
    ).ok
    assert (outside / "secret").read_text(encoding="utf-8") == "private"


def test_helper_command_failure_uses_executor_evidence(tmp_path: Path) -> None:
    (tmp_path / "task.py").write_text(
        "print('actual evidence')\nraise SystemExit(7)\n", encoding="utf-8"
    )
    result = dispatch_tool(tool_payload("run_command", argv=["python", "task.py"]), root=tmp_path)
    assert not result.ok
    assert result.exit_code == 7
    assert "actual evidence" in result.output


def test_isolated_helper_imports_editable_install_instead_of_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shadow = tmp_path / "astra_coder"
    shadow.mkdir()
    (shadow / "__init__.py").write_text(
        "raise RuntimeError('repository shadow imported')", encoding="utf-8"
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "astra_coder.sandbox_tools"],
        input=tool_payload("unknown"),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = ToolResult.model_validate_json(completed.stdout)
    assert not result.ok
    assert result.error == "invalid sandbox tool request"
