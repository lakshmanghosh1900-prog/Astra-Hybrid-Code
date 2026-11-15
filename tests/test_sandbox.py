from collections.abc import Sequence
from pathlib import Path

from astra_coder.sandbox import (
    DockerSandbox,
    SandboxRequest,
    SandboxResult,
)


class FakeRunner:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.argv: tuple[str, ...] | None = None
        self.timeout: float | None = None

    def run(
        self,
        argv: Sequence[str],
        timeout_seconds: float,
        stdin: str | None = None,
    ) -> SandboxResult:
        self.argv = tuple(argv)
        self.timeout = timeout_seconds
        return self.result


def request(tmp_path: Path) -> SandboxRequest:
    return SandboxRequest(image="astra:test", argv=["pytest", "-q"], workspace=tmp_path)


def test_command_has_defense_in_depth_flags(tmp_path: Path) -> None:
    sandbox = DockerSandbox(runner=FakeRunner(SandboxResult(ok=True)), docker_binary="docker")
    command = sandbox.command(request(tmp_path))
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges:true" in command
    assert "--pids-limit=128" in command
    assert "--memory=512m" in command
    assert "--cpus=1.0" in command
    assert "--user=10001:10001" in command
    assert command[-2:] == ("astra:test", "pytest") or command[-3:] == (
        "astra:test",
        "pytest",
        "-q",
    )


def test_runner_receives_timeout_and_returns_evidence(tmp_path: Path) -> None:
    runner = FakeRunner(SandboxResult(ok=True, output="passed", exit_code=0))
    sandbox = DockerSandbox(runner=runner, docker_binary="docker")
    result = sandbox.run(request(tmp_path))
    assert result.ok
    assert result.output == "passed"
    assert runner.timeout == 120.0
    assert runner.argv is not None


def test_unavailable_docker_fails_closed(tmp_path: Path) -> None:
    sandbox = DockerSandbox(
        runner=FakeRunner(SandboxResult(ok=True)), docker_binary=None, detect_docker=False
    )
    assert not sandbox.available
    result = sandbox.run(request(tmp_path))
    assert not result.ok
    assert "refusing host execution" in (result.error or "")


def test_timeout_is_machine_readable(tmp_path: Path) -> None:
    result = SandboxResult(ok=False, error="sandbox timed out", exit_code=124, timed_out=True)
    sandbox = DockerSandbox(runner=FakeRunner(result), docker_binary="docker")
    actual = sandbox.run(request(tmp_path))
    assert actual.timed_out
    assert actual.exit_code == 124
