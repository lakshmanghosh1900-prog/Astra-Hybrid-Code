"""Docker sandbox contract with fail-closed defaults and bounded execution."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class SandboxLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    memory: str = Field(default="512m", pattern=r"^[1-9][0-9]*[kKmMgG]$")
    cpus: float = Field(default=1.0, gt=0, le=32)
    pids: int = Field(default=128, gt=0, le=10_000)
    tmpfs_size: str = Field(default="128m", pattern=r"^[1-9][0-9]*[kKmMgG]$")


class SandboxRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    image: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*$")
    argv: list[str] = Field(min_length=1, max_length=64)
    workspace: Path
    timeout_seconds: float = Field(default=120.0, gt=0, le=3_600)
    limits: SandboxLimits = Field(default_factory=SandboxLimits)


class SandboxResult(BaseModel):
    ok: bool
    output: str = ""
    error: str | None = None
    exit_code: int | None = None
    timed_out: bool = False


class DockerRunner(Protocol):
    def run(self, argv: Sequence[str], timeout_seconds: float) -> SandboxResult: ...


class SubprocessDockerRunner:
    def run(self, argv: Sequence[str], timeout_seconds: float) -> SandboxResult:
        try:
            completed = subprocess.run(  # noqa: S603
                list(argv),
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(ok=False, error="sandbox timed out", exit_code=124, timed_out=True)
        except OSError as exc:
            return SandboxResult(ok=False, error=f"docker could not start: {exc}")
        output = (completed.stdout + completed.stderr)[:200_000]
        return SandboxResult(
            ok=completed.returncode == 0, output=output, exit_code=completed.returncode
        )


class DockerSandbox:
    def __init__(
        self,
        runner: DockerRunner | None = None,
        docker_binary: str | None = None,
        *,
        detect_docker: bool = True,
    ) -> None:
        self._docker_binary = (docker_binary or shutil.which("docker")) if detect_docker else None
        self._runner = runner or SubprocessDockerRunner()

    @property
    def available(self) -> bool:
        return self._docker_binary is not None

    def command(self, request: SandboxRequest) -> tuple[str, ...]:
        workspace = request.workspace.resolve()
        if not workspace.is_dir():
            raise ValueError("sandbox workspace must be an existing directory")
        if self._docker_binary is None:
            binary = "docker"
        else:
            binary = self._docker_binary
        return (
            binary,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--pids-limit={request.limits.pids}",
            f"--memory={request.limits.memory}",
            f"--cpus={request.limits.cpus}",
            "--user=10001:10001",
            f"--mount=type=bind,src={workspace},dst=/workspace,rw",
            f"--tmpfs=/tmp:rw,noexec,nosuid,size={request.limits.tmpfs_size}",
            "--workdir=/workspace",
            request.image,
            *request.argv,
        )

    def run(self, request: SandboxRequest) -> SandboxResult:
        if not self.available:
            return SandboxResult(ok=False, error="Docker is unavailable; refusing host execution")
        return self._runner.run(self.command(request), request.timeout_seconds)
