"""Docker sandbox contract with fail-closed defaults and bounded execution."""

from __future__ import annotations

import shutil
import subprocess
import uuid
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    stdin: str | None = None
    workspace_volume: str | None = Field(
        default=None, min_length=2, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]+$"
    )
    volume_subpath: str | None = Field(default=None, min_length=1, max_length=4_096)
    read_only_workspace: bool = False
    timeout_seconds: float = Field(default=120.0, gt=0, le=3_600)
    limits: SandboxLimits = Field(default_factory=SandboxLimits)

    @field_validator("volume_subpath")
    @classmethod
    def validate_volume_subpath(cls, value: str | None) -> str | None:
        if value is not None and (
            any(part in {"", ".", ".."} for part in value.split("/"))
            or any(character in value for character in "\\,:")
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("volume_subpath must be a safe, nonempty relative POSIX path")
        return value

    @model_validator(mode="after")
    def validate_volume_scope(self) -> SandboxRequest:
        if (self.workspace_volume is None) != (self.volume_subpath is None):
            raise ValueError(
                "workspace_volume and a task-scoped volume_subpath are required together"
            )
        return self


class SandboxResult(BaseModel):
    ok: bool
    output: str = ""
    error: str | None = None
    exit_code: int | None = None
    timed_out: bool = False


class DockerRunner(Protocol):
    def run(
        self, argv: Sequence[str], timeout_seconds: float, stdin: str | None = None
    ) -> SandboxResult: ...


class SubprocessDockerRunner:
    def run(
        self, argv: Sequence[str], timeout_seconds: float, stdin: str | None = None
    ) -> SandboxResult:
        if len(argv) < 2 or argv[1] != "run":
            return SandboxResult(ok=False, error="sandbox runner accepts only docker run")
        container_name = f"astra-sandbox-{uuid.uuid4().hex}"
        command = [argv[0], "run", f"--name={container_name}", *argv[2:]]
        try:
            completed = subprocess.run(  # noqa: S603
                command,
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(ok=False, error="sandbox timed out", exit_code=124, timed_out=True)
        except OSError as exc:
            return SandboxResult(ok=False, error=f"docker could not start: {exc}")
        finally:
            # Killing the docker CLI on timeout does not stop its container. Always
            # remove this invocation's unique container, even after a failed launch.
            with suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(  # noqa: S603
                    [argv[0], "rm", "--force", container_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
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
        # --mount is writable by default; unlike -v, it does not accept bare rw.
        access = ",readonly" if request.read_only_workspace else ""
        if request.workspace_volume is not None:
            mount = (
                f"--mount=type=volume,src={request.workspace_volume},dst=/workspace,"
                f"volume-subpath={request.volume_subpath},volume-nocopy{access}"
            )
        else:
            if "," in str(workspace):
                raise ValueError("sandbox bind workspace must not contain commas")
            mount = f"--mount=type=bind,src={workspace},dst=/workspace{access}"
        return (
            binary,
            "run",
            "--rm",
            "--pull=never",
            *(("-i",) if request.stdin is not None else ()),
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--pids-limit={request.limits.pids}",
            f"--memory={request.limits.memory}",
            f"--cpus={request.limits.cpus}",
            "--user=10001:10001",
            mount,
            f"--tmpfs=/tmp:rw,noexec,nosuid,size={request.limits.tmpfs_size}",
            "--workdir=/workspace",
            request.image,
            *request.argv,
        )

    def run(self, request: SandboxRequest) -> SandboxResult:
        if not self.available:
            return SandboxResult(ok=False, error="Docker is unavailable; refusing host execution")
        if request.stdin is not None:
            return self._runner.run(
                self.command(request), request.timeout_seconds, stdin=request.stdin
            )
        # Keep runners using the original two-argument contract working when no
        # stdin is requested; never silently drop a trusted-helper payload.
        return self._runner.run(self.command(request), request.timeout_seconds)
