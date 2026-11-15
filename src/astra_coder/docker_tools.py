"""Docker-only ToolMesh: every repository operation runs in the trusted image."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from .sandbox import DockerSandbox, SandboxLimits, SandboxRequest
from .sandbox_tools import SandboxToolCall, ToolName, validate_tool_call
from .tools import (
    ReadFileInput,
    RunCommandInput,
    SearchInput,
    ToolError,
    ToolMesh,
    ToolResult,
    WritePatchInput,
)


class DockerToolMesh(ToolMesh):
    """Keep the typed tool interface while doing no repository I/O on the host."""

    def __init__(
        self,
        root: str | Path,
        image: str,
        *,
        sandbox: DockerSandbox | None = None,
        boundary_guard: Callable[[], None] | None = None,
        remaining_seconds: Callable[[], float] | None = None,
        workspace_volume: str | None = None,
        volume_subpath: str | None = None,
        read_only_workspace: bool = False,
        timeout_seconds: float = 120.0,
        limits: SandboxLimits | None = None,
    ) -> None:
        # PathGuard only checks the workspace directory here. Target paths are
        # resolved exclusively by the trusted helper inside the container.
        super().__init__(root)
        self._sandbox = sandbox if sandbox is not None else DockerSandbox()
        self._boundary_guard = boundary_guard
        self._remaining_seconds = remaining_seconds
        self._request = SandboxRequest(
            image=image,
            argv=["python", "-I", "-m", "astra_coder.sandbox_tools"],
            workspace=self.guard.root,
            workspace_volume=workspace_volume,
            volume_subpath=volume_subpath,
            read_only_workspace=read_only_workspace,
            timeout_seconds=timeout_seconds,
            limits=limits if limits is not None else SandboxLimits(),
        )

    def _dispatch(
        self,
        tool: ToolName,
        arguments: dict[str, object],
        *,
        command_timeout: float | None = None,
    ) -> ToolResult:
        if self._boundary_guard is not None:
            self._boundary_guard()
        try:
            call = SandboxToolCall(tool=tool, arguments=arguments)
            validate_tool_call(call)
            request = SandboxRequest.model_validate(
                {
                    **self._request.model_dump(),
                    "stdin": call.model_dump_json(),
                    "read_only_workspace": self._request.read_only_workspace
                    or tool in {"read_file", "search", "git_diff"},
                    "timeout_seconds": (
                        max(self._request.timeout_seconds, command_timeout + 5)
                        if command_timeout is not None
                        else self._request.timeout_seconds
                    ),
                }
            )
            if self._remaining_seconds is not None:
                request = SandboxRequest.model_validate(
                    {
                        **request.model_dump(),
                        "timeout_seconds": min(request.timeout_seconds, self._remaining_seconds()),
                    }
                )
            result = self._sandbox.run(request)
            if not result.ok:
                return ToolResult(
                    ok=False,
                    output=result.output,
                    error=result.error or "Docker sandbox execution failed",
                    exit_code=result.exit_code,
                )
            try:
                return ToolResult.model_validate_json(result.output, strict=True)
            except ValidationError:
                return ToolResult(ok=False, error="invalid sandbox tool response")
        except (ToolError, OSError, ValueError) as exc:
            return ToolResult(ok=False, error=str(exc))

    def read_file(self, request: ReadFileInput) -> ToolResult:
        return self._dispatch("read_file", request.model_dump())

    def write_patch(self, request: WritePatchInput) -> ToolResult:
        with self._write_lock:
            return self._dispatch("write_patch", request.model_dump())

    def search(self, request: SearchInput) -> ToolResult:
        return self._dispatch("search", request.model_dump())

    def run_command(self, request: RunCommandInput) -> ToolResult:
        return self._dispatch(
            "run_command", request.model_dump(), command_timeout=request.timeout_seconds
        )

    def run_tests(self, request: RunCommandInput) -> ToolResult:
        return self._dispatch(
            "run_tests", request.model_dump(), command_timeout=request.timeout_seconds
        )

    def git_diff(self) -> ToolResult:
        return self._dispatch("git_diff", {})
