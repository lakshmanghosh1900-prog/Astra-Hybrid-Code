"""Trusted stdin/JSON tool entry point, invoked as python -I -m inside Docker."""

from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .tools import (
    ReadFileInput,
    RunCommandInput,
    SearchInput,
    SubprocessExecutor,
    ToolError,
    ToolMesh,
    ToolResult,
    WritePatchInput,
)

ToolName = Literal["read_file", "write_patch", "search", "run_command", "run_tests", "git_diff"]
ToolInput = ReadFileInput | WritePatchInput | SearchInput | RunCommandInput


class SandboxToolCall(BaseModel):
    """Only tool inputs cross the boundary; success is computed by the tool mesh."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tool: ToolName
    arguments: dict[str, object] = Field(default_factory=dict)


def validate_tool_path(path: str, *, allow_root: bool = False) -> None:
    """Lexical validation shared with the adapter, without touching host files."""
    parts = path.split("/")
    if (
        not path
        or PurePosixPath(path).is_absolute()
        or "\\" in path
        or ":" in path
        or ".." in parts
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise ToolError("tool paths must be safe relative POSIX paths")
    if any(part.casefold().rstrip(" .") == ".git" for part in parts):
        raise ToolError("access to .git metadata is not accepted")
    if not allow_root and not PurePosixPath(path).parts:
        raise ToolError("a file path is required")


def validate_tool_call(call: SandboxToolCall) -> ToolInput | None:
    """Revalidate typed arguments at the container trust boundary."""
    if call.tool == "read_file":
        read = ReadFileInput.model_validate(call.arguments, strict=True)
        validate_tool_path(read.path)
        return read
    if call.tool == "write_patch":
        write = WritePatchInput.model_validate(call.arguments, strict=True)
        validate_tool_path(write.path)
        return write
    if call.tool == "search":
        return SearchInput.model_validate(call.arguments, strict=True)
    if call.tool in {"run_command", "run_tests"}:
        command = RunCommandInput.model_validate(call.arguments, strict=True)
        validate_tool_path(command.cwd, allow_root=True)
        return command
    if call.arguments:
        raise ToolError("git_diff does not accept arguments")
    return None


def dispatch_tool(payload: str, *, root: str | Path = "/workspace") -> ToolResult:
    """Execute one validated call in the sandbox; never used by the host adapter."""
    try:
        call = SandboxToolCall.model_validate_json(payload)
        request = validate_tool_call(call)
        mesh = ToolMesh(root, executor=SubprocessExecutor())
        if call.tool == "read_file" and isinstance(request, ReadFileInput):
            return mesh.read_file(request)
        if call.tool == "write_patch" and isinstance(request, WritePatchInput):
            return mesh.write_patch(request)
        if call.tool == "search" and isinstance(request, SearchInput):
            return mesh.search(request)
        if call.tool == "run_command" and isinstance(request, RunCommandInput):
            return mesh.run_command(request)
        if call.tool == "run_tests" and isinstance(request, RunCommandInput):
            return mesh.run_tests(request)
        return mesh.git_diff()
    except ValidationError:
        # Do not echo potentially sensitive file contents from invalid payloads.
        return ToolResult(ok=False, error="invalid sandbox tool request")
    except (ToolError, OSError, UnicodeError, ValueError) as exc:
        return ToolResult(ok=False, error=str(exc))


def main() -> int:
    result = dispatch_tool(sys.stdin.read())
    sys.stdout.write(result.model_dump_json() + "\n")
    # Tool failures are conveyed by ToolResult; a nonzero helper exit denotes a
    # transport/runtime failure rather than a failed repository command.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
