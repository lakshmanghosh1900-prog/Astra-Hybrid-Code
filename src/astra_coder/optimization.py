"""Context/cost optimization and read-only extension boundaries."""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from .intelligence import ContextBudgeter, ContextItem, ContextPackage, RepositoryIndexer


class ContextCache:
    """Bounded in-memory cache keyed by a stable context request hash."""

    def __init__(self, max_entries: int = 128) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._items: OrderedDict[str, ContextPackage] = OrderedDict()

    def get(self, key: str) -> ContextPackage | None:
        item = self._items.get(key)
        if item is not None:
            self._items.move_to_end(key)
        return item

    def put(self, key: str, value: ContextPackage) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)

    @staticmethod
    def key(*parts: str) -> str:
        return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


class ContextCompactor:
    def __init__(self, budgeter: ContextBudgeter | None = None) -> None:
        self.budgeter = budgeter or ContextBudgeter()

    def compact(self, items: Iterable[ContextItem], max_tokens: int) -> ContextPackage:
        deduped: dict[str, ContextItem] = {}
        for item in items:
            previous = deduped.get(item.path)
            if previous is None or item.relevance > previous.relevance:
                deduped[item.path] = item
        return self.budgeter.build(list(deduped.values()), max_tokens)


class ProjectMemory:
    """Read-only ASTRA.md project memory; it cannot modify policy or tools."""

    def __init__(
        self, root: str | Path, filename: str = "ASTRA.md", max_bytes: int = 100_000
    ) -> None:
        self.root = Path(root).resolve()
        self.filename = filename
        self.max_bytes = max_bytes

    def load(self) -> str:
        path = self.root / self.filename
        if not path.exists():
            return ""
        if path.is_symlink() or not path.is_file():
            raise ValueError("project memory must be a regular file")
        raw = path.read_bytes()
        if len(raw) > self.max_bytes:
            raise ValueError("project memory exceeds configured limit")
        return raw.decode("utf-8", errors="replace")


Hook = Callable[[str, dict[str, str]], None]


class HookRegistry:
    def __init__(self) -> None:
        self._hooks: dict[str, list[Hook]] = {}

    def register(self, event: str, hook: Hook) -> None:
        if not event or not event.isidentifier():
            raise ValueError("hook event must be an identifier")
        self._hooks.setdefault(event, []).append(hook)

    def emit(self, event: str, payload: dict[str, str]) -> None:
        for hook in self._hooks.get(event, []):
            hook(event, dict(payload))


class McpTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=128)
    read_only: bool


class McpResult(BaseModel):
    ok: bool
    output: str = ""
    error: str | None = None


class McpTransport(Protocol):
    def list_tools(self) -> tuple[McpTool, ...]: ...

    def call(self, name: str, arguments: dict[str, str]) -> McpResult: ...


class McpClient:
    """MCP boundary that exposes only declared read-only tools to sub-agents."""

    def __init__(self, transport: McpTransport) -> None:
        self.transport = transport
        self._tools = {tool.name: tool for tool in transport.list_tools() if tool.read_only}

    def list_tools(self) -> tuple[McpTool, ...]:
        return tuple(self._tools.values())

    def call_read_only(self, name: str, arguments: dict[str, str]) -> McpResult:
        tool = self._tools.get(name)
        if tool is None:
            return McpResult(ok=False, error="MCP tool is unknown or not read-only")
        return self.transport.call(tool.name, arguments)


@dataclass(frozen=True, slots=True)
class ReadOnlySubAgent:
    root: Path

    def context(self, query: str, max_tokens: int = 8_000) -> ContextPackage:
        index = RepositoryIndexer(self.root).index()
        items = [
            ContextItem(
                path=file.path,
                content=file.text,
                relevance=1.0 if query.lower() in file.text.lower() else 0.1,
            )
            for file in index.files.values()
        ]
        return ContextCompactor().compact(items, max_tokens)
