from pathlib import Path

from astra_coder.intelligence import ContextItem, ContextPackage
from astra_coder.optimization import (
    ContextCache,
    ContextCompactor,
    HookRegistry,
    McpClient,
    McpResult,
    McpTool,
    ProjectMemory,
    ReadOnlySubAgent,
)


def package(path: str) -> ContextPackage:
    item = ContextItem(path=path, content="context", relevance=1)
    return ContextPackage(items=(item,), estimated_tokens=item.estimated_tokens)


def test_context_cache_is_bounded_lru() -> None:
    cache = ContextCache(max_entries=2)
    cache.put("a", package("a"))
    cache.put("b", package("b"))
    assert cache.get("a") is not None
    cache.put("c", package("c"))
    assert cache.get("b") is None
    assert cache.get("a") is not None


def test_compactor_deduplicates_and_respects_budget() -> None:
    result = ContextCompactor().compact(
        [
            ContextItem(path="a", content="low", relevance=0.1),
            ContextItem(path="a", content="higher", relevance=0.9),
            ContextItem(path="b", content="b" * 100, relevance=0.5),
        ],
        max_tokens=3,
    )
    assert result.items[0].content == "higher"
    assert result.estimated_tokens <= 3


def test_project_memory_is_read_only_and_bounded(tmp_path: Path) -> None:
    (tmp_path / "ASTRA.md").write_text("project conventions", encoding="utf-8")
    assert ProjectMemory(tmp_path).load() == "project conventions"
    (tmp_path / "ASTRA.md").write_text("x" * 20, encoding="utf-8")
    try:
        ProjectMemory(tmp_path, max_bytes=10).load()
    except ValueError as exc:
        assert "limit" in str(exc)
    else:
        raise AssertionError("oversized project memory accepted")


def test_hooks_are_ordered_and_payload_is_copied() -> None:
    events: list[str] = []
    hooks = HookRegistry()
    hooks.register("before_edit", lambda event, payload: events.append(f"{event}:{payload['id']}"))
    payload = {"id": "1"}
    hooks.emit("before_edit", payload)
    payload["id"] = "changed"
    assert events == ["before_edit:1"]


class FakeMcp:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_tools(self) -> tuple[McpTool, ...]:
        return (
            McpTool(name="search_docs", read_only=True),
            McpTool(name="delete_data", read_only=False),
        )

    def call(self, name: str, arguments: dict[str, str]) -> McpResult:
        self.calls.append(name)
        return McpResult(ok=True, output=arguments.get("q", ""))


def test_mcp_client_exposes_only_read_only_tools() -> None:
    transport = FakeMcp()
    client = McpClient(transport)
    assert [tool.name for tool in client.list_tools()] == ["search_docs"]
    assert client.call_read_only("search_docs", {"q": "hello"}).ok
    denied = client.call_read_only("delete_data", {})
    assert not denied.ok
    assert transport.calls == ["search_docs"]


def test_read_only_subagent_builds_context_without_write_tools(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def hello(): pass", encoding="utf-8")
    result = ReadOnlySubAgent(tmp_path).context("hello")
    assert result.items[0].path == "a.py"
    assert (tmp_path / "a.py").read_text(encoding="utf-8") == "def hello(): pass"
