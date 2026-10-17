from pathlib import Path

import pytest

from astra_coder.intelligence import ContextBudgeter, ContextItem, RepositoryIndexer


def test_indexer_extracts_symbols_imports_and_incremental_changes(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "import os\n\nclass App:\n    def run(self):\n        return os.getcwd()\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("hello Astra", encoding="utf-8")
    indexer = RepositoryIndexer(tmp_path)
    first = indexer.index()
    assert first.files["main.py"].symbols[0].name == "App"
    assert first.dependencies["main.py"] == ("os",)
    assert set(first.changed_paths) == {"main.py", "README.md"}

    second = indexer.index(first)
    assert second.changed_paths == ()
    (tmp_path / "main.py").write_text("def changed():\n    return 1\n", encoding="utf-8")
    third = indexer.index(second)
    assert third.changed_paths == ("main.py",)
    assert third.files["main.py"].symbols[0].name == "changed"


def test_search_is_bounded_and_rejects_invalid_regex(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("one\ntarget\ntarget\n", encoding="utf-8")
    indexer = RepositoryIndexer(tmp_path)
    matches = indexer.search("target", max_results=1)
    assert len(matches) == 1
    assert matches[0].line == 2
    with pytest.raises(ValueError):
        indexer.search("[", max_results=2)


def test_context_budgeter_prioritizes_relevance_and_truncates() -> None:
    package = ContextBudgeter().build(
        [
            ContextItem(path="low", content="l" * 40, relevance=0.1),
            ContextItem(path="high", content="h" * 40, relevance=1.0),
        ],
        max_tokens=12,
    )
    assert package.items[0].path == "high"
    assert package.estimated_tokens <= 12
    assert len(package.items[0].content) <= 48
