"""Deterministic repository indexing, search, and context budgeting."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import tree_sitter_python as tree_sitter_python
from pydantic import BaseModel, ConfigDict, Field
from tree_sitter import Language, Parser


class Symbol(BaseModel):
    path: str
    name: str
    kind: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class SearchMatch(BaseModel):
    path: str
    line: int = Field(ge=1)
    text: str


class FileIndex(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    sha256: str
    size: int = Field(ge=0)
    text: str
    symbols: tuple[Symbol, ...] = ()
    imports: tuple[str, ...] = ()


class IndexSnapshot(BaseModel):
    files: dict[str, FileIndex]
    dependencies: dict[str, tuple[str, ...]]
    changed_paths: tuple[str, ...] = ()


class ContextItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    content: str
    relevance: float = 0.0

    @property
    def estimated_tokens(self) -> int:
        return max(1, len(self.content) // 4)


class ContextPackage(BaseModel):
    items: tuple[ContextItem, ...]
    estimated_tokens: int = Field(ge=0)


class ContextBudgeter:
    def build(self, items: list[ContextItem], max_tokens: int) -> ContextPackage:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        selected: list[ContextItem] = []
        used = 0
        for item in sorted(items, key=lambda value: (-value.relevance, value.path)):
            available = max_tokens - used
            if available <= 0:
                break
            if item.estimated_tokens <= available:
                selected.append(item)
                used += item.estimated_tokens
                continue
            max_chars = max(4, available * 4)
            selected.append(item.model_copy(update={"content": item.content[:max_chars]}))
            used = max_tokens
            break
        return ContextPackage(items=tuple(selected), estimated_tokens=used)


class RepositoryIndexer:
    _IGNORED = frozenset({".git", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"})

    def __init__(self, root: str | Path, max_file_bytes: int = 1_000_000) -> None:
        self.root = Path(root).resolve()
        self.max_file_bytes = max_file_bytes
        self._parser = Parser(Language(tree_sitter_python.language()))

    def index(self, previous: IndexSnapshot | None = None) -> IndexSnapshot:
        if not self.root.is_dir():
            raise ValueError("repository root must be a directory")
        files: dict[str, FileIndex] = {}
        changed: list[str] = []
        for path in self._iter_files():
            relative = path.relative_to(self.root).as_posix()
            content_bytes = path.read_bytes()
            digest = hashlib.sha256(content_bytes).hexdigest()
            old = previous.files.get(relative) if previous else None
            if old is not None and old.sha256 == digest:
                files[relative] = old
                continue
            changed.append(relative)
            text = content_bytes.decode("utf-8", errors="replace")
            files[relative] = FileIndex(
                path=relative,
                sha256=digest,
                size=len(content_bytes),
                text=text,
                symbols=self._symbols(relative, content_bytes),
                imports=self._imports(relative, text),
            )
        dependencies = {path: file.imports for path, file in files.items() if file.imports}
        return IndexSnapshot(
            files=files, dependencies=dependencies, changed_paths=tuple(sorted(changed))
        )

    def search(self, pattern: str, max_results: int = 100) -> tuple[SearchMatch, ...]:
        if not pattern or max_results <= 0:
            return ()
        try:
            expression = re.compile(pattern)
        except re.error as exc:
            raise ValueError("invalid search pattern") from exc
        rg = shutil.which("rg")
        if rg:
            return self._search_rg(rg, pattern, max_results)
        matches: list[SearchMatch] = []
        for path in self._iter_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_number, line in enumerate(text.splitlines(), 1):
                if expression.search(line):
                    matches.append(
                        SearchMatch(
                            path=path.relative_to(self.root).as_posix(), line=line_number, text=line
                        )
                    )
                    if len(matches) >= max_results:
                        return tuple(matches)
        return tuple(matches)

    def _search_rg(self, rg: str, pattern: str, max_results: int) -> tuple[SearchMatch, ...]:
        completed = subprocess.run(  # noqa: S603
            [
                rg,
                "--line-number",
                "--color",
                "never",
                "--hidden",
                "--glob",
                "!.git",
                "--",
                pattern,
                ".",
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if completed.returncode not in (0, 1):
            raise ValueError("ripgrep search failed")
        matches: list[SearchMatch] = []
        for raw_line in completed.stdout.splitlines():
            path_text, separator, rest = raw_line.partition(":")
            line_text, separator, content = rest.partition(":")
            if not separator or not line_text.isdigit():
                continue
            matches.append(
                SearchMatch(path=path_text.removeprefix("./"), line=int(line_text), text=content)
            )
            if len(matches) >= max_results:
                break
        return tuple(matches)

    def _iter_files(self) -> Iterator[Path]:
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if any(part in self._IGNORED for part in path.relative_to(self.root).parts):
                continue
            if path.name.startswith(".env") or path.stat().st_size > self.max_file_bytes:
                continue
            yield path

    def _symbols(self, path: str, content: bytes) -> tuple[Symbol, ...]:
        if not path.endswith(".py"):
            return ()
        tree = self._parser.parse(content)
        symbols: list[Symbol] = []
        stack: list[Any] = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in {"function_definition", "class_definition"}:
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    symbols.append(
                        Symbol(
                            path=path,
                            name=name_node.text.decode("utf-8", errors="replace"),
                            kind=node.type.removesuffix("_definition"),
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                        )
                    )
            stack.extend(reversed(node.children))
        return tuple(sorted(symbols, key=lambda item: (item.start_line, item.name)))

    def _imports(self, path: str, text: str) -> tuple[str, ...]:
        if not path.endswith(".py"):
            return ()
        imports: list[str] = []
        for line in text.splitlines():
            match = re.match(r"^\s*(?:from\s+([\w.]+)|import\s+([\w.]+))", line)
            if match:
                imports.append(match.group(1) or match.group(2))
        return tuple(dict.fromkeys(imports))
