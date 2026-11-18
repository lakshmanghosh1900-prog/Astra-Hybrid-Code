import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread

from astra_coder.memory_engine import (
    AstraMemoryEngine,
    MemoryEngineError,
    MemoryStatus,
)


def engine(
    tmp_path: Path, *, now: list[datetime] | None = None, **kwargs: object
) -> AstraMemoryEngine:
    clock = (lambda: now[0]) if now is not None else None
    return AstraMemoryEngine(
        tmp_path / "memory.db",
        clock=clock,
        **kwargs,  # type: ignore[arg-type]
    )


def test_save_and_recall_rank_by_overlap(tmp_path: Path) -> None:
    store = engine(tmp_path)
    store.save_memory("database connection timeout", "retry with backoff")
    store.save_memory("css alignment issue", "use flexbox")

    results = store.search("database connection timeout retry")

    assert results
    assert results[0].entry.solution == "retry with backoff"
    assert "database" in results[0].matched_terms
    legacy = store.recall_relevant_memories("database")
    assert legacy and legacy[0]["solution"] == "retry with backoff"
    store.close()


def test_identical_memories_are_deduplicated(tmp_path: Path) -> None:
    store = engine(tmp_path)
    first = store.save_memory("same context", "same solution")
    second = store.remember("same context", "same solution", importance=0.9)

    assert first.id == second.id
    assert second.hits == 1
    assert store.stats().total == 1
    store.close()


def test_namespace_isolation_and_status_filter(tmp_path: Path) -> None:
    store = engine(tmp_path)
    store.remember("alpha failure", "alpha fix", namespace="alpha", status="FAILURE")
    store.remember("beta success", "beta fix", namespace="beta", status="SUCCESS")

    assert store.search("failure", namespace="default") == ()
    alpha = store.search("failure", namespace="alpha")
    assert alpha and alpha[0].entry.namespace == "alpha"
    assert store.search("fix", namespace="alpha", status=MemoryStatus.SUCCESS) == ()
    beta = store.search("fix", namespace="beta", status="SUCCESS")
    assert beta and beta[0].entry.namespace == "beta"
    store.close()


def test_memories_survive_reopen(tmp_path: Path) -> None:
    first = engine(tmp_path)
    saved = first.remember("persisted context", "persisted fix", tags=("durable",))
    first.close()

    second = engine(tmp_path)
    results = second.search("persisted", tags=("durable",))

    assert results and results[0].entry.id == saved.id
    assert results[0].entry.tags == ("durable",)
    second.close()


def test_expiry_filter_and_prune(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = engine(tmp_path, now=now)
    store.remember("short lived", "fix", ttl_seconds=60)

    now[0] += timedelta(seconds=61)

    assert store.search("short lived") == ()
    expired = store.search("short lived", include_expired=True)
    assert expired and expired[0].entry.expires_at is not None
    stats = store.stats()
    assert stats.expired == 1 and stats.active == 0
    assert store.prune() == 1
    assert store.stats().total == 0
    store.close()


def test_default_ttl_is_applied(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = engine(tmp_path, now=now, default_ttl_seconds=30.0)
    entry = store.remember("ttl context", "ttl fix")

    assert entry.expires_at == now[0] + timedelta(seconds=30)
    store.close()


def test_retention_removes_low_importance_entries(tmp_path: Path) -> None:
    store = engine(tmp_path, max_entries=2)
    store.remember("low value", "low fix", importance=0.1)
    store.remember("high value", "high fix", importance=0.9)
    store.remember("medium value", "medium fix", importance=0.5)

    stats = store.stats()
    retained = {entry.context for entry in store.export()}
    assert stats.total == 2
    assert "low value" not in retained
    assert retained == {"high value", "medium value"}
    store.close()


def test_secrets_are_redacted_before_storage(tmp_path: Path) -> None:
    store = engine(tmp_path)
    entry = store.remember(
        "authorization: token=supersecretvalue123", "use api_key=anothersecretvalue"
    )

    assert "supersecretvalue123" not in entry.context
    assert "anothersecretvalue" not in entry.solution
    assert "[REDACTED]" in entry.context
    store.close()


def test_forget_export_and_namespace_stats(tmp_path: Path) -> None:
    store = engine(tmp_path)
    one = store.remember("one", "fix one", namespace="alpha")
    two = store.remember("two", "fix two", namespace="beta")

    assert store.stats().namespaces == ("alpha", "beta")
    assert store.forget(one.id)
    assert not store.forget(one.id)
    assert [entry.id for entry in store.export()] == [two.id]
    assert store.forget_namespace("beta") == 1
    assert store.export() == ()
    store.close()


def test_concurrent_writes_are_serialized(tmp_path: Path) -> None:
    store = engine(tmp_path)

    def writer(prefix: int) -> None:
        for index in range(10):
            store.remember(f"thread {prefix} context {index}", f"thread {prefix} fix {index}")

    threads = [Thread(target=writer, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert store.stats().total == 40
    store.close()


def test_invalid_inputs_and_closed_engine_fail_closed(tmp_path: Path) -> None:
    store = engine(tmp_path)
    for call in (
        lambda: store.remember("", "fix"),
        lambda: store.remember("context", ""),
        lambda: store.remember("context", "fix", importance=2.0),
        lambda: store.remember("context", "fix", ttl_seconds=0),
        lambda: store.remember("context", "fix", namespace="bad namespace"),
        lambda: store.remember("context", "fix", status="UNKNOWN"),
        lambda: store.search("query", limit=0),
    ):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError("invalid memory input was accepted")

    store.close()
    assert store.closed
    store.close()
    try:
        store.stats()
    except MemoryEngineError:
        pass
    else:
        raise AssertionError("closed engine accepted an operation")


def test_context_manager_closes_store(tmp_path: Path) -> None:
    with AstraMemoryEngine(tmp_path / "memory.db") as store:
        store.remember("context", "fix")
    assert store.closed


def test_unsupported_schema_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "memory.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 99")
    try:
        AstraMemoryEngine(path)
    except MemoryEngineError as exc:
        assert "schema" in str(exc)
    else:
        raise AssertionError("unsupported schema version was accepted")


def test_database_directory_error_is_wrapped(tmp_path: Path) -> None:
    try:
        AstraMemoryEngine(tmp_path)
    except MemoryEngineError:
        pass
    else:
        raise AssertionError("directory database path was accepted")


def test_empty_query_returns_no_matches(tmp_path: Path) -> None:
    store = engine(tmp_path)
    store.remember("context", "fix")
    assert store.search("   ") == ()
    assert store.search("!!!") == ()
    store.close()
