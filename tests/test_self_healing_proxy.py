from datetime import UTC, datetime
from pathlib import Path

from astra_coder.memory_engine import AstraMemoryEngine, MemoryEngineError, MemoryStatus
from astra_coder.policy import Action, Actor, PolicyConfig, PolicyEngine, Role
from astra_coder.runtime import RiskTier
from astra_coder.self_healing_proxy import (
    AstraSelfHealingProxy,
    FailureCategory,
    FailureReport,
    HealingAction,
    HealingStatus,
    SelfHealingError,
)


def test_successful_call_passes_through() -> None:
    proxy = AstraSelfHealingProxy()
    outcome = proxy.execute_with_guardrail(lambda value: value * 2, 21)

    assert outcome.status is HealingStatus.SUCCEEDED
    assert outcome.healed
    assert outcome.value == 42
    assert outcome.attempts == 1
    assert outcome.last_failure is None


def test_healer_patch_is_applied_and_verified() -> None:
    state = {"calls": 0}

    def flaky() -> str:
        state["calls"] += 1
        if state["calls"] == 1:
            raise ValueError("boom")
        return "ok"

    proxy = AstraSelfHealingProxy(
        healer=lambda report: HealingAction(patch="replace boom", rationale=report.error_type),
        verifier=lambda action: "replace" in action.patch,
        backoff_seconds=0.0,
    )
    outcome = proxy.execute(flaky)

    assert outcome.status is HealingStatus.HEALED
    assert outcome.value == "ok"
    assert outcome.attempts == 2
    assert outcome.patch_applied == "replace boom"
    assert outcome.last_failure is not None
    assert outcome.last_failure.category is FailureCategory.VALIDATION


def test_healing_records_success_in_memory(tmp_path: Path) -> None:
    memory = AstraMemoryEngine(tmp_path / "memory.db")
    state = {"calls": 0}

    def flaky() -> str:
        state["calls"] += 1
        if state["calls"] == 1:
            raise ValueError("database locked")
        return "ok"

    proxy = AstraSelfHealingProxy(
        healer=lambda _report: HealingAction(patch="use WAL mode"),
        memory=memory,
        backoff_seconds=0.0,
    )
    assert proxy.execute(flaky).status is HealingStatus.HEALED

    results = memory.search("database locked")
    assert results and results[0].entry.solution == "use WAL mode"
    assert results[0].entry.status is MemoryStatus.SUCCESS
    memory.close()


def test_exhausted_healing_records_failure(tmp_path: Path) -> None:
    memory = AstraMemoryEngine(tmp_path / "memory.db")

    def always_fail() -> str:
        raise AssertionError("still broken")

    proxy = AstraSelfHealingProxy(
        healer=lambda _report: HealingAction(patch="best effort"),
        memory=memory,
        max_attempts=3,
        max_identical_failures=10,
        backoff_seconds=0.0,
    )
    outcome = proxy.execute(always_fail)

    assert outcome.status is HealingStatus.EXHAUSTED
    assert outcome.attempts == 3
    assert len(outcome.failures) == 3
    failures = memory.search("still broken", status=MemoryStatus.FAILURE)
    assert failures and failures[0].entry.status is MemoryStatus.FAILURE
    memory.close()


def test_no_healer_fails_after_first_non_transient_error() -> None:
    proxy = AstraSelfHealingProxy()

    def broken() -> str:
        raise ValueError("bad input")

    outcome = proxy.execute(broken)
    assert outcome.status is HealingStatus.FAILED
    assert outcome.attempts == 1
    assert len(outcome.failures) == 1


def test_transient_errors_retry_without_healer() -> None:
    state = {"calls": 0}

    def flaky() -> str:
        state["calls"] += 1
        if state["calls"] == 1:
            raise ConnectionError("network down")
        return "ok"

    proxy = AstraSelfHealingProxy(max_attempts=2, backoff_seconds=0.0)
    outcome = proxy.execute(flaky)

    assert outcome.status is HealingStatus.HEALED
    assert outcome.attempts == 2
    assert outcome.failures[0].category is FailureCategory.TRANSIENT


def test_transient_retry_can_be_disabled() -> None:
    def broken() -> str:
        raise ConnectionError("network down")

    proxy = AstraSelfHealingProxy(retry_transient=False)
    outcome = proxy.execute(broken)
    assert outcome.status is HealingStatus.FAILED
    assert outcome.attempts == 1


def test_rejected_patch_fails_closed() -> None:
    def broken() -> str:
        raise ValueError("bad")

    proxy = AstraSelfHealingProxy(
        healer=lambda _report: HealingAction(patch="unsafe"),
        verifier=lambda _action: False,
        backoff_seconds=0.0,
    )
    outcome = proxy.execute(broken)

    assert outcome.status is HealingStatus.FAILED
    assert outcome.patch_applied is None


def test_unapplied_patch_and_missing_patch_fail() -> None:
    def broken() -> str:
        raise ValueError("bad")

    for healer in (
        lambda _report: HealingAction(patch="fix", applied=False),
        lambda _report: None,
    ):
        outcome = AstraSelfHealingProxy(healer=healer).execute(broken)
        assert outcome.status is HealingStatus.FAILED

    raising = AstraSelfHealingProxy(
        healer=lambda _report: (_ for _ in ()).throw(RuntimeError("healer down"))
    ).execute(broken)
    assert raising.status is HealingStatus.FAILED


def test_identical_failure_loop_breaker_blocks() -> None:
    calls = {"count": 0}

    def broken() -> str:
        calls["count"] += 1
        raise ValueError(f"failure {calls['count']}")

    proxy = AstraSelfHealingProxy(
        healer=lambda _report: HealingAction(patch="fix"),
        max_attempts=3,
        max_identical_failures=2,
        backoff_seconds=0.0,
    )
    outcome = proxy.execute(broken)

    assert outcome.status is HealingStatus.BLOCKED
    assert outcome.attempts == 3
    assert len(proxy.failure_history) == 3


def test_keyboard_interrupt_is_never_swallowed() -> None:
    def interrupt() -> str:
        raise KeyboardInterrupt

    proxy = AstraSelfHealingProxy(healer=lambda _report: HealingAction(patch="fix"))
    try:
        proxy.execute(interrupt)
    except KeyboardInterrupt:
        pass
    else:
        raise AssertionError("KeyboardInterrupt was swallowed")


def test_callback_receives_failure_and_errors_are_counted() -> None:
    reports: list[FailureReport] = []

    def callback(report: FailureReport) -> None:
        reports.append(report)
        raise RuntimeError("callback failed")

    def broken() -> str:
        raise ValueError("bad")

    proxy = AstraSelfHealingProxy(agent_studio_callback=callback)
    outcome = proxy.execute(broken)

    assert outcome.status is HealingStatus.FAILED
    assert len(reports) == 1
    assert proxy.callback_errors == 1


def test_preflight_failure_is_classified() -> None:
    def denied() -> None:
        raise PermissionError("no access")

    proxy = AstraSelfHealingProxy(preflight=denied)
    outcome = proxy.execute(lambda: "never")

    assert outcome.status is HealingStatus.FAILED
    assert outcome.failures[0].category is FailureCategory.PERMISSION


def test_policy_preflight_denial_blocks_handler() -> None:
    policy = PolicyEngine(PolicyConfig(approval_min_risk=RiskTier.T0))
    actor = Actor(actor_id="developer-1", role=Role.DEVELOPER)
    calls = {"count": 0}

    def preflight() -> None:
        decision = policy.evaluate(actor, Action.EDIT, RiskTier.T0, "task-1")
        if not decision.allowed:
            raise PermissionError(decision.reason)

    def handler() -> str:
        calls["count"] += 1
        return "unreachable"

    outcome = AstraSelfHealingProxy(preflight=preflight).execute(handler)

    assert outcome.status is HealingStatus.FAILED
    assert outcome.last_failure is not None
    assert outcome.last_failure.category is FailureCategory.PERMISSION
    assert calls["count"] == 0


def test_recalled_solutions_are_available_to_healer(tmp_path: Path) -> None:
    memory = AstraMemoryEngine(tmp_path / "memory.db")
    first_state = {"calls": 0}

    def first_flaky() -> str:
        first_state["calls"] += 1
        if first_state["calls"] == 1:
            raise ValueError("cache miss")
        return "ok"

    first = AstraSelfHealingProxy(
        healer=lambda _report: HealingAction(patch="warm the cache"),
        memory=memory,
        backoff_seconds=0.0,
    )
    assert first.execute(first_flaky).status is HealingStatus.HEALED

    second_state = {"calls": 0}
    recalled: list[tuple[str, ...]] = []

    def second_flaky() -> str:
        second_state["calls"] += 1
        if second_state["calls"] == 1:
            raise ValueError("cache miss")
        return "ok"

    def healer(report: FailureReport) -> HealingAction:
        recalled.append(report.recalled_solutions)
        return HealingAction(patch="warm the cache again")

    second = AstraSelfHealingProxy(healer=healer, memory=memory, backoff_seconds=0.0)
    assert second.execute(second_flaky).status is HealingStatus.HEALED
    assert recalled and "warm the cache" in recalled[0]
    memory.close()


def test_memory_errors_are_counted_not_raised(tmp_path: Path) -> None:
    memory = AstraMemoryEngine(tmp_path / "memory.db")
    memory.close()

    def broken() -> str:
        raise ValueError("bad")

    proxy = AstraSelfHealingProxy(memory=memory)
    outcome = proxy.execute(broken)

    assert outcome.status is HealingStatus.FAILED
    assert proxy.memory_errors >= 2


def test_trigger_self_healing_compatibility() -> None:
    no_healer = AstraSelfHealingProxy()
    assert no_healer.trigger_self_healing("boom", "trace") == {
        "status": "UNRESOLVED",
        "patch_applied": None,
    }

    proxy = AstraSelfHealingProxy(healer=lambda _report: HealingAction(patch="fix"))
    result = proxy.trigger_self_healing("token=supersecretvalue", "trace")
    assert result["status"] == "HEALED"
    assert result["patch_applied"] == "fix"

    failing = AstraSelfHealingProxy(healer=lambda _report: None)
    assert failing.trigger_self_healing("boom", "trace")["status"] == "FAILED"

    raising = AstraSelfHealingProxy(
        healer=lambda _report: (_ for _ in ()).throw(RuntimeError("healer down"))
    )
    assert raising.trigger_self_healing("boom", "trace")["status"] == "FAILED"


def test_execute_or_raise() -> None:
    proxy = AstraSelfHealingProxy()
    assert proxy.execute_or_raise(lambda: "value") == "value"

    def broken() -> str:
        raise ValueError("bad")

    try:
        proxy.execute_or_raise(broken)
    except SelfHealingError as exc:
        assert exc.outcome.status is HealingStatus.FAILED
    else:
        raise AssertionError("execute_or_raise did not raise")


def test_fingerprint_normalizes_volatile_values() -> None:
    first = AstraSelfHealingProxy.fingerprint("ValueError", "id 123 failed at 0xdeadbeef")
    second = AstraSelfHealingProxy.fingerprint("ValueError", "id 999 failed at 0xcafebabe")
    different = AstraSelfHealingProxy.fingerprint("ValueError", "another message")

    assert first == second
    assert first != different
    assert len(first) == 64


def test_classification_and_reset() -> None:
    assert AstraSelfHealingProxy.classify(TimeoutError()) is FailureCategory.TIMEOUT
    assert AstraSelfHealingProxy.classify(PermissionError()) is FailureCategory.PERMISSION
    assert AstraSelfHealingProxy.classify(ConnectionError()) is FailureCategory.TRANSIENT
    assert AstraSelfHealingProxy.classify(TypeError()) is FailureCategory.VALIDATION
    assert AstraSelfHealingProxy.classify(RuntimeError()) is FailureCategory.UNKNOWN

    def broken() -> str:
        raise ValueError("bad")

    proxy = AstraSelfHealingProxy()
    proxy.execute(broken)
    assert proxy.failure_history
    proxy.reset_history()
    assert proxy.failure_history == ()


def test_configuration_validation() -> None:
    for call in (
        lambda: AstraSelfHealingProxy(max_attempts=0),
        lambda: AstraSelfHealingProxy(max_attempts=4),
        lambda: AstraSelfHealingProxy(backoff_seconds=-1),
        lambda: AstraSelfHealingProxy(max_identical_failures=0),
    ):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError("invalid proxy configuration was accepted")


def test_memory_failure_status_round_trip(tmp_path: Path) -> None:
    memory = AstraMemoryEngine(tmp_path / "memory.db")
    entry = memory.remember("context", "solution", status="FAILURE")
    assert entry.status is MemoryStatus.FAILURE
    memory.close()

    try:
        memory.remember("context", "solution")
    except MemoryEngineError:
        pass
    else:
        raise AssertionError("closed memory accepted a write")


def test_timestamp_clock_is_injected() -> None:
    fixed = datetime(2026, 3, 1, tzinfo=UTC)
    proxy = AstraSelfHealingProxy(clock=lambda: fixed)

    def broken() -> str:
        raise ValueError("bad")

    outcome = proxy.execute(broken)
    assert outcome.failures[0].occurred_at == fixed
