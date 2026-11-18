import time

from astra_coder.agent_orchestrator import (
    AgentExecutionError,
    AgentRole,
    AgentStatus,
    AgentTask,
    AstraAgent,
    AstraOrchestrator,
    OrchestrationError,
)


def test_parallel_tasks_round_robin_and_report() -> None:
    seen: list[str] = []

    def first(task: AgentTask) -> str:
        seen.append("first")
        return f"first:{task.description}"

    def second(task: AgentTask) -> str:
        seen.append("second")
        return f"second:{task.description}"

    orchestrator = AstraOrchestrator(
        [
            AstraAgent("alpha", AgentRole.TESTER, first),
            AstraAgent("beta", AgentRole.REVIEWER, second),
        ]
    )
    report = orchestrator.run_parallel_tasks(["one", "two", "three"])

    assert report.total == 3
    assert report.succeeded == 3
    assert report.failed == report.timed_out == report.cancelled == 0
    assert report.all_succeeded
    assert report.duration_seconds >= 0
    assert [result.agent_name for result in report.results] == ["alpha", "beta", "alpha"]
    assert sorted(seen) == ["first", "first", "second"]


def test_failure_is_isolated_and_redacted() -> None:
    def broken(_task: AgentTask) -> str:
        raise ValueError("token=supersecretvalue123")

    orchestrator = AstraOrchestrator(
        [
            AstraAgent("broken", AgentRole.DEBUGGER, broken),
            AstraAgent("healthy", AgentRole.TESTER, lambda task: task.description),
        ]
    )
    report = orchestrator.run_parallel_tasks(["a", "b"])

    assert report.succeeded == 1
    assert report.failed == 1
    assert report.results[0].status is AgentStatus.FAILED
    assert "supersecretvalue123" not in (report.results[0].error or "")
    assert report.results[1].succeeded


def test_agent_retries_then_succeeds() -> None:
    calls: list[int] = []

    def flaky(_task: AgentTask) -> str:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("temporary")
        return "recovered"

    agent = AstraAgent("flaky", AgentRole.CODER, flaky, max_attempts=2)
    result = agent.execute(AgentTask(description="work"))

    assert result.succeeded
    assert result.attempts == 2
    assert result.output == "recovered"
    assert len(calls) == 2


def test_execute_task_success_and_failure() -> None:
    assert AstraAgent("echo", "tester").execute_task("hello").endswith("hello")
    agent = AstraAgent(
        "bad", AgentRole.TESTER, lambda _task: (_ for _ in ()).throw(ValueError("x"))
    )
    try:
        agent.execute_task("work")
    except AgentExecutionError as exc:
        assert exc.result.status is AgentStatus.FAILED
    else:
        raise AssertionError("execute_task did not raise on failure")


def test_timeout_produces_terminal_result() -> None:
    def slow(_task: AgentTask) -> str:
        time.sleep(0.2)
        return "late"

    orchestrator = AstraOrchestrator([AstraAgent("slow", AgentRole.TESTER, slow)])
    report = orchestrator.run_parallel_tasks(["work"], timeout_seconds=0.01)

    assert report.timed_out == 1
    assert report.results[0].status is AgentStatus.TIMED_OUT
    assert "deadline" in (report.results[0].error or "")


def test_fail_fast_cancels_pending_work() -> None:
    calls: list[str] = []

    def handler(task: AgentTask) -> str:
        calls.append(task.description)
        if task.description == "fail":
            raise RuntimeError("boom")
        time.sleep(0.1)
        return "late"

    orchestrator = AstraOrchestrator(
        [AstraAgent("worker", AgentRole.TESTER, handler)],
        fail_fast=True,
        max_workers=1,
    )
    report = orchestrator.run_parallel_tasks(["fail", "pending"])

    assert report.failed == 1
    assert report.cancelled == 1
    assert calls[0] == "fail"


def test_validation_and_registration_bounds() -> None:
    orchestrator = AstraOrchestrator()
    for call in (
        lambda: AstraAgent("bad name", AgentRole.TESTER),
        lambda: AstraAgent("name", "unknown"),
        lambda: AstraAgent("name", AgentRole.TESTER, max_attempts=0),
        lambda: AstraAgent("name", AgentRole.TESTER, retry_backoff_seconds=-1),
        lambda: AstraOrchestrator(max_workers=0),
        lambda: AstraOrchestrator(default_timeout_seconds=0),
    ):
        try:
            call()
        except ValueError:
            continue
        raise AssertionError("invalid agent configuration was accepted")

    agent = AstraAgent("unique", AgentRole.TESTER)
    orchestrator.register_agent(agent)
    try:
        orchestrator.register_agent(agent)
    except OrchestrationError:
        pass
    else:
        raise AssertionError("duplicate agent was registered")

    try:
        AstraOrchestrator().run_parallel_tasks(["work"])
    except OrchestrationError:
        pass
    else:
        raise AssertionError("orchestrator ran without agents")

    try:
        orchestrator.run_parallel_tasks(["x"] * 1001)
    except OrchestrationError:
        pass
    else:
        raise AssertionError("task limit was not enforced")

    empty = orchestrator.run_parallel_tasks([])
    assert empty.total == 0
    assert not empty.all_succeeded
    assert orchestrator.agent_names() == ("unique",)
    assert orchestrator.get_agent("missing") is None


def test_default_handler_and_report_helpers() -> None:
    agent = AstraAgent("default", AgentRole.ARCHITECT)
    result = agent.execute(AgentTask(description="design"))
    assert result.succeeded
    assert "design" in (result.output or "")
    assert result.duration_seconds >= 0
    assert not result.succeeded or result.status is AgentStatus.SUCCEEDED


def test_handler_returning_empty_string_is_still_success() -> None:
    agent = AstraAgent("empty", AgentRole.TESTER, lambda _task: "")
    result = agent.execute(AgentTask(description="work"))
    assert result.succeeded
    assert result.output == ""


def test_timeout_validation() -> None:
    orchestrator = AstraOrchestrator([AstraAgent("agent", AgentRole.TESTER)])
    try:
        orchestrator.run_parallel_tasks(["work"], timeout_seconds=0)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid timeout was accepted")
