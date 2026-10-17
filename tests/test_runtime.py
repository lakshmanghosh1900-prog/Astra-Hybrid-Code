from astra_coder.runtime import (
    AgentLoop,
    CancellationToken,
    InvalidTransition,
    StepResult,
    Task,
    TaskLimits,
    TaskState,
    TaskStateMachine,
)


def test_state_machine_rejects_false_success() -> None:
    task = Task(prompt="do work", repo_path="/repo")
    try:
        TaskStateMachine.transition(task, TaskState.SUCCEEDED)
    except InvalidTransition:
        pass
    else:
        raise AssertionError("received task became successful without verification")


def test_bounded_loop_completes_valid_flow() -> None:
    task = Task(prompt="do work", repo_path="/repo", limits=TaskLimits(max_steps=12))
    states = iter(
        [
            TaskState.POLICY_CHECKED,
            TaskState.CONTEXT_BUILT,
            TaskState.PLANNED,
            TaskState.EDITING,
            TaskState.OBSERVING,
            TaskState.VERIFYING,
            TaskState.REVIEWING,
            TaskState.SUCCEEDED,
        ]
    )

    def handler(_task: Task, _token: CancellationToken) -> StepResult:
        state = next(states)
        return StepResult(next_state=state, tokens=5, done=state is TaskState.SUCCEEDED)

    result = AgentLoop().run(task, handler)
    assert result.state is TaskState.SUCCEEDED
    assert result.steps == 8
    assert result.tokens == 40


def test_loop_stops_at_step_budget() -> None:
    task = Task(prompt="loop", repo_path="/repo", limits=TaskLimits(max_steps=1))

    def handler(_task: Task, _token: CancellationToken) -> StepResult:
        return StepResult(next_state=TaskState.POLICY_CHECKED)

    result = AgentLoop().run(task, handler)
    assert result.state is TaskState.FAILED
    assert result.failure_reason == "step budget exceeded"


def test_loop_honors_cancellation_before_work() -> None:
    task = Task(prompt="cancel", repo_path="/repo")
    token = CancellationToken()
    token.cancel("operator requested stop")

    def handler(_task: Task, _token: CancellationToken) -> StepResult:
        raise AssertionError("handler must not run after cancellation")

    result = AgentLoop().run(task, handler, token)
    assert result.state is TaskState.CANCELLED
    assert result.failure_reason == "operator requested stop"


def test_loop_enforces_token_budget() -> None:
    task = Task(prompt="tokens", repo_path="/repo", limits=TaskLimits(max_tokens=3))

    def handler(_task: Task, _token: CancellationToken) -> StepResult:
        return StepResult(next_state=TaskState.POLICY_CHECKED, tokens=4)

    result = AgentLoop().run(task, handler)
    assert result.state is TaskState.FAILED
    assert result.failure_reason == "token budget exceeded"


def test_loop_enforces_wall_clock_budget() -> None:
    now = [0.0]
    task = Task(prompt="time", repo_path="/repo", limits=TaskLimits(max_seconds=1.0))

    def clock() -> float:
        return now[0]

    def handler(_task: Task, _token: CancellationToken) -> StepResult:
        now[0] = 2.0
        return StepResult(next_state=TaskState.POLICY_CHECKED)

    result = AgentLoop(clock=clock).run(task, handler)
    assert result.state is TaskState.FAILED
    assert result.failure_reason == "wall-clock budget exceeded"
