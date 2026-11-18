import shutil
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from astra_coder.agents import (
    ArchitectAgent,
    EditorAgent,
    IndependentReviewerAgent,
    Plan,
    PlanAction,
)
from astra_coder.memory_engine import AstraMemoryEngine, MemoryStatus
from astra_coder.orchestrator import OrchestrationBlocked, OrchestrationResult
from astra_coder.persistence import AuditLog, StateStore, TaskScope
from astra_coder.policy import Actor, PolicyConfig, PolicyEngine
from astra_coder.runtime import RiskTier, Task, TaskLimits, TaskState
from astra_coder.sandbox import DockerSandbox, SandboxResult
from astra_coder.service import SubmitRequest, TaskService
from astra_coder.tools import ToolResult
from astra_coder.verification import GateName, GateSpec, VerificationEngine
from astra_coder.worker import (
    DockerCommandExecutor,
    DockerOrchestratorFactory,
    DockerVerificationRunner,
    GitWorktreeFactory,
    PolicyExecutionGuard,
    TaskOrchestratorFactory,
    TaskWorker,
)


class RecordingDockerRunner:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.argv: tuple[str, ...] | None = None
        self.timeout: float | None = None
        self.calls: list[tuple[str, ...]] = []

    def run(
        self, argv: Sequence[str], timeout_seconds: float, stdin: str | None = None
    ) -> SandboxResult:
        self.argv = tuple(argv)
        self.timeout = timeout_seconds
        self.calls.append(tuple(argv))
        if stdin is not None:
            return SandboxResult(
                ok=True,
                exit_code=0,
                output=ToolResult(ok=self.result.ok, output=self.result.output).model_dump_json(),
            )
        return self.result


def docker_sandbox(result: SandboxResult) -> tuple[DockerSandbox, RecordingDockerRunner]:
    runner = RecordingDockerRunner(result)
    return DockerSandbox(runner=runner, docker_binary="docker"), runner


def make_git_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git = shutil.which("git") or "git"
    subprocess.run([git, "init", "-q"], cwd=root, check=True)  # noqa: S603
    subprocess.run(  # noqa: S603
        [git, "config", "user.email", "worker-tests@example.invalid"], cwd=root, check=True
    )
    subprocess.run(  # noqa: S603
        [git, "config", "user.name", "Astra Worker Tests"], cwd=root, check=True
    )
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    subprocess.run([git, "add", "tracked.txt"], cwd=root, check=True)  # noqa: S603
    subprocess.run([git, "commit", "-qm", "initial"], cwd=root, check=True)  # noqa: S603
    return root


def test_command_executor_uses_docker_and_scopes_nested_workdir(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    sandbox, runner = docker_sandbox(SandboxResult(ok=True, output="passed", exit_code=0))

    result = DockerCommandExecutor(tmp_path, "astra:test", sandbox=sandbox).execute(
        ("pytest", "-q"), nested, 7.5
    )

    assert result.ok
    assert result.output == "passed"
    assert result.error is None
    assert result.exit_code == 0
    assert result.matches == ()
    assert runner.timeout == 7.5
    assert runner.argv is not None
    assert any(
        entry.startswith("--mount=type=bind,src=")
        and entry.endswith(",dst=/workspace")
        and nested.name in entry
        for entry in runner.argv
    )
    assert runner.argv[-3:] == ("astra:test", "pytest", "-q")


def test_verification_runner_translates_sandbox_result() -> None:
    sandbox, runner = docker_sandbox(
        SandboxResult(ok=False, output="stdout", error="stderr", exit_code=3)
    )

    result = DockerVerificationRunner(Path.cwd(), "astra:test", sandbox=sandbox).run(
        ("pytest", "-q"), Path.cwd(), 12.0
    )

    assert result.exit_code == 3
    assert result.stdout == "stdout"
    assert result.stderr == "stderr"
    assert not result.unavailable
    assert not result.timed_out
    assert runner.timeout == 12.0
    assert runner.argv is not None and runner.argv[-3:] == ("astra:test", "pytest", "-q")


def test_gitleaks_gate_mounts_read_only_git_metadata(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    sandbox, runner = docker_sandbox(SandboxResult(ok=True, output="no leaks found", exit_code=0))
    verifier = DockerVerificationRunner(
        repo,
        "astra:test",
        sandbox=sandbox,
        workspace_volume="astra_repos",
        volume_subpath="repo",
        volume_root=tmp_path,
    )
    engine = VerificationEngine(
        verifier, (GateSpec(name=GateName.GITLEAKS, argv=("gitleaks-scan", "detect")),)
    )

    assert engine.run(repo).passed
    assert runner.argv is not None
    assert any("dst=/git-metadata" in part for part in runner.argv)
    assert any("volume-subpath=repo/.git" in part for part in runner.argv)
    assert any("dst=/git-metadata" in part and ",readonly" in part for part in runner.argv)


def test_docker_orchestrator_factory_injects_sandboxed_commands(tmp_path: Path) -> None:
    architect = ArchitectAgent(
        lambda _task, _context: Plan(
            goal="run fixture",
            steps=(PlanAction(tool="run_command", payload={"argv": ["pytest", "-q"]}),),
        )
    )
    sandbox, runner = docker_sandbox(SandboxResult(ok=True, output="passed", exit_code=0))
    factory = DockerOrchestratorFactory(
        architect,
        EditorAgent(),
        IndependentReviewerAgent(),
        "astra:test",
        sandbox=sandbox,
        gates=(GateSpec(name=GateName.TESTS, argv=("fixture",)),),
    )
    task = Task(prompt="run", repo_path=str(tmp_path), state=TaskState.CONTEXT_BUILT)

    result = factory(tmp_path).run(task, "safe context", tmp_path)

    assert result.task.state is TaskState.SUCCEEDED
    assert len(runner.calls) == 2
    assert runner.calls[0][-4:] == ("python", "-I", "-m", "astra_coder.sandbox_tools")
    assert runner.calls[1][-2:] == ("astra:test", "fixture")


def test_docker_unavailability_fails_closed_for_both_adapters(tmp_path: Path) -> None:
    sandbox = DockerSandbox(
        runner=RecordingDockerRunner(SandboxResult(ok=True)),
        docker_binary=None,
        detect_docker=False,
    )

    command = DockerCommandExecutor(tmp_path, "astra:test", sandbox=sandbox).execute(
        ("pytest",), tmp_path, 1.0
    )
    verification = DockerVerificationRunner(tmp_path, "astra:test", sandbox=sandbox).run(
        ("pytest",), tmp_path, 1.0
    )

    assert not command.ok
    assert "refusing host execution" in (command.error or "")
    assert verification.unavailable
    assert "refusing host execution" in verification.stderr


def test_adapters_reject_workdir_outside_supplied_workspace(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-worker"
    outside.mkdir()
    sandbox, runner = docker_sandbox(SandboxResult(ok=True))

    command = DockerCommandExecutor(tmp_path, "astra:test", sandbox=sandbox).execute(
        ("pytest",), outside, 1.0
    )
    verification = DockerVerificationRunner(tmp_path, "astra:test", sandbox=sandbox).run(
        ("pytest",), outside, 1.0
    )

    assert not command.ok
    assert "outside the supplied workspace" in (command.error or "")
    assert verification.unavailable
    assert "outside the supplied workspace" in verification.stderr
    assert runner.argv is None


class RecordingOrchestrator:
    def __init__(self) -> None:
        self.calls: list[tuple[Task, str, str | Path | None]] = []

    def run(
        self, task: Task, context: str, workspace: str | Path | None = None
    ) -> OrchestrationResult:
        self.calls.append((task, context, workspace))
        return OrchestrationResult(task=task)


def test_task_worker_propagates_exact_worktree_and_runs_once(tmp_path: Path) -> None:
    task = Task(prompt="work", repo_path=str(tmp_path), state=TaskState.CONTEXT_BUILT)
    exact_workspace = tmp_path / "returned-worktree"
    orchestrator = RecordingOrchestrator()
    factory_workspaces: list[str | Path] = []

    def make_orchestrator(workspace: str | Path) -> RecordingOrchestrator:
        factory_workspaces.append(workspace)
        return orchestrator

    worker = TaskWorker(
        cast(TaskOrchestratorFactory, make_orchestrator), lambda supplied_task: exact_workspace
    )
    result = worker.run(task, "built context")

    assert result.task is task
    assert factory_workspaces == [exact_workspace]
    assert orchestrator.calls == [(task, "built context", exact_workspace)]


def test_git_worktree_factory_binds_worker_to_isolated_worktree(tmp_path: Path) -> None:
    root = make_git_repo(tmp_path)
    store = StateStore("sqlite:///:memory:")
    task = Task(prompt="work", repo_path=str(root), state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.save_scope(
        TaskScope(
            task_id=task.id,
            spec_hash="a" * 64,
            scope_hash="b" * 64,
            repo_path=str(root),
            risk=task.risk,
            created_at=datetime.now(UTC),
        )
    )
    factory = GitWorktreeFactory(store)

    workspace = factory(task)

    assert workspace != root
    assert workspace.parent == root.parent / f".{root.name}.astra-worktrees"
    factory.validate(task, workspace)
    (workspace / "worker.txt").write_text("isolated\n", encoding="utf-8")
    assert not (root / "worker.txt").exists()
    factory._managers[str(task.id)].rollback(str(task.id))


def test_git_worktree_factory_rejects_unapproved_worktree(tmp_path: Path) -> None:
    root = make_git_repo(tmp_path)
    store = StateStore("sqlite:///:memory:")
    task = Task(prompt="work", repo_path=str(root), state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.save_scope(
        TaskScope(
            task_id=task.id,
            spec_hash="a" * 64,
            scope_hash="b" * 64,
            repo_path=str(root),
            risk=task.risk,
            created_at=datetime.now(UTC),
        )
    )
    factory = GitWorktreeFactory(store)
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(OrchestrationBlocked, match="task worktree"):
        factory.validate(task, outside)


@pytest.mark.parametrize(
    "state",
    [TaskState.RECEIVED, TaskState.POLICY_CHECKED, TaskState.AWAITING_APPROVAL],
)
def test_task_worker_blocks_nonterminal_states(state: TaskState, tmp_path: Path) -> None:
    task = Task(prompt="work", repo_path=str(tmp_path), state=state)
    called = False

    def make_orchestrator(workspace: str | Path) -> RecordingOrchestrator:
        nonlocal called
        called = True
        return RecordingOrchestrator()

    worker = TaskWorker(cast(TaskOrchestratorFactory, make_orchestrator), lambda _task: tmp_path)
    with pytest.raises(OrchestrationBlocked, match="context-built"):
        worker.run(task, "built context")
    assert not called


def test_task_worker_does_not_rerun_terminal_task(tmp_path: Path) -> None:
    task = Task(prompt="done", repo_path=str(tmp_path), state=TaskState.SUCCEEDED)
    called = False

    def make_orchestrator(workspace: str | Path) -> RecordingOrchestrator:
        nonlocal called
        called = True
        return RecordingOrchestrator()

    result = TaskWorker(
        cast(TaskOrchestratorFactory, make_orchestrator), lambda _task: tmp_path
    ).run(task, "ignored")

    assert result.task is task
    assert not called


def test_task_worker_claims_and_completes_one_queued_task(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    audit = AuditLog(store)
    memory = AstraMemoryEngine(tmp_path / "worker-memory.db", audit=audit, audit_actor="worker-1")
    task = Task(prompt="queued", repo_path=str(tmp_path), state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    orchestrator = RecordingOrchestrator()
    original_run = orchestrator.run

    def run_and_succeed(
        task_to_run: Task, context: str, workspace: str | Path | None = None
    ) -> OrchestrationResult:
        original_run(task_to_run, context, workspace)
        task_to_run.state = TaskState.SUCCEEDED
        return OrchestrationResult(task=task_to_run)

    orchestrator.run = run_and_succeed  # type: ignore[assignment, method-assign]
    worker = TaskWorker(
        cast(TaskOrchestratorFactory, lambda _workspace: orchestrator),
        lambda supplied_task: tmp_path / str(supplied_task.id),
        store=store,
        audit=audit,
        worker_id="worker-1",
        memory=memory,
    )
    result = worker.run_next(lambda supplied_task: f"context for {supplied_task.id}")

    assert result is not None and result.task.state is TaskState.SUCCEEDED
    request = store.get_execution_request(task.id)
    assert request is not None and request.status == "succeeded"
    assert audit.replay(str(task.id))[-1].action == "worker_completed"
    recalled = memory.search(f"task {task.id}")
    assert recalled and recalled[0].entry.status is MemoryStatus.SUCCESS
    assert audit.verify_chain()
    memory.close()


def test_task_worker_fails_closed_when_execution_guard_rejects(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    audit = AuditLog(store)
    task = Task(prompt="queued", repo_path=str(tmp_path), state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    called = False

    def unexpected_orchestrator(_workspace: str | Path) -> RecordingOrchestrator:
        nonlocal called
        called = True
        return RecordingOrchestrator()

    def reject(_task: Task) -> None:
        raise OrchestrationBlocked("kill switch is enabled")

    worker = TaskWorker(
        cast(TaskOrchestratorFactory, unexpected_orchestrator),
        lambda supplied_task: tmp_path / str(supplied_task.id),
        store=store,
        audit=audit,
        execution_guard=reject,
    )
    result = worker.run_next(lambda _task: "unreachable")

    assert result is not None and result.task.state is TaskState.FAILED
    assert "kill switch" in (result.task.failure_reason or "")
    assert not called
    request = store.get_execution_request(task.id)
    assert request is not None and request.status == "failed"


def test_policy_execution_guard_enforces_task_step_budget(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    root = make_git_repo(tmp_path)
    task = Task(
        prompt="budgeted",
        repo_path=str(root),
        state=TaskState.CONTEXT_BUILT,
        limits=TaskLimits(max_steps=1),
    )
    store.save_task(task)
    from astra_coder.git_safety import GitSafety

    revision = GitSafety(root).current_revision()
    store.save_scope(
        TaskScope(
            task_id=task.id,
            spec_hash=TaskService._spec_hash(task),
            scope_hash=TaskService._scope_hash(task, revision),
            repo_path=str(root.resolve()),
            base_revision=revision,
            risk=task.risk,
            created_at=datetime.now(UTC),
        )
    )
    policy_guard = PolicyExecutionGuard(
        store, PolicyEngine(PolicyConfig()), Actor(actor_id="developer", role="developer")
    )

    policy_guard(task)
    with pytest.raises(OrchestrationBlocked, match="step budget"):
        policy_guard(task)
    assert task.steps == 1


@pytest.mark.parametrize("denial", ["kill-switch", "revoked", "spec-changed"])
def test_worker_rechecks_durable_policy_between_actions(tmp_path: Path, denial: str) -> None:
    root = make_git_repo(tmp_path)
    store = StateStore("sqlite:///:memory:")
    policy = PolicyEngine()
    developer = Actor(actor_id="dev", role="developer")
    reviewer = Actor(actor_id="reviewer", role="reviewer")
    service = TaskService(store, policy)
    task = service.submit(
        developer, SubmitRequest(prompt="work", repo_path=str(root), risk=RiskTier.T2)
    )
    service.approve(reviewer, task.id)
    service.request_execution(developer, task.id)
    recovered_task = store.get_task(task.id)
    assert recovered_task is not None
    task = recovered_task
    guard = PolicyExecutionGuard(store, policy, developer)
    guard(task)
    if denial == "kill-switch":
        store.set_kill_switch(True)
    elif denial == "revoked":
        store.revoke_approval(task.id)
    else:
        task.prompt = "changed after approval"
    with pytest.raises(OrchestrationBlocked):
        guard(task)
