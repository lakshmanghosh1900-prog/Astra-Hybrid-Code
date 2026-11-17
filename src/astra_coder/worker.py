"""Dedicated, dependency-injected task worker adapters."""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from .agents import ArchitectAgent, EditorAgent, IndependentReviewerAgent
from .docker_tools import DockerToolMesh
from .git_safety import GitSafety
from .orchestrator import (
    OrchestrationBlocked,
    OrchestrationResult,
    TaskOrchestrator,
)
from .persistence import AuditLog, PersistenceError, StateStore
from .policy import Action, Actor, PolicyEngine, Role
from .runtime import TERMINAL_STATES, Task, TaskState, TaskStateMachine
from .sandbox import DockerSandbox, SandboxRequest, SandboxResult
from .service import TaskService
from .tools import ToolResult
from .verification import GateSpec, ProcessResult, VerificationEngine


def _git_metadata_subpath(workspace: Path, volume_root: Path | None) -> str:
    if volume_root is None:
        raise ValueError("scanner git metadata requires a configured volume root")
    git = shutil.which("git")
    if git is None:
        raise ValueError("git unavailable; scanner git metadata cannot be resolved")
    checked = subprocess.run(  # noqa: S603
        [git, "-C", str(workspace), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if checked.returncode != 0:
        raise ValueError(checked.stderr.strip() or "unable to resolve git common directory")
    common_directory = Path(checked.stdout.strip()).resolve()
    relative = common_directory.relative_to(volume_root.resolve()).as_posix()
    if any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError("git common directory is outside the workspace volume")
    return relative


class _DockerWorkspaceAdapter:
    def __init__(
        self,
        workspace: str | Path,
        image: str,
        sandbox: DockerSandbox | None,
        workspace_volume: str | None = None,
        volume_subpath: str | None = None,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        if not self.workspace.is_dir():
            raise ValueError("sandbox workspace must be an existing directory")
        self.image = image
        self.sandbox = sandbox or DockerSandbox()
        self.workspace_volume = workspace_volume
        self.volume_subpath = volume_subpath

    def request(
        self, argv: Sequence[str], cwd: str | Path, timeout_seconds: float
    ) -> SandboxRequest:
        candidate = Path(cwd)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        candidate = candidate.resolve()
        try:
            relative_workdir = candidate.relative_to(self.workspace)
        except ValueError as exc:
            raise ValueError("command workdir is outside the supplied workspace") from exc
        if not candidate.is_dir():
            raise ValueError("command workdir must be an existing directory")
        return SandboxRequest(
            image=self.image,
            argv=list(argv),
            workspace=self.workspace / relative_workdir,
            workspace_volume=self.workspace_volume,
            volume_subpath=(
                f"{self.volume_subpath}/{relative_workdir.as_posix()}"
                if self.volume_subpath and relative_workdir.parts
                else self.volume_subpath
            ),
            timeout_seconds=timeout_seconds,
        )

    def run(self, argv: Sequence[str], cwd: str | Path, timeout_seconds: float) -> SandboxResult:
        return self.sandbox.run(self.request(argv, cwd, timeout_seconds))


class DockerCommandExecutor:
    """A ToolMesh executor that refuses to run commands outside Docker."""

    def __init__(
        self,
        workspace: str | Path,
        image: str,
        *,
        sandbox: DockerSandbox | None = None,
        workspace_volume: str | None = None,
        volume_subpath: str | None = None,
        boundary_guard: Callable[[], None] | None = None,
        remaining_seconds: Callable[[], float] | None = None,
    ) -> None:
        self._adapter = _DockerWorkspaceAdapter(
            workspace, image, sandbox, workspace_volume, volume_subpath
        )
        self._boundary_guard = boundary_guard
        self._remaining_seconds = remaining_seconds

    def execute(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ToolResult:
        if self._boundary_guard is not None:
            self._boundary_guard()
        if self._remaining_seconds is not None:
            timeout_seconds = min(timeout_seconds, self._remaining_seconds())
        try:
            result = self._adapter.run(argv, cwd, timeout_seconds)
        except (OSError, ValueError) as exc:
            return ToolResult(ok=False, error=str(exc))
        return ToolResult(
            ok=result.ok,
            output=result.output,
            error=result.error,
            exit_code=result.exit_code,
        )


class DockerVerificationRunner:
    """A VerificationEngine runner that executes each gate in Docker."""

    def __init__(
        self,
        workspace: str | Path,
        image: str,
        *,
        sandbox: DockerSandbox | None = None,
        workspace_volume: str | None = None,
        volume_subpath: str | None = None,
        volume_root: str | Path | None = None,
        boundary_guard: Callable[[], None] | None = None,
        remaining_seconds: Callable[[], float] | None = None,
    ) -> None:
        self._adapter = _DockerWorkspaceAdapter(
            workspace, image, sandbox, workspace_volume, volume_subpath
        )
        self._volume_root = Path(volume_root).resolve() if volume_root is not None else None
        self._boundary_guard = boundary_guard
        self._remaining_seconds = remaining_seconds

    def run(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ProcessResult:
        if self._boundary_guard is not None:
            self._boundary_guard()
        if self._remaining_seconds is not None:
            timeout_seconds = min(timeout_seconds, self._remaining_seconds())
        try:
            request = self._adapter.request(argv, cwd, timeout_seconds)
            if Path(argv[0]).name in {"gitleaks", "gitleaks.exe", "gitleaks-scan"}:
                request = request.model_copy(
                    update={
                        "git_metadata_subpath": _git_metadata_subpath(
                            self._adapter.workspace, self._volume_root
                        )
                    }
                )
            result = self._adapter.sandbox.run(
                request.model_copy(update={"read_only_workspace": True})
            )
        except (OSError, ValueError) as exc:
            return ProcessResult(unavailable=True, stderr=str(exc))
        unavailable = not self._adapter.sandbox.available or (
            not result.ok and result.exit_code is None and not result.timed_out
        )
        return ProcessResult(
            exit_code=result.exit_code,
            stdout=result.output,
            stderr=result.error or "",
            unavailable=unavailable,
            timed_out=result.timed_out,
        )


TaskOrchestratorFactory = Callable[[str | Path], TaskOrchestrator]
WorktreeFactory = Callable[[Task], str | Path]
ContextFactory = Callable[[Task], str]
ExecutionGuard = Callable[[Task], None]
WorkspaceValidator = Callable[[Task, Path], None]


class PolicyExecutionGuard:
    """Re-check approval, repository scope, budgets, and kill switch in the worker."""

    def __init__(self, store: StateStore, policy: PolicyEngine, actor: Actor) -> None:
        self.store = store
        self.policy = policy
        self.actor = actor
        self._started: dict[str, float] = {}

    def __call__(self, task: Task) -> None:
        started = self._started.setdefault(str(task.id), time.monotonic())
        durable_task = self.store.get_task(task.id)
        if durable_task is not None and durable_task.state in TERMINAL_STATES:
            raise OrchestrationBlocked("task was cancelled or terminated by an operator")
        self.policy.set_kill_switch(
            Actor(actor_id="worker-policy", role=Role.ADMIN), self.store.get_kill_switch()
        )
        if task.steps >= task.limits.max_steps:
            raise OrchestrationBlocked("step budget exceeded")
        if time.monotonic() - started >= task.limits.max_seconds:
            raise OrchestrationBlocked("wall-clock budget exceeded")
        if task.tokens >= task.limits.max_tokens:
            raise OrchestrationBlocked("token budget exceeded")
        scope = self.store.get_scope(task.id)
        if scope is None:
            raise OrchestrationBlocked("task execution scope is unavailable")
        if (
            TaskService._spec_hash(task) != scope.spec_hash
            or str(Path(task.repo_path).resolve()) != scope.repo_path
            or task.risk != scope.risk
            or GitSafety(scope.repo_path).current_revision() != scope.base_revision
            or TaskService._scope_hash(task, scope.base_revision) != scope.scope_hash
        ):
            raise OrchestrationBlocked("task specification or repository approval binding changed")
        approval = self.store.get_approval(task.id)
        self.policy.deny(str(task.id), Actor(actor_id="worker-policy", role=Role.ADMIN))
        if approval is not None:
            if (
                not approval.active
                or approval.spec_hash != scope.spec_hash
                or approval.scope_hash != scope.scope_hash
                or approval.policy_version != scope.policy_version
            ):
                raise OrchestrationBlocked("approval expired, revoked, or changed")
            self.policy.restore_approval(
                str(task.id), approval.approver, approval.spec_hash, approval.scope_hash
            )
        decision = self.policy.evaluate(
            self.actor,
            Action.EXECUTE,
            task.risk,
            str(task.id),
            touched_paths=[scope.repo_path],
            spec_hash=scope.spec_hash,
            scope_hash=scope.scope_hash,
        )
        if not decision.allowed:
            raise OrchestrationBlocked(decision.reason)
        task.steps += 1

    def remaining_seconds(self, task: Task) -> float:
        started = self._started.setdefault(str(task.id), time.monotonic())
        remaining = task.limits.max_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise OrchestrationBlocked("wall-clock budget exceeded")
        return remaining


class DockerOrchestratorFactory:
    """Build an orchestrator whose commands and verification run in Docker."""

    def __init__(
        self,
        architect: ArchitectAgent,
        editor: EditorAgent,
        reviewer: IndependentReviewerAgent,
        image: str,
        *,
        sandbox: DockerSandbox | None = None,
        gates: tuple[GateSpec, ...] | None = None,
        boundary_guard: ExecutionGuard | None = None,
        workspace_volume: str | None = None,
        volume_root: str | Path | None = None,
    ) -> None:
        self.architect = architect
        self.editor = editor
        self.reviewer = reviewer
        self.image = image
        self.sandbox = sandbox
        self.gates = gates
        self.boundary_guard = boundary_guard
        self.workspace_volume = workspace_volume
        self.volume_root = Path(volume_root).resolve() if volume_root is not None else None

    def __call__(self, workspace: str | Path) -> TaskOrchestrator:
        sandbox = self.sandbox or DockerSandbox()
        subpath = (
            Path(workspace).resolve().relative_to(self.volume_root).as_posix()
            if self.volume_root is not None
            else None
        )
        active: Task | None = None

        def boundary(task: Task) -> None:
            nonlocal active
            active = task
            if self.boundary_guard is not None:
                self.boundary_guard(task)

        def tool_boundary() -> None:
            if active is None:
                raise OrchestrationBlocked("task policy boundary was not established")
            boundary(active)

        def remaining() -> float:
            if isinstance(self.boundary_guard, PolicyExecutionGuard) and active is not None:
                return self.boundary_guard.remaining_seconds(active)
            return 120.0

        verifier = VerificationEngine(
            DockerVerificationRunner(
                workspace,
                self.image,
                sandbox=sandbox,
                workspace_volume=self.workspace_volume,
                volume_subpath=subpath,
                volume_root=self.volume_root,
                boundary_guard=tool_boundary,
                remaining_seconds=remaining,
            ),
            self.gates,
        )
        return TaskOrchestrator(
            self.architect,
            self.editor,
            self.reviewer,
            verifier,
            tool_mesh_factory=lambda root: DockerToolMesh(
                root,
                self.image,
                sandbox=sandbox,
                boundary_guard=tool_boundary,
                remaining_seconds=remaining,
                workspace_volume=self.workspace_volume,
                volume_subpath=subpath,
                timeout_seconds=min(120.0, remaining()),
            ),
            workspace_guard=lambda _task, root: self._require_exact_workspace(workspace, root),
            boundary_guard=boundary,
        )

    @staticmethod
    def _require_exact_workspace(expected: str | Path, actual: Path) -> None:
        if Path(expected).resolve() != actual.resolve():
            raise OrchestrationBlocked("execution workspace is not the approved task worktree")


class GitWorktreeFactory:
    """Create task-owned worktrees without modifying the user's root worktree."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._managers: dict[str, GitSafety] = {}

    def __call__(self, task: Task) -> Path:
        scope = self.store.get_scope(task.id)
        if scope is None:
            raise PersistenceError("task worktree scope is unavailable")
        root = Path(scope.repo_path).resolve()
        manager = GitSafety(root)
        workspace = manager.create_worktree(str(task.id), scope.base_revision or None)
        self._managers[str(task.id)] = manager
        if not scope.base_revision:
            self.store.save_scope(
                scope.model_copy(update={"base_revision": workspace.base_revision})
            )
        return workspace.path

    def validate(self, task: Task, workspace: str | Path) -> None:
        scope = self.store.get_scope(task.id)
        if scope is None:
            raise OrchestrationBlocked("task worktree scope is unavailable")
        root = Path(scope.repo_path).resolve()
        expected = root.parent / f".{root.name}.astra-worktrees" / str(task.id)
        if Path(workspace).resolve() != expected.resolve():
            raise OrchestrationBlocked("execution workspace is not the task worktree")
        if not Path(workspace).is_dir() or not (Path(workspace) / ".git").exists():
            raise OrchestrationBlocked("task worktree is unavailable")


class TaskWorker:
    """Run exactly one context-built task in its injected worktree."""

    def __init__(
        self,
        orchestrator_factory: TaskOrchestratorFactory,
        worktree_factory: WorktreeFactory,
        *,
        store: StateStore | None = None,
        audit: AuditLog | None = None,
        worker_id: str = "astra-worker",
        execution_guard: ExecutionGuard | None = None,
        workspace_validator: WorkspaceValidator | None = None,
    ) -> None:
        self._orchestrator_factory = orchestrator_factory
        self._worktree_factory = worktree_factory
        self._store = store
        self._audit = audit
        self._worker_id = worker_id
        self._execution_guard = execution_guard
        self._workspace_validator = workspace_validator or (
            worktree_factory.validate if isinstance(worktree_factory, GitWorktreeFactory) else None
        )

    def run(self, task: Task, context: str) -> OrchestrationResult:
        if task.state in TERMINAL_STATES:
            return OrchestrationResult(task=task)
        if task.state is not TaskState.CONTEXT_BUILT:
            raise OrchestrationBlocked(
                "task must be context-built before a dedicated worker can execute it"
            )
        workspace = self._worktree_factory(task)
        if self._workspace_validator is not None:
            self._workspace_validator(task, Path(workspace))
        if self._audit is not None:
            self._audit.append(
                self._worker_id,
                "worker_workspace",
                str(task.id),
                "isolated",
                {"workspace": str(workspace)},
            )
        orchestrator = self._orchestrator_factory(workspace)
        return orchestrator.run(task, context, workspace=workspace)

    def run_next(self, context_factory: ContextFactory) -> OrchestrationResult | None:
        """Claim and execute one queued task; never execute directly from the API process."""
        if self._store is None or self._audit is None:
            raise RuntimeError("queued worker requires a state store and audit log")
        request = self._store.claim_next_execution(self._worker_id)
        if request is None:
            return None
        self._audit.append(self._worker_id, "worker_claimed", str(request.task_id), "running")
        task = self._store.get_task(request.task_id)
        if task is None:
            error = "queued task no longer exists"
            self._store.complete_execution(request.task_id, "failed", error)
            self._audit.append(
                self._worker_id,
                "worker_failed",
                str(request.task_id),
                "failed_closed",
                {"error": error},
            )
            return None
        latest_task = self._store.get_task(task.id)
        if latest_task is not None:
            task = latest_task
        try:
            if self._execution_guard is not None:
                self._execution_guard(task)
            result = self.run(task, context_factory(task))
        except Exception as exc:  # noqa: BLE001
            TaskStateMachine.fail(task, f"worker failed closed: {exc}")
            result = OrchestrationResult(task=task)
        if result.task.state not in TERMINAL_STATES:
            TaskStateMachine.fail(result.task, "worker returned without terminal evidence")
        result.task = self._store.finalize_execution(
            result.task, self._worker_id, result.model_dump(mode="json")
        )
        status = "succeeded" if result.task.state is TaskState.SUCCEEDED else "failed"
        self._audit.append(
            self._worker_id,
            "worker_completed" if status == "succeeded" else "worker_failed",
            str(result.task.id),
            status,
            {
                "state": result.task.state.value,
                "verification_hash": (
                    result.verification.evidence_hash if result.verification is not None else None
                ),
                "workspace": (
                    result.verification.workspace if result.verification is not None else None
                ),
            },
        )
        return result
