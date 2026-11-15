from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from astra_coder.agents import Plan, PlanAction, ReviewResult
from astra_coder.api import create_app, create_service
from astra_coder.auth import TokenPrincipalResolver
from astra_coder.config import Settings
from astra_coder.git_safety import GitSafety
from astra_coder.orchestrator import OrchestrationResult
from astra_coder.persistence import AuditLog, PersistenceError, StateStore
from astra_coder.policy import Action, Actor, PolicyEngine, Role
from astra_coder.runtime import RiskTier, Task, TaskLimits, TaskState
from astra_coder.service import ServiceError, SubmitRequest, TaskService
from astra_coder.verification import GateName, GateResult, GateStatus, VerificationSummary

DEVELOPER = Actor(actor_id="developer", role=Role.DEVELOPER)
REVIEWER = Actor(actor_id="reviewer", role=Role.REVIEWER)
ADMIN = Actor(actor_id="administrator", role=Role.ADMIN)


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    return StateStore(f"sqlite:///{tmp_path / 'execution.db'}")


@pytest.fixture
def service(store: StateStore, monkeypatch: pytest.MonkeyPatch) -> TaskService:
    # Keep repository metadata deterministic while exercising real path resolution,
    # scope/approval persistence, policy decisions, and HTTP authentication.
    monkeypatch.setattr(GitSafety, "_ensure_repo", lambda _self: None)
    monkeypatch.setattr(GitSafety, "current_revision", lambda _self: "a" * 40)
    return TaskService(store, PolicyEngine())


def approved_task(service: TaskService, root: Path) -> Task:
    task = service.submit(
        DEVELOPER, SubmitRequest(prompt="bounded change", repo_path=str(root), risk=RiskTier.T2)
    )
    return service.approve(REVIEWER, task.id)


def rich_result(task: Task) -> OrchestrationResult:
    return OrchestrationResult(
        task=task,
        plan=Plan(
            goal="bounded change",
            steps=(PlanAction(tool="read_file", payload={"path": "example.py"}),),
        ),
        verification=VerificationSummary(
            workspace=task.repo_path,
            evidence_hash="b" * 64,
            gates=(
                GateResult(
                    name=GateName.TESTS,
                    status=GateStatus.PASSED,
                    argv=("pytest", "-q"),
                    exit_code=0,
                    stdout="passed",
                    stderr="",
                    duration_seconds=0.1,
                    evidence_hash="c" * 64,
                ),
            ),
        ),
        review=ReviewResult(accepted=True, reason="independent evidence is complete"),
    )


@pytest.mark.parametrize("task_count", [1, 2])
def test_two_stores_claim_atomically_without_double_claims(
    store: StateStore, task_count: int
) -> None:
    second = StateStore(str(store.engine.url))
    tasks = [
        Task(prompt=f"queued {index}", repo_path="repo", state=TaskState.CONTEXT_BUILT)
        for index in range(task_count)
    ]
    for task in tasks:
        store.save_task(task)
        store.enqueue_execution(task.id, "developer")

    updates_ready = Barrier(2)

    def synchronize_updates(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if statement.startswith("UPDATE task_execution_requests"):
            # A read-then-write implementation has already selected the same row
            # in both stores here. Atomic UPDATE claims serialize safely instead.
            updates_ready.wait(timeout=10)

    for state in (store, second):
        event.listen(state.engine, "before_cursor_execute", synchronize_updates)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_claim = pool.submit(store.claim_next_execution, "worker-a")
            second_claim = pool.submit(second.claim_next_execution, "worker-b")
            claims = [first_claim.result(timeout=15), second_claim.result(timeout=15)]
    finally:
        for state in (store, second):
            event.remove(state.engine, "before_cursor_execute", synchronize_updates)

    claimed = [request for request in claims if request is not None]
    assert len(claimed) == task_count
    assert {request.task_id for request in claimed} == {task.id for task in tasks}
    for request in claimed:
        persisted = second.get_execution_request(request.task_id)
        assert persisted is not None
        assert persisted.status == "running"
        assert persisted.worker_id == request.worker_id
        assert persisted.claimed_at is not None
    assert store.claim_next_execution("worker-c") is None


@pytest.mark.parametrize(
    "role", [Role.VIEWER, Role.DEVELOPER, Role.REVIEWER, Role.OPERATOR, "unknown"]
)
def test_kill_switch_routes_require_admin(service: TaskService, role: str) -> None:
    resolver = TokenPrincipalResolver({"fixture-principal": Actor(actor_id="user", role=role)})
    client = TestClient(create_app(service, resolver))
    headers = {"Authorization": "Bearer fixture-principal"}

    assert client.get("/controls/kill-switch", headers=headers).status_code == 403
    assert (
        client.post("/controls/kill-switch", headers=headers, json={"enabled": True}).status_code
        == 403
    )
    assert not service.store.get_kill_switch()
    assert not service.policy.kill_switch_enabled
    assert service.audit.events() == ()


def test_kill_switch_routes_require_trusted_authentication(service: TaskService) -> None:
    client = TestClient(create_app(service, TokenPrincipalResolver({"fixture-admin": ADMIN})))
    for headers in ({}, {"X-Astra-Role": "admin"}, {"Authorization": "Bearer invalid"}):
        assert client.get("/controls/kill-switch", headers=headers).status_code == 401
        assert (
            client.post(
                "/controls/kill-switch", headers=headers, json={"enabled": True}
            ).status_code
            == 401
        )
    assert not service.store.get_kill_switch()


def test_kill_switch_is_durable_and_refreshes_existing_services(
    service: TaskService, tmp_path: Path
) -> None:
    task = service.submit(DEVELOPER, SubmitRequest(prompt="run", repo_path=str(tmp_path)))
    second = TaskService(StateStore(str(service.store.engine.url)), PolicyEngine())
    client = TestClient(create_app(service, TokenPrincipalResolver({"fixture-admin": ADMIN})))
    headers = {"Authorization": "Bearer fixture-admin"}

    assert client.get("/controls/kill-switch", headers=headers).json() == {"enabled": False}
    response = client.post("/controls/kill-switch", headers=headers, json={"enabled": True})
    assert response.status_code == 200 and response.json() == {"enabled": True}
    reopened = TaskService(StateStore(str(service.store.engine.url)), PolicyEngine())
    assert reopened.get_kill_switch(ADMIN)
    assert reopened.policy.kill_switch_enabled
    with pytest.raises(ServiceError, match="kill switch"):
        second.submit(DEVELOPER, SubmitRequest(prompt="blocked", repo_path=str(tmp_path)))
    with pytest.raises(ServiceError, match="kill switch"):
        second.request_execution(DEVELOPER, task.id)
    assert second.get_kill_switch(ADMIN)
    assert service.store.get_execution_request(task.id) is None

    assert not second.set_kill_switch(ADMIN, False)
    assert not client.get("/controls/kill-switch", headers=headers).json()["enabled"]
    service.request_execution(DEVELOPER, task.id)
    controls = [entry for entry in service.audit.events() if entry.action == "set_kill_switch"]
    assert [entry.decision for entry in controls] == ["enabled", "disabled"]
    assert all(entry.actor == ADMIN.actor_id for entry in controls)
    assert service.audit.verify_chain()


def test_kill_switch_api_rejects_coerced_boolean(service: TaskService) -> None:
    client = TestClient(create_app(service, TokenPrincipalResolver({"fixture-admin": ADMIN})))
    response = client.post(
        "/controls/kill-switch",
        headers={"Authorization": "Bearer fixture-admin"},
        json={"enabled": "false"},
    )
    assert response.status_code == 422
    assert not service.store.get_kill_switch()


def test_execution_result_json_survives_reopening(store: StateStore) -> None:
    task = Task(prompt="finished", repo_path="repo", state=TaskState.SUCCEEDED)
    result = rich_result(task)
    assert store.get_execution_result(task.id) is None
    store.save_execution_result(task.id, result.model_dump_json())

    reopened = StateStore(str(store.engine.url))
    payload = reopened.get_execution_result(task.id)
    assert payload == result.model_dump(mode="json")
    assert OrchestrationResult.model_validate(payload) == result
    task.failure_reason = "updated evidence"
    reopened.save_execution_result(task.id, result.model_dump(mode="json"))
    assert store.get_execution_result(task.id) == result.model_dump(mode="json")


def test_execution_result_rejects_invalid_json_and_other_task(store: StateStore) -> None:
    task = Task(prompt="finished", repo_path="repo", state=TaskState.FAILED)
    other = Task(prompt="other", repo_path="repo")
    with pytest.raises(PersistenceError, match="invalid"):
        store.save_execution_result(task.id, "not JSON")
    with pytest.raises(PersistenceError, match="invalid"):
        store.save_execution_result(task.id, {})
    with pytest.raises(PersistenceError, match="different task"):
        store.save_execution_result(
            task.id, OrchestrationResult(task=other).model_dump(mode="json")
        )
    assert store.get_execution_result(task.id) is None


@pytest.mark.parametrize(
    ("state", "status"),
    [
        (TaskState.SUCCEEDED, "succeeded"),
        (TaskState.FAILED, "failed"),
        (TaskState.CANCELLED, "cancelled"),
        (TaskState.BLOCKED, "failed"),
    ],
)
def test_finalize_execution_persists_task_queue_and_result(
    store: StateStore, state: TaskState, status: str
) -> None:
    task = Task(prompt="queued", repo_path="repo", state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    assert store.claim_next_execution("worker-a") is not None
    task.state = state
    task.steps = 3
    result = rich_result(task)

    effective = store.finalize_execution(task, "worker-a", result.model_dump(mode="json"))

    reopened = StateStore(str(store.engine.url))
    assert effective == task == reopened.get_task(task.id)
    request = reopened.get_execution_request(task.id)
    assert request is not None and request.status == status
    assert request.completed_at is not None
    assert reopened.get_execution_result(task.id) == result.model_dump(mode="json")
    with pytest.raises(PersistenceError, match="owned"):
        store.finalize_execution(task, "worker-a", result.model_dump_json())


def test_finalize_execution_requires_running_request_and_owner(store: StateStore) -> None:
    task = Task(prompt="queued", repo_path="repo", state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    completed = task.model_copy(update={"state": TaskState.SUCCEEDED})
    result = OrchestrationResult(task=completed).model_dump(mode="json")
    with pytest.raises(PersistenceError, match="owned"):
        store.finalize_execution(completed, "worker-a", result)
    store.claim_next_execution("worker-a")
    with pytest.raises(PersistenceError, match="owned"):
        store.finalize_execution(completed, "worker-b", result)
    assert store.get_task(task.id) == task
    request = store.get_execution_request(task.id)
    assert request is not None and request.status == "running" and request.completed_at is None
    assert store.get_execution_result(task.id) is None


def test_finalize_execution_rejects_nonterminal_or_inconsistent_result(store: StateStore) -> None:
    task = Task(prompt="queued", repo_path="repo", state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    store.claim_next_execution("worker-a")
    with pytest.raises(PersistenceError, match="terminal"):
        store.finalize_execution(task, "worker-a", OrchestrationResult(task=task).model_dump_json())
    completed = task.model_copy(update={"state": TaskState.SUCCEEDED})
    with pytest.raises(PersistenceError, match="snapshot"):
        store.finalize_execution(
            completed, "worker-a", OrchestrationResult(task=task).model_dump_json()
        )
    assert store.get_task(task.id) == task
    assert store.get_execution_result(task.id) is None


@pytest.mark.parametrize("external_state", [TaskState.CANCELLED, TaskState.BLOCKED])
def test_finalize_execution_preserves_external_cancellation_or_block(
    service: TaskService, tmp_path: Path, external_state: TaskState
) -> None:
    task = approved_task(service, tmp_path)
    service.request_execution(DEVELOPER, task.id)
    service.store.claim_next_execution("worker-a")
    stale_task = task.model_copy(update={"state": TaskState.SUCCEEDED, "steps": 4})
    result = rich_result(stale_task)
    external = TaskService(StateStore(str(service.store.engine.url)), PolicyEngine())
    if external_state is TaskState.CANCELLED:
        stopped = external.cancel(DEVELOPER, task.id)
    else:
        external.store.save_task(task.model_copy(update={"state": TaskState.PLANNED}))
        stopped = external.deny(REVIEWER, task.id, "approval withdrawn")

    effective = service.store.finalize_execution(stale_task, "worker-a", result.model_dump_json())

    assert effective == stopped == external.store.get_task(task.id)
    persisted = service.store.get_execution_result(task.id)
    assert persisted is not None
    assert OrchestrationResult.model_validate(persisted).task == stopped
    assert persisted["verification"] == result.model_dump(mode="json")["verification"]
    request = external.store.get_execution_request(task.id)
    assert request is not None
    assert request.status == ("cancelled" if external_state is TaskState.CANCELLED else "failed")
    assert request.error == stopped.failure_reason


def test_finalize_execution_rolls_back_all_writes_if_result_write_fails(store: StateStore) -> None:
    task = Task(prompt="queued", repo_path="repo", state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    store.claim_next_execution("worker-a")
    completed = task.model_copy(update={"state": TaskState.SUCCEEDED})

    def fail_result_insert(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if statement.startswith("INSERT INTO task_execution_results"):
            raise PersistenceError("injected result write failure")

    event.listen(store.engine, "before_cursor_execute", fail_result_insert)
    try:
        with pytest.raises(PersistenceError, match="injected"):
            store.finalize_execution(
                completed, "worker-a", OrchestrationResult(task=completed).model_dump_json()
            )
    finally:
        event.remove(store.engine, "before_cursor_execute", fail_result_insert)
    reopened = StateStore(str(store.engine.url))
    assert reopened.get_task(task.id) == task
    request = reopened.get_execution_request(task.id)
    assert request is not None and request.status == "running" and request.completed_at is None
    assert reopened.get_execution_result(task.id) is None


@pytest.mark.parametrize(
    "changed",
    [
        "prompt",
        "limits",
        "risk",
        "repo_path",
        "scope_spec_hash",
        "scope_scope_hash",
        "scope_repo_path",
        "scope_base_revision",
        "scope_risk",
        "head_revision",
    ],
)
def test_queue_rejects_changed_task_or_scope(
    service: TaskService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    task = approved_task(service, tmp_path)
    scope = service.store.get_scope(task.id)
    assert scope is not None
    if changed == "prompt":
        task.prompt = "different request"
    elif changed == "limits":
        task.limits = TaskLimits(max_steps=task.limits.max_steps + 1)
    elif changed == "risk":
        task.risk = RiskTier.T1
    elif changed == "repo_path":
        other = tmp_path / "other"
        other.mkdir()
        task.repo_path = str(other)
    elif changed == "head_revision":
        monkeypatch.setattr(GitSafety, "current_revision", lambda _self: "d" * 40)
    else:
        field = changed.removeprefix("scope_")
        value = {
            "spec_hash": "d" * 64,
            "scope_hash": "d" * 64,
            "repo_path": str(tmp_path / "other"),
            "base_revision": "d" * 40,
            "risk": RiskTier.T1,
        }[field]
        service.store.save_scope(scope.model_copy(update={field: value}))
    service.store.save_task(task)

    with pytest.raises(ServiceError, match="scope"):
        service.request_execution(DEVELOPER, task.id)
    assert service.store.get_execution_request(task.id) is None


@pytest.mark.parametrize(
    "changed", ["spec_hash", "scope_hash", "policy_version", "expiry", "revoked"]
)
def test_queue_rejects_mismatched_or_inactive_durable_approval(
    service: TaskService, tmp_path: Path, changed: str
) -> None:
    task = approved_task(service, tmp_path)
    approval = service.store.get_approval(task.id)
    assert approval is not None
    service.store.save_approval(
        task.id,
        approval.approver,
        "",
        "d" * 64 if changed == "spec_hash" else approval.spec_hash,
        "d" * 64 if changed == "scope_hash" else approval.scope_hash,
        "different" if changed == "policy_version" else approval.policy_version,
        expires_at=datetime.now(UTC) - timedelta(seconds=1) if changed == "expiry" else None,
    )
    if changed == "revoked":
        service.store.revoke_approval(task.id)
    with pytest.raises(ServiceError, match="approval"):
        service.request_execution(DEVELOPER, task.id)
    assert service.store.get_execution_request(task.id) is None


@pytest.mark.parametrize("changed", ["spec", "scope"])
def test_restart_does_not_restore_approval_under_replaced_scope_hashes(
    service: TaskService, tmp_path: Path, changed: str
) -> None:
    task = approved_task(service, tmp_path)
    scope = service.store.get_scope(task.id)
    assert scope is not None
    if changed == "spec":
        task.prompt = "replacement specification"
        scope.spec_hash = service._spec_hash(task)
    else:
        other = tmp_path / "replacement-repo"
        other.mkdir()
        task.repo_path = str(other)
        scope.repo_path = str(other.resolve())
        scope.scope_hash = service._scope_hash(task, scope.base_revision)
    service.store.save_task(task)
    service.store.save_scope(scope)
    restarted = TaskService(StateStore(str(service.store.engine.url)), PolicyEngine())

    decision = restarted.policy.evaluate(
        DEVELOPER,
        Action.EXECUTE,
        task.risk,
        str(task.id),
        spec_hash=scope.spec_hash,
        scope_hash=scope.scope_hash,
    )
    assert not decision.allowed and decision.approval_required
    with pytest.raises(ServiceError, match="approval"):
        restarted.request_execution(DEVELOPER, task.id)
    assert service.store.get_execution_request(task.id) is None


def test_api_restart_preserves_worker_requests_and_worker_restart_recovers_only_owner(
    store: StateStore, tmp_path: Path
) -> None:
    tasks: dict[str, Task] = {}
    for name in ("worker-a", "worker-b", "queued", "standalone"):
        task = Task(prompt=name, repo_path=str(tmp_path), state=TaskState.CONTEXT_BUILT)
        store.save_task(task)
        store.save_approval(task.id, "reviewer", "", "a" * 64, "b" * 64, "1")
        tasks[name] = task
        if name != "standalone":
            store.enqueue_execution(task.id, "developer")
        if name in {"worker-a", "worker-b"}:
            assert store.claim_next_execution(name) is not None
            task.state = TaskState.EDITING
            store.save_task(task)
    database_url = str(store.engine.url)

    api_service = create_service(Settings(database_url=database_url))

    for name in ("worker-a", "worker-b", "queued"):
        assert api_service.store.get_task(tasks[name].id) == tasks[name]
        approval = api_service.store.get_approval(tasks[name].id)
        assert approval is not None and approval.active
    standalone = api_service.store.get_task(tasks["standalone"].id)
    assert standalone is not None and standalone.state is TaskState.FAILED
    approval = api_service.store.get_approval(standalone.id)
    assert approval is not None and not approval.active

    reopened = StateStore(database_url)
    audit = AuditLog(reopened)
    recovered = reopened.recover_worker_after_restart(audit, "worker-a")
    assert len(recovered) == 1 and recovered[0].id == tasks["worker-a"].id
    assert recovered[0].state is TaskState.FAILED
    assert "worker restart" in (recovered[0].failure_reason or "")
    approval = reopened.get_approval(recovered[0].id)
    assert approval is not None and not approval.active
    request = reopened.get_execution_request(recovered[0].id)
    assert request is not None and request.status == "failed" and request.completed_at is not None
    other_request = reopened.get_execution_request(tasks["worker-b"].id)
    assert other_request is not None and other_request.status == "running"
    assert reopened.get_task(tasks["worker-b"].id) == tasks["worker-b"]
    queued = reopened.get_execution_request(tasks["queued"].id)
    assert queued is not None and queued.status == "queued"
    assert reopened.recover_worker_after_restart(audit, "worker-a") == ()
    next_request = reopened.claim_next_execution("worker-a")
    assert next_request is not None and next_request.task_id == tasks["queued"].id
    stale = tasks["worker-a"].model_copy(update={"state": TaskState.SUCCEEDED})
    with pytest.raises(PersistenceError, match="owned"):
        reopened.finalize_execution(
            stale, "worker-a", OrchestrationResult(task=stale).model_dump_json()
        )
    assert audit.verify_chain()


@pytest.mark.parametrize("state", [TaskState.CANCELLED, TaskState.BLOCKED])
def test_worker_recovery_preserves_external_terminal_state(
    store: StateStore, state: TaskState
) -> None:
    task = Task(prompt="interrupted", repo_path="repo", state=TaskState.CONTEXT_BUILT)
    store.save_task(task)
    store.enqueue_execution(task.id, "developer")
    store.claim_next_execution("worker-a")
    task.state = state
    task.failure_reason = "operator stopped execution"
    store.save_task(task)

    recovered = store.recover_worker_after_restart(AuditLog(store), "worker-a")

    assert recovered == (task,)
    assert store.get_task(task.id) == task
    request = store.get_execution_request(task.id)
    assert request is not None and request.status == (
        "cancelled" if state == TaskState.CANCELLED else "failed"
    )
    assert request.error == task.failure_reason
