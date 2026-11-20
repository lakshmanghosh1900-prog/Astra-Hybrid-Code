import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from astra_coder.api import create_app, create_service
from astra_coder.cli import app
from astra_coder.config import Settings, load_settings
from astra_coder.persistence import StateStore
from astra_coder.policy import Actor, PolicyConfig, PolicyEngine
from astra_coder.runtime import RiskTier, Task, TaskState
from astra_coder.service import ServiceError, SubmitRequest, TaskService
from test_git_safety import make_repo


def settings() -> Settings:
    return load_settings(
        {
            "ASTRA_AUTH_MODE": "tokens",
            "ASTRA_AUTH_TOKENS": json.dumps(
                {
                    "developer-token": {"actor_id": "dev", "role": "developer"},
                    "reviewer-token": {"actor_id": "reviewer", "role": "reviewer"},
                }
            ),
        }
    )


def test_api_submit_approval_cancel_and_sse(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    service = TaskService(store, PolicyEngine(PolicyConfig()))
    client = TestClient(create_app(service, settings=settings()))
    response = client.post(
        "/tasks",
        json={"prompt": "implement feature", "repo_path": str(make_repo(tmp_path)), "risk": "T2"},
        headers={"Authorization": "Bearer developer-token"},
    )
    assert response.status_code == 201
    task_id = response.json()["id"]
    assert response.json()["state"] == "awaiting_approval"
    approved = client.post(
        f"/tasks/{task_id}/approve", headers={"Authorization": "Bearer reviewer-token"}
    )
    assert approved.status_code == 200
    assert approved.json()["state"] == "context_built"
    stream = client.get(
        f"/tasks/{task_id}/events", headers={"Authorization": "Bearer developer-token"}
    )
    assert stream.status_code == 200
    assert "event: audit" in stream.text
    ids = [int(line[4:]) for line in stream.text.splitlines() if line.startswith("id: ")]
    assert len(ids) > 1
    resumed = client.get(
        f"/tasks/{task_id}/events",
        params={"after": ids[0]},
        headers={"Authorization": "Bearer developer-token"},
    )
    assert resumed.status_code == 200
    assert resumed.text == stream.text.split("\n\n", 1)[1]

    cancelled = client.post(
        f"/tasks/{task_id}/cancel", headers={"Authorization": "Bearer developer-token"}
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"


def test_api_reviewer_denial_is_persisted(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    client = TestClient(create_app(TaskService(store, PolicyEngine()), settings=settings()))
    developer = {"Authorization": "Bearer developer-token"}
    reviewer = {"Authorization": "Bearer reviewer-token"}
    submitted = client.post(
        "/tasks",
        json={"prompt": "bounded change", "repo_path": str(make_repo(tmp_path)), "risk": "T2"},
        headers=developer,
    )
    assert submitted.status_code == 201
    task_id = submitted.json()["id"]
    url = f"/tasks/{task_id}"
    denied = client.post(f"{url}/deny", json={"reason": "outside scope"}, headers=reviewer)
    assert denied.status_code == 200
    assert denied.json()["state"] == "blocked"
    assert store.get_task(task_id).failure_reason == "outside scope"


def test_api_rejects_missing_or_caller_supplied_identity(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    client = TestClient(create_app(TaskService(store, PolicyEngine()), settings=settings()))
    for headers in ({}, {"X-Astra-Actor": "admin", "X-Astra-Role": "admin"}):
        response = client.post(
            "/tasks",
            json={"prompt": "implement feature", "repo_path": str(tmp_path)},
            headers=headers,
        )
        assert response.status_code == 401


def test_api_missing_task_is_not_success(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    client = TestClient(create_app(TaskService(store, PolicyEngine()), settings=settings()))
    response = client.get(
        "/tasks/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": "Bearer developer-token"},
    )
    assert response.status_code == 404


def test_api_reads_require_authentication(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    client = TestClient(create_app(TaskService(store, PolicyEngine()), settings=settings()))
    task_id = "00000000-0000-0000-0000-000000000000"
    assert client.get("/tasks").status_code == 401
    assert client.get(f"/tasks/{task_id}").status_code == 401
    assert client.get(f"/tasks/{task_id}/diff").status_code == 401
    assert client.get(f"/tasks/{task_id}/events").status_code == 401


def test_submitter_cannot_approve_own_task(tmp_path: Path) -> None:
    service = TaskService(StateStore("sqlite:///:memory:"), PolicyEngine())
    task = service.submit(
        Actor(actor_id="same-user", role="developer"),
        SubmitRequest(prompt="change", repo_path=str(make_repo(tmp_path)), risk=RiskTier.T2),
    )
    try:
        service.approve(Actor(actor_id="same-user", role="reviewer"), task.id)
    except ServiceError as exc:
        assert "submitter" in str(exc)
    else:
        raise AssertionError("submitter approved its own task")


def test_api_execute_only_queues_after_policy_and_approval(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    service = TaskService(store, PolicyEngine(PolicyConfig()))
    client = TestClient(create_app(service, settings=settings()))
    response = client.post(
        "/tasks",
        json={"prompt": "change", "repo_path": str(make_repo(tmp_path)), "risk": "T2"},
        headers={"Authorization": "Bearer developer-token"},
    )
    task_id = response.json()["id"]
    blocked = client.post(
        f"/tasks/{task_id}/execute", headers={"Authorization": "Bearer developer-token"}
    )
    assert blocked.status_code == 403
    assert "approval" in blocked.json()["detail"]
    approved = client.post(
        f"/tasks/{task_id}/approve", headers={"Authorization": "Bearer reviewer-token"}
    )
    assert approved.status_code == 200
    queued = client.post(
        f"/tasks/{task_id}/execute", headers={"Authorization": "Bearer developer-token"}
    )
    assert queued.status_code == 202
    assert queued.json()["state"] == "context_built"
    request = store.get_execution_request(task_id)
    assert request is not None and request.status == "queued"
    duplicate = client.post(
        f"/tasks/{task_id}/execute", headers={"Authorization": "Bearer developer-token"}
    )
    assert duplicate.status_code == 403
    assert "already queued" in duplicate.json()["detail"]
    cancelled = client.post(
        f"/tasks/{task_id}/cancel", headers={"Authorization": "Bearer developer-token"}
    )
    assert cancelled.status_code == 200
    request = store.get_execution_request(task_id)
    assert request is not None and request.status == "cancelled"


def test_api_execute_requires_authentication(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    client = TestClient(create_app(TaskService(store, PolicyEngine()), settings=settings()))
    assert (
        client.post(
            "/tasks/00000000-0000-0000-0000-000000000000/execute",
        ).status_code
        == 401
    )


def test_approval_is_restored_from_durable_scope(tmp_path: Path) -> None:
    database = f"sqlite:///{tmp_path / 'approval.db'}"
    developer = Actor(actor_id="dev", role="developer")
    reviewer = Actor(actor_id="reviewer", role="reviewer")
    first = TaskService(StateStore(database), PolicyEngine())
    task = first.submit(
        developer,
        SubmitRequest(prompt="change", repo_path=str(make_repo(tmp_path)), risk=RiskTier.T2),
    )
    first.approve(reviewer, task.id)
    second = TaskService(StateStore(database), PolicyEngine())
    scope = second.store.get_scope(task.id)
    assert scope is not None
    assert second.policy.evaluate(
        developer,
        "edit",
        task.risk,
        str(task.id),
        spec_hash=scope.spec_hash,
        scope_hash=scope.scope_hash,
    ).allowed


def test_create_service_recovers_incomplete_tasks(tmp_path: Path) -> None:
    database = f"sqlite:///{tmp_path / 'recovery.db'}"
    store = StateStore(database)
    task = Task(prompt="interrupted", repo_path=str(tmp_path), state=TaskState.EDITING)
    store.save_task(task)
    service_settings = load_settings({"ASTRA_DATABASE_URL": database})
    create_service(service_settings)
    recovered = StateStore(database).get_task(task.id)
    assert recovered is not None
    assert recovered.state is TaskState.FAILED


def test_cli_doctor_works() -> None:
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "astra" in result.stdout
