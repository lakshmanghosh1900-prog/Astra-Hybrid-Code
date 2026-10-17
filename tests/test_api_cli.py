from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from astra_coder.api import create_app
from astra_coder.cli import app
from astra_coder.persistence import StateStore
from astra_coder.policy import PolicyConfig, PolicyEngine
from astra_coder.service import TaskService


def test_api_submit_approval_cancel_and_sse(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    service = TaskService(store, PolicyEngine(PolicyConfig()))
    client = TestClient(create_app(service))
    response = client.post(
        "/tasks",
        json={"prompt": "implement feature", "repo_path": str(tmp_path), "risk": "T2"},
        headers={"X-Astra-Actor": "dev", "X-Astra-Role": "developer"},
    )
    assert response.status_code == 201
    task_id = response.json()["id"]
    assert response.json()["state"] == "awaiting_approval"
    approved = client.post(f"/tasks/{task_id}/approve", headers={"X-Astra-Role": "reviewer"})
    assert approved.status_code == 200
    assert approved.json()["state"] == "context_built"
    stream = client.get(f"/tasks/{task_id}/events")
    assert stream.status_code == 200
    assert "event: audit" in stream.text

    cancelled = client.post(f"/tasks/{task_id}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"


def test_api_missing_task_is_not_success(tmp_path: Path) -> None:
    store = StateStore("sqlite:///:memory:")
    client = TestClient(create_app(TaskService(store, PolicyEngine())))
    response = client.get("/tasks/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_cli_doctor_works() -> None:
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "astra" in result.stdout
