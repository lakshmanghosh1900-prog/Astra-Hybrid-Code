"""Real Compose demo, with fresh volumes and ephemeral server-only credentials."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker unavailable")
    project = f"astra-worker-smoke-{secrets.token_hex(4)}"
    env = os.environ.copy()
    tokens = {role: secrets.token_urlsafe(32) for role in ("developer", "reviewer", "admin")}
    gates = [
        {
            "name": "tests",
            "argv": [
                "python",
                "-I",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--rootdir=/app/demo/verification",
                "/app/demo/verification/test_contract.py",
            ],
            "timeout_seconds": 30,
        },
        {
            "name": "lint",
            "argv": ["ruff", "check", "--no-cache", "demo_math.py"],
            "timeout_seconds": 30,
        },
        {
            "name": "typecheck",
            "argv": ["mypy", "--cache-dir=/tmp/mypy", "demo_math.py"],
            "timeout_seconds": 30,
        },
    ]
    env.update(
        {
            "ASTRA_AUTH_MODE": "tokens",
            "ASTRA_AUTH_TOKENS": json.dumps(
                {token: {"actor_id": role, "role": role} for role, token in tokens.items()}
            ),
            "ASTRA_SOURCE_REPO": str(root),
            "ASTRA_WORKSPACE_VOLUME": f"{project}-workspaces",
            "ASTRA_WORKER_GATES_JSON": json.dumps(gates),
            "ASTRA_API_PORT": "18000",
            "ASTRA_DASHBOARD_PORT": "13000",
            "ASTRA_DASHBOARD_ORIGIN": "http://127.0.0.1:13000",
        }
    )
    compose = [docker, "compose", "-p", project, "--profile", "worker"]

    def command(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [*compose, *args],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=True,
        )

    client = httpx.Client(base_url="http://127.0.0.1:18000", timeout=10)

    def wait_api() -> None:
        for _ in range(60):
            try:
                if client.get("/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1)
        raise RuntimeError("API readiness timed out")

    def request(method: str, path: str, role: str = "developer", **kwargs: Any) -> httpx.Response:
        return client.request(
            method, path, headers={"Authorization": f"Bearer {tokens[role]}"}, **kwargs
        )

    def run_task(code: str, expected_state: str) -> dict[str, Any]:
        plan = {
            "goal": "structured arithmetic demo (no model generation)",
            "steps": [
                {"tool": "write_patch", "payload": {"path": "demo_math.py", "content": code}}
            ],
        }
        created = request(
            "POST",
            "/tasks",
            json={"prompt": json.dumps(plan), "repo_path": "/repositories/repo", "risk": "T2"},
        )
        assert created.status_code == 201, created.text
        task_id = created.json()["id"]
        assert created.json()["state"] == "awaiting_approval"
        assert request("POST", f"/tasks/{task_id}/execute").status_code == 403
        assert request("POST", f"/tasks/{task_id}/approve").status_code == 403
        assert request("POST", f"/tasks/{task_id}/approve", "reviewer").status_code == 200
        assert request("POST", f"/tasks/{task_id}/execute").status_code == 202
        for _ in range(120):
            durable = request("GET", f"/tasks/{task_id}/result").json()
            if durable["request"]["status"] not in {"queued", "running"}:
                break
            time.sleep(1)
        assert durable["result"] is not None, durable
        assert durable["result"]["task"]["state"] == expected_state, durable
        assert client.get(f"/tasks/{task_id}/result").status_code == 401
        return {"task_id": task_id, **durable}

    report: dict[str, Any] = {
        "project": project,
        "started_at": datetime.now(UTC).isoformat(),
        "scope": (
            "real structured-plan arithmetic execution; NOT a model or release-quality benchmark"
        ),
        "verification_profile": gates,
        "security_scanners": "not included in scoped demo; release gate remains blocked",
    }
    try:
        command("up", "-d", "--no-build", "api", "dashboard", "worker")
        wait_api()
        assert client.get("/tasks").status_code == 401
        assert httpx.get("http://127.0.0.1:13000/", timeout=10).status_code == 200
        good = run_task("def add(a: int, b: int) -> int:\n    return a + b\n", "succeeded")
        good_result = good["result"]
        assert all(gate["status"] == "passed" for gate in good_result["verification"]["gates"])
        assert good_result["review"]["accepted"] is True
        expected_workspace = f"/repositories/.repo.astra-worktrees/{good['task_id']}"
        assert good_result["verification"]["workspace"] == expected_workspace
        isolated = command(
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "from pathlib import Path; "
            "assert not Path('/repositories/repo/demo_math.py').exists(); "
            "assert not Path('/var/run/docker.sock').exists(); "
            "print('original unchanged; API has no socket')",
        )
        report["original_repository_isolation"] = isolated.stdout.strip()
        bad = run_task("def add(a: int, b: int) -> int:\n    return a - b\n", "failed")
        assert any(gate["status"] == "failed" for gate in bad["result"]["verification"]["gates"])
        assert (
            request(
                "POST", "/controls/kill-switch", "developer", json={"enabled": True}
            ).status_code
            == 403
        )
        assert (
            request("POST", "/controls/kill-switch", "admin", json={"enabled": True}).status_code
            == 200
        )
        denied = request(
            "POST",
            "/tasks",
            json={"prompt": "must not execute", "repo_path": "/repositories/repo", "risk": "T2"},
        )
        assert denied.status_code == 403, denied.text
        assert (
            request("POST", "/controls/kill-switch", "admin", json={"enabled": False}).status_code
            == 200
        )
        command("restart", "api")
        wait_api()
        persisted = request("GET", f"/tasks/{good['task_id']}/result").json()
        assert (
            persisted["result"]["verification"]["evidence_hash"]
            == good_result["verification"]["evidence_hash"]
        )
        command(
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            "from astra_coder.persistence import StateStore,AuditLog; "
            "assert AuditLog(StateStore('sqlite:////data/astra.db')).verify_chain(); "
            "print('audit chain verified')",
        )
        report.update(
            {
                "status": "passed",
                "positive_execution": good,
                "negative_execution": bad,
                "authentication": "401 unauthenticated; 403 developer approval/admin controls",
                "kill_switch": "admin-only durable switch denied new tasks",
                "durability": "same result and evidence hash survived API process restart",
                "audit_chain": "verified across API and worker events",
            }
        )
        print(f"PASS: real worker flow; positive={good['task_id']} negative={bad['task_id']}")
    except Exception as exc:
        report["status"] = "failed"
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr)
        logs = subprocess.run(  # noqa: S603
            [*compose, "logs", "--no-color", "worker", "workspace-seed"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        print(logs.stdout)
        raise
    finally:
        client.close()
        command("stop")
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["data_retained"] = True
        # Standard artifact, containing only demo inputs/evidence, never credentials.
        output = root / "reports" / "worker-smoke.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Evidence: reports/worker-smoke.json (services stopped, volumes retained)")


if __name__ == "__main__":
    main()
