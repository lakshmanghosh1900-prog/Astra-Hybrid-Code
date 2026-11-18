"""Opt-in dedicated structured-plan worker. Never runs repository code on its host."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from threading import Event

from .agents import ArchitectAgent, EditorAgent, IndependentReviewerAgent, Plan
from .config import Settings, load_settings
from .free_cascade import CascadePlanBuilder, build_free_cascade_gateway
from .memory_engine import AstraMemoryEngine
from .persistence import AuditLog, StateStore
from .policy import Actor, PolicyConfig, PolicyEngine
from .redaction import SecretRedactor
from .runtime import Task
from .sandbox import DockerSandbox
from .sandbox_tools import SandboxToolCall, validate_tool_call
from .security import AuditSink
from .verification import GateSpec, default_gates
from .worker import DockerOrchestratorFactory, GitWorktreeFactory, PolicyExecutionGuard, TaskWorker


def structured_plan(task: Task, context: str) -> Plan:
    """Explicit JSON plan mode: no simulated model calls or free-text success."""
    del context
    plan = Plan.model_validate_json(task.prompt)
    for step in plan.steps:
        call = SandboxToolCall.model_validate({"tool": step.tool, "arguments": step.payload})
        validate_tool_call(call)
    return plan


def build_architect(
    settings: Settings,
    policy: PolicyEngine,
    actor: Actor,
    audit_sink: AuditSink,
) -> ArchitectAgent:
    """Build the default free-cascade planner; structured JSON is an explicit fallback."""
    if settings.worker_plan_mode == "structured":
        return ArchitectAgent(structured_plan)
    gateway = build_free_cascade_gateway(settings)
    return ArchitectAgent(
        CascadePlanBuilder(
            gateway=gateway,
            policy=policy,
            actor=actor,
            audit_sink=audit_sink,
            redactor=SecretRedactor(settings.secret_values()),
            allow_remote_t4=settings.allow_remote_t4,
            allow_paid_remote=settings.allow_paid_remote,
        )
    )


def configured_gates(raw: str | None) -> tuple[GateSpec, ...]:
    if not raw:
        return default_gates()
    values = json.loads(raw)
    if not isinstance(values, list) or not values:
        raise ValueError("worker requires a nonempty list of independent verification gates")
    gates = tuple(GateSpec.model_validate(value) for value in values)
    if len({gate.name for gate in gates}) != len(gates):
        raise ValueError("verification gate names must be unique")
    return gates


def main() -> int:
    if os.environ.get("ASTRA_WORKER_ENABLED") != "1":
        raise RuntimeError("worker is disabled; explicitly set ASTRA_WORKER_ENABLED=1")
    settings = load_settings()
    if settings.repo_root is None or not settings.repo_root.is_dir():
        raise RuntimeError("worker requires an existing ASTRA_REPO_ROOT")
    sandbox = DockerSandbox()
    image = os.environ.get("ASTRA_SANDBOX_IMAGE", "astracoder-api:local")
    if not sandbox.available:
        raise RuntimeError("Docker unavailable; refusing host execution")
    for argv in (
        ["docker", "info", "--format", "{{.OSType}}"],
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
    ):
        checked = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)  # noqa: S603
        if checked.returncode != 0:
            raise RuntimeError("Docker engine or prebuilt sandbox image is unavailable")
    image = checked.stdout.strip()
    # Exactly one process owns this stable ID. A crash is recovered, never replayed.
    import fcntl

    lock_path = Path(os.environ.get("ASTRA_WORKER_LOCK", "/data/worker.lock"))
    with lock_path.open("a") as lock:
        # fcntl's Linux-only attributes are absent from Windows type stubs.
        getattr(fcntl, "flock")(lock, getattr(fcntl, "LOCK_EX") | getattr(fcntl, "LOCK_NB"))  # noqa: B009
        store = StateStore(settings.database_url)
        audit = AuditLog(store)
        worker_id = "compose-worker"
        memory = AstraMemoryEngine(
            os.environ.get("ASTRA_MEMORY_DB", "/data/astra-memory.db"),
            audit=audit,
            audit_actor=worker_id,
        )
        store.recover_worker_after_restart(audit, worker_id)
        policy = PolicyEngine(PolicyConfig(repo_root=settings.repo_root))
        worker_actor = Actor(actor_id=worker_id, role=settings.worker_role)

        def audit_sink(
            actor_id: str,
            action: str,
            target: str,
            decision: str,
            metadata: dict[str, object],
        ) -> object:
            return audit.append(actor_id, action, target, decision, metadata)

        architect = build_architect(settings, policy, worker_actor, audit_sink)
        guard = PolicyExecutionGuard(store, policy, worker_actor)
        factory = DockerOrchestratorFactory(
            architect,
            EditorAgent(),
            IndependentReviewerAgent(),
            image,
            sandbox=sandbox,
            gates=configured_gates(os.environ.get("ASTRA_WORKER_GATES_JSON")),
            boundary_guard=guard,
            workspace_volume=os.environ.get("ASTRA_WORKSPACE_VOLUME"),
            volume_root=settings.repo_root,
        )
        worker = TaskWorker(
            factory,
            GitWorktreeFactory(store),
            store=store,
            audit=audit,
            worker_id=worker_id,
            execution_guard=guard,
            memory=memory,
        )
        stopping = Event()
        signal.signal(signal.SIGTERM, lambda *_: stopping.set())
        signal.signal(signal.SIGINT, lambda *_: stopping.set())
        print("structured-plan worker ready; repository code is Docker-only", flush=True)
        while not stopping.is_set():
            result = worker.run_next(lambda _task: "")
            if result is not None:
                print(f"{result.task.id} {result.task.state.value}", flush=True)
            stopping.wait(0.5)
        memory.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"worker startup failed closed: {exc}", file=sys.stderr)
        time.sleep(1)
        raise SystemExit(1) from exc
