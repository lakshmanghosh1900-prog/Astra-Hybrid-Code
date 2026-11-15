from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sqlalchemy import update

from astra_coder.persistence import AuditLog, AuditRecord, PersistenceError, StateStore
from astra_coder.runtime import Task, TaskState


def store() -> StateStore:
    return StateStore("sqlite:///:memory:")


def test_task_state_persists_and_reads_back() -> None:
    state = store()
    task = Task(prompt="persist", repo_path="/repo")
    state.save_task(task)
    task.state = TaskState.PLANNED
    state.save_task(task)
    loaded = state.get_task(task.id)
    assert loaded is not None
    assert loaded.state is TaskState.PLANNED


def test_audit_log_redacts_and_verifies_hash_chain() -> None:
    state = store()
    audit = AuditLog(state)
    first = audit.append("dev", "model_call", "task", "allowed", {"api_key": "secret", "count": 1})
    second = audit.append("dev", "write", "task", "allowed", {"path": "a.py"})
    assert first.metadata["api_key"] == "[REDACTED]"
    assert second.sequence == first.sequence + 1
    assert audit.verify_chain()


def test_audit_log_redacts_credential_aliases() -> None:
    audit = AuditLog(store())
    event = audit.append(
        "dev",
        "request",
        "task",
        "denied",
        {"authorization": "Bearer secret", "apiKey": "secret", "nested": {"private-key": "x"}},
    )
    assert event.metadata["authorization"] == "[REDACTED]"
    assert event.metadata["apiKey"] == "[REDACTED]"
    assert event.metadata["nested"]["private-key"] == "[REDACTED]"


def test_audit_tampering_is_detected() -> None:
    state = store()
    audit = AuditLog(state)
    event = audit.append("dev", "write", "task", "allowed", {"path": "a.py"})
    with state.sessions.begin() as session:
        session.execute(
            update(AuditRecord)
            .where(AuditRecord.sequence == event.sequence)
            .values(decision="bypassed")
        )
    assert not audit.verify_chain()


def test_replay_and_restart_recovery_fail_closed() -> None:
    state = store()
    audit = AuditLog(state)
    task = Task(id=uuid4(), prompt="recover", repo_path="/repo", state=TaskState.EDITING)
    state.save_task(task)
    recovered = state.recover_after_restart(audit)
    assert recovered[0].state is TaskState.FAILED
    loaded = state.get_task(task.id)
    assert loaded is not None and loaded.failure_reason is not None
    assert loaded.failure_reason.startswith("interrupted")
    assert audit.replay(str(task.id))[0].decision == "failed_closed"


def test_approval_survives_store_reopen_and_recovery_is_idempotent(tmp_path: Path) -> None:
    database = f"sqlite:///{tmp_path / 'state.db'}"
    first = StateStore(database)
    task = Task(id=uuid4(), prompt="recover", repo_path=str(tmp_path), state=TaskState.EDITING)
    first.save_task(task)
    first_audit = AuditLog(first)
    first.recover_after_restart(first_audit)
    reopened = StateStore(database)
    reopened_audit = AuditLog(reopened)
    assert reopened.recover_after_restart(reopened_audit) == ()
    reopened_task = reopened.get_task(task.id)
    assert reopened_task is not None
    assert reopened_task.state is TaskState.FAILED


def test_expired_and_revoked_approvals_are_inactive() -> None:
    state = store()
    task_id = uuid4()
    expired = state.save_approval(
        task_id,
        "reviewer",
        "",
        "a" * 64,
        "b" * 64,
        "1",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert not expired.active
    state.revoke_approval(task_id)
    revoked = state.get_approval(task_id)
    assert revoked is not None and not revoked.active


def test_execution_queue_claim_and_completion_are_durable() -> None:
    state = store()
    task = Task(prompt="queue", repo_path="/repo", state=TaskState.CONTEXT_BUILT)
    state.save_task(task)
    queued = state.enqueue_execution(task.id, "developer")
    assert queued.status == "queued"
    try:
        state.enqueue_execution(task.id, "developer")
    except PersistenceError as exc:
        assert "already queued" in str(exc)
    else:
        raise AssertionError("duplicate execution request was accepted")
    claimed = state.claim_next_execution("worker-1")
    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.worker_id == "worker-1"
    completed = state.complete_execution(task.id, "succeeded")
    assert completed.status == "succeeded"
    assert completed.completed_at is not None


def test_queued_execution_can_be_cancelled_without_claiming() -> None:
    state = store()
    task = Task(prompt="queue", repo_path="/repo", state=TaskState.CONTEXT_BUILT)
    state.save_task(task)
    state.enqueue_execution(task.id, "developer")
    cancelled = state.cancel_execution(task.id)
    assert cancelled is not None and cancelled.status == "cancelled"
    assert state.claim_next_execution("worker-1") is None


def test_restart_preserves_queued_execution_for_the_worker() -> None:
    state = store()
    audit = AuditLog(state)
    task = Task(prompt="queued", repo_path="/repo", state=TaskState.CONTEXT_BUILT)
    state.save_task(task)
    state.enqueue_execution(task.id, "developer")
    assert state.recover_after_restart(audit) == ()
    recovered = state.get_task(task.id)
    assert recovered is not None and recovered.state is TaskState.CONTEXT_BUILT
    request = state.get_execution_request(task.id)
    assert request is not None and request.status == "queued"


def test_audit_appenders_share_one_chain_across_store_instances(tmp_path: Path) -> None:
    database = f"sqlite:///{tmp_path / 'shared-audit.db'}"
    audits = [AuditLog(StateStore(database)), AuditLog(StateStore(database))]

    def append_many(index: int) -> None:
        for step in range(12):
            audits[index].append(f"writer-{index}", "step", str(step), "observed")

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(append_many, [0, 1]))
    assert len(audits[0].events()) == 24
    assert audits[0].verify_chain()
