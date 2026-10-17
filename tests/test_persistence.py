from uuid import uuid4

from sqlalchemy import update

from astra_coder.persistence import AuditLog, AuditRecord, StateStore
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
    assert state.get_task(task.id).failure_reason.startswith("interrupted")
    assert audit.replay(str(task.id))[0].decision == "failed_closed"
