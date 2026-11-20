from __future__ import annotations

import uuid
from pathlib import Path
from typing import Literal

from .gate import ReaGateResult, enforce_rea_gate
from .receipt import append_audit_event


def require_stage05b_execution(
    *,
    repo_root: Path | str,
    actor_id: str,
    role: str,
    action: str = "RUN_REA_EXECUTION",
    approver_id: str | None = None,
    self_certified: bool = False,
    audit_log_path: Path | str | None = None,
) -> ReaGateResult:
    result = enforce_rea_gate(
        repo_root=repo_root,
        actor_id=actor_id,
        role=role,
        action=action,
        approver_id=approver_id,
        self_certified=self_certified,
        require_scope_binding=True,
    )
    if audit_log_path is None:
        return result
    actor_type: Literal["HUMAN_OPERATOR", "SYSTEM_VERIFIER"] = (
        "HUMAN_OPERATOR" if role == "HUMAN_APPROVER" else "SYSTEM_VERIFIER"
    )
    try:
        append_audit_event(
            Path(audit_log_path),
            event_id=f"rea-{uuid.uuid4().hex}",
            event_type="STAGE_05B_GATE_EVALUATED",
            actor_type=actor_type,
            actor_identity=actor_id,
            authorization_id=None,
            decision="APPROVED" if result.allowed else "REJECTED",
            evidence_reference=result.evaluated_at_utc,
            timestamp_utc=result.evaluated_at_utc,
        )
    except (OSError, ValueError) as exc:
        return ReaGateResult(
            allowed=False,
            stage=result.stage,
            checks=result.checks,
            blocking_reasons=[
                *result.blocking_reasons,
                f"R4 audit append failed closed: {type(exc).__name__}: {exc}",
            ],
            evaluated_at_utc=result.evaluated_at_utc,
        )
    return result
