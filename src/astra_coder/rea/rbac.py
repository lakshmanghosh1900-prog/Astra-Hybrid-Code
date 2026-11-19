"""Strict RBAC policy enforcement for Stage 05b REA governance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

RoleName = Literal["HUMAN_APPROVER", "OPERATOR", "REVIEWER", "EXECUTOR", "AGENT"]
ActionName = Literal[
    "APPROVE_STAGE_05B",
    "REVOKE_AUTHORIZATION",
    "RUN_REA_EXECUTION",
    "RUN_AUDIT_ONLY",
    "INSPECT_ARTIFACTS",
]

_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "HUMAN_APPROVER": {
        "APPROVE_STAGE_05B",
        "REVOKE_AUTHORIZATION",
        "RUN_REA_EXECUTION",
        "RUN_AUDIT_ONLY",
        "INSPECT_ARTIFACTS",
    },
    "OPERATOR": {
        "RUN_REA_EXECUTION",
        "RUN_AUDIT_ONLY",
        "INSPECT_ARTIFACTS",
    },
    "REVIEWER": {
        "RUN_AUDIT_ONLY",
        "INSPECT_ARTIFACTS",
    },
    "EXECUTOR": {
        "RUN_REA_EXECUTION",
        "RUN_AUDIT_ONLY",
        "INSPECT_ARTIFACTS",
    },
    "AGENT": {
        "INSPECT_ARTIFACTS",
    },
}


@dataclass(frozen=True)
class RbacDecision:
    allowed: bool
    actor_id: str
    role: str
    action: str
    reason: str


def evaluate_rbac(
    *,
    actor_id: str,
    role: str,
    action: str,
    approver_id: str | None = None,
    self_certified: bool = False,
) -> RbacDecision:
    """Evaluate strict RBAC permissions and block self-approval/self-certification."""
    clean_actor = (actor_id or "").strip()
    clean_role = (role or "").strip().upper()
    clean_action = (action or "").strip().upper()

    if not clean_actor:
        return RbacDecision(
            allowed=False,
            actor_id="",
            role=clean_role,
            action=clean_action,
            reason="Missing actor_id",
        )

    if clean_role not in _ROLE_PERMISSIONS:
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason=f"Unknown or unauthorized role: {clean_role}",
        )

    if clean_action == "APPROVE_STAGE_05B" and clean_role != "HUMAN_APPROVER":
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason="Only HUMAN_APPROVER may approve Stage 05b",
        )

    if clean_role in {"EXECUTOR", "AGENT"} and self_certified:
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason=f"Role {clean_role} cannot self-certify execution",
        )

    if (
        clean_action in {"APPROVE_STAGE_05B", "RUN_REA_EXECUTION"}
        and approver_id is not None
        and approver_id.strip()
        and approver_id.strip() == clean_actor
        and clean_role in {"EXECUTOR", "AGENT"}
    ):
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason="Self-authorization by executor/agent is prohibited",
        )

    allowed_actions = _ROLE_PERMISSIONS[clean_role]
    if clean_action not in allowed_actions:
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason=f"Role {clean_role} is not permitted for action {clean_action}",
        )

    return RbacDecision(
        allowed=True,
        actor_id=clean_actor,
        role=clean_role,
        action=clean_action,
        reason="RBAC policy check passed",
    )
