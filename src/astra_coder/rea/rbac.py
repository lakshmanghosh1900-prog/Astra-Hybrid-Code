"""Strict RBAC policy enforcement for Stage 05b REA governance."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from .trust import validate_trusted_approver
from .validation import strict_sha256

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

_APPROVAL_REQUIRED_ROLES = frozenset({"EXECUTOR", "AGENT", "OPERATOR"})
_APPROVAL_ACTIONS = frozenset({"APPROVE_STAGE_05B", "RUN_REA_EXECUTION"})


@dataclass(frozen=True)
class RbacDecision:
    allowed: bool
    actor_id: str
    role: str
    action: str
    reason: str


def evaluate_rbac(
    *,
    actor_id: object,
    role: object,
    action: object,
    approver_id: object = None,
    self_certified: object = False,
    approver_context: object = None,
    require_scope_binding: object = False,
) -> RbacDecision:
    actor_out = actor_id if isinstance(actor_id, str) else ""
    role_out = role if isinstance(role, str) else ""
    action_out = action if isinstance(action, str) else ""
    approver_out = approver_id if isinstance(approver_id, str) else None

    if (
        not isinstance(actor_id, str)
        or not isinstance(role, str)
        or not isinstance(action, str)
        or (approver_id is not None and not isinstance(approver_id, str))
        or not isinstance(self_certified, bool)
        or (approver_context is not None and not isinstance(approver_context, Mapping))
        or not isinstance(require_scope_binding, bool)
    ):
        return RbacDecision(
            allowed=False,
            actor_id=actor_out,
            role=role_out,
            action=action_out,
            reason="Invalid RBAC input types",
        )

    assert isinstance(actor_id, str)
    assert isinstance(role, str)
    assert isinstance(action, str)
    assert approver_id is None or isinstance(approver_id, str)
    assert isinstance(self_certified, bool)
    assert approver_context is None or isinstance(approver_context, Mapping)
    assert isinstance(require_scope_binding, bool)

    clean_actor = actor_id.strip()
    clean_role = role.strip().upper()
    clean_action = action.strip().upper()
    clean_approver = approver_out.strip() if approver_out is not None else ""
    context = dict(approver_context or {})

    if not clean_actor:
        return RbacDecision(
            allowed=False,
            actor_id="",
            role=clean_role,
            action=clean_action,
            reason="Missing actor_id",
        )

    signing_principal = context.get("signing_key_id")
    if isinstance(signing_principal, str) and signing_principal.strip():
        clean_signer = signing_principal.strip()
        if clean_approver and clean_signer == clean_approver:
            return RbacDecision(
                allowed=False,
                actor_id=clean_actor,
                role=clean_role,
                action=clean_action,
                reason="Signing principal must be separated from approving principal",
            )
        if clean_signer == clean_actor:
            return RbacDecision(
                allowed=False,
                actor_id=clean_actor,
                role=clean_role,
                action=clean_action,
                reason="Signing principal must be separated from acting principal",
            )

    if require_scope_binding:
        if (
            not isinstance(context.get("authorization_id"), str)
            or not context["authorization_id"].strip()
        ):
            return RbacDecision(
                allowed=False,
                actor_id=clean_actor,
                role=clean_role,
                action=clean_action,
                reason="Scope binding requires an authorization_id in approval context",
            )
        if strict_sha256(context.get("artifact_sha256")) is None:
            return RbacDecision(
                allowed=False,
                actor_id=clean_actor,
                role=clean_role,
                action=clean_action,
                reason="Scope binding requires an artifact_sha256 in approval context",
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

    if clean_role == "HUMAN_APPROVER" and clean_action in _APPROVAL_ACTIONS:
        raw_now = context.get("now")
        now = raw_now if isinstance(raw_now, datetime) else None
        approver_error = validate_trusted_approver(clean_actor, clean_action, context, now)
        if approver_error is not None:
            return RbacDecision(
                allowed=False,
                actor_id=clean_actor,
                role=clean_role,
                action=clean_action,
                reason=approver_error,
            )

    if clean_role in _APPROVAL_REQUIRED_ROLES and self_certified:
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason=f"Role {clean_role} cannot self-certify execution",
        )

    if (
        clean_action in _APPROVAL_ACTIONS
        and clean_approver
        and clean_approver == clean_actor
        and clean_role in _APPROVAL_REQUIRED_ROLES
    ):
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason="Self-authorization by executor/agent/operator is prohibited",
        )

    if clean_approver and clean_approver == clean_actor:
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason="Actor and approver principals must be separated",
        )

    if (
        clean_action in _APPROVAL_ACTIONS
        and clean_role in _APPROVAL_REQUIRED_ROLES
        and not clean_approver
    ):
        return RbacDecision(
            allowed=False,
            actor_id=clean_actor,
            role=clean_role,
            action=clean_action,
            reason=(
                "Independent trusted approver required: this role cannot run or "
                "certify Stage 05b without an approved identity"
            ),
        )

    if clean_action in _APPROVAL_ACTIONS and clean_approver:
        raw_now = context.get("now")
        now = raw_now if isinstance(raw_now, datetime) else None
        error = validate_trusted_approver(clean_approver, clean_action, context, now)
        if error is not None:
            return RbacDecision(
                allowed=False,
                actor_id=clean_actor,
                role=clean_role,
                action=clean_action,
                reason=error,
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
