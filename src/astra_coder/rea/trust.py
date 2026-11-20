"""Trust registries are env-named JSON files and the single source of trust.

The file named by ``ASTRA_REA_TRUSTED_KEYS_PATH`` holds ``keys`` and the file
named by ``ASTRA_REA_APPROVER_REGISTRY_PATH`` holds ``approvers``. Key records
carry ``public_key_pem`` and optional ``not_before`` / ``not_after``. Approver
records carry ``allowed_actions``, ``authorization_id``, ``artifact_sha256``,
and optional ``bundle_sha256`` bindings. There are no in-code key or approver
fallbacks: a missing, unreadable, or malformed registry yields an explicit
fail-closed diagnostic from the detailed loaders.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .clock import MAX_CLOCK_SKEW_SECONDS
from .validation import parse_aware_utc, strict_sha256

_TRUSTED_KEYS_ENV = "ASTRA_REA_TRUSTED_KEYS_PATH"
_APPROVERS_ENV = "ASTRA_REA_APPROVER_REGISTRY_PATH"


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    public_key: bytes
    status: str
    not_before: datetime | None
    not_after: datetime | None


@dataclass(frozen=True)
class TrustedApprover:
    approver_id: str
    role: str
    status: str
    allowed_actions: frozenset[str]
    authorization_id: str
    artifact_sha256: str
    bundle_sha256: str | None
    not_before: datetime | None
    not_after: datetime | None


@dataclass(frozen=True)
class TrustedKeyLoadResult:
    keys: dict[str, TrustedKey]
    error: str | None
    issues: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TrustedApproverLoadResult:
    approvers: dict[str, TrustedApprover]
    error: str | None
    issues: tuple[str, ...] = field(default_factory=tuple)


def _load_registry_detailed(env_name: str, section: str) -> tuple[dict[str, Any], str | None]:
    raw_path = os.environ.get(env_name)
    if not raw_path or not raw_path.strip():
        return {}, f"{env_name} is not configured (file-based registry is required)"
    path = Path(raw_path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {}, f"{env_name} registry could not be loaded ({type(exc).__name__}): {raw_path}"
    if not isinstance(document, dict):
        return {}, f"{env_name} registry root must be a JSON object: {raw_path}"
    records = document.get(section)
    if not isinstance(records, dict):
        return {}, f"{env_name} registry is missing the '{section}' object: {raw_path}"
    return records, None


def _combine_registry_error(env_name: str, error: str | None, issues: list[str]) -> str | None:
    if not issues:
        return error
    detail = "; ".join(issues)
    if error is not None:
        return f"{error}; {detail}"
    return f"{env_name} registry validation failed: {detail}"


def _load_registry(env_name: str, section: str) -> dict[str, Any]:
    return _load_registry_detailed(env_name, section)[0]


def _parse_optional_time(value: Any) -> tuple[datetime | None, bool]:
    if value is None:
        return None, True
    parsed = parse_aware_utc(value)
    return parsed, parsed is not None


def load_trusted_keys_detailed() -> TrustedKeyLoadResult:
    records, error = _load_registry_detailed(_TRUSTED_KEYS_ENV, "keys")
    result: dict[str, TrustedKey] = {}
    issues: list[str] = []
    for key_id, raw in records.items():
        if not isinstance(key_id, str) or not key_id.strip():
            issues.append(f"key entry has invalid key_id: {key_id!r}")
            continue
        if not isinstance(raw, dict):
            issues.append(f"key entry {key_id!r} is not a JSON object")
            continue
        public_key = raw.get("public_key_pem")
        if not isinstance(public_key, str) or not public_key.strip():
            issues.append(f"key entry {key_id!r} is missing public_key_pem")
            continue
        if raw.get("status") != "ACTIVE":
            continue
        not_before, before_ok = _parse_optional_time(raw.get("not_before"))
        not_after, after_ok = _parse_optional_time(raw.get("not_after"))
        if not before_ok or not after_ok:
            issues.append(f"key entry {key_id!r} has malformed not_before/not_after")
            continue
        result[key_id] = TrustedKey(
            key_id=key_id,
            public_key=public_key.encode("utf-8"),
            status="ACTIVE",
            not_before=not_before,
            not_after=not_after,
        )
    combined = _combine_registry_error(_TRUSTED_KEYS_ENV, error, issues)
    return TrustedKeyLoadResult(result, combined, tuple(issues))


def load_trusted_keys() -> dict[str, TrustedKey]:
    return load_trusted_keys_detailed().keys


def load_trusted_approvers_detailed() -> TrustedApproverLoadResult:
    records, error = _load_registry_detailed(_APPROVERS_ENV, "approvers")
    result: dict[str, TrustedApprover] = {}
    issues: list[str] = []
    for approver_id, raw in records.items():
        if not isinstance(approver_id, str) or not approver_id.strip():
            issues.append(f"approver entry has invalid approver_id: {approver_id!r}")
            continue
        if not isinstance(raw, dict):
            issues.append(f"approver entry {approver_id!r} is not a JSON object")
            continue
        if raw.get("status") != "ACTIVE" or raw.get("role") != "HUMAN_APPROVER":
            continue
        not_before, before_ok = _parse_optional_time(raw.get("not_before"))
        not_after, after_ok = _parse_optional_time(raw.get("not_after"))
        if not before_ok or not after_ok:
            issues.append(f"approver entry {approver_id!r} has malformed not_before/not_after")
            continue
        raw_actions = raw.get("allowed_actions")
        if isinstance(raw_actions, list) and all(isinstance(a, str) for a in raw_actions):
            allowed_actions = frozenset(raw_actions)
        elif raw_actions is None:
            allowed_actions = frozenset()
        else:
            issues.append(f"approver entry {approver_id!r} has malformed allowed_actions")
            continue
        authorization_id = raw.get("authorization_id")
        if not isinstance(authorization_id, str) or not authorization_id.strip():
            issues.append(f"approver entry {approver_id!r} is missing authorization_id binding")
            continue
        artifact_sha256 = strict_sha256(raw.get("artifact_sha256"))
        if artifact_sha256 is None:
            issues.append(
                f"approver entry {approver_id!r} is missing or invalid artifact_sha256 binding"
            )
            continue
        bundle_sha256: str | None = None
        if raw.get("bundle_sha256") is not None:
            bundle_sha256 = strict_sha256(raw.get("bundle_sha256"))
            if bundle_sha256 is None:
                issues.append(f"approver entry {approver_id!r} has invalid bundle_sha256")
                continue
        result[approver_id] = TrustedApprover(
            approver_id=approver_id,
            role="HUMAN_APPROVER",
            status="ACTIVE",
            allowed_actions=allowed_actions,
            authorization_id=authorization_id,
            artifact_sha256=artifact_sha256,
            bundle_sha256=bundle_sha256,
            not_before=not_before,
            not_after=not_after,
        )
    combined = _combine_registry_error(_APPROVERS_ENV, error, issues)
    return TrustedApproverLoadResult(result, combined, tuple(issues))


def load_trusted_approvers() -> dict[str, TrustedApprover]:
    return load_trusted_approvers_detailed().approvers


def key_is_active(key: TrustedKey, now: datetime) -> bool:
    if key.status != "ACTIVE":
        return False
    if (
        key.not_before is not None
        and now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) < key.not_before
    ):
        return False
    if (
        key.not_after is not None
        and now - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) > key.not_after
    ):
        return False
    return True


def approver_is_active(approver: TrustedApprover, now: datetime) -> bool:
    if approver.status != "ACTIVE" or approver.role != "HUMAN_APPROVER":
        return False
    if (
        approver.not_before is not None
        and now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) < approver.not_before
    ):
        return False
    if (
        approver.not_after is not None
        and now - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) > approver.not_after
    ):
        return False
    return True


def validate_trusted_approver(
    approver_id: str,
    action: str,
    context: Mapping[str, Any],
    now: datetime | None = None,
) -> str | None:
    reference = now if now is not None else datetime.now(UTC)
    load_result = load_trusted_approvers_detailed()
    if load_result.error is not None:
        return f"Approver registry unavailable: {load_result.error}"
    approver = load_result.approvers.get(approver_id)
    if approver is None:
        return f"Unknown or untrusted approver_id: {approver_id}"
    if not approver_is_active(approver, reference):
        return f"Approver is not active: {approver_id}"
    if not approver.allowed_actions or action not in approver.allowed_actions:
        return f"Approver is not authorized for action: {action}"

    context_auth_id = context.get("authorization_id")
    if not isinstance(context_auth_id, str) or not context_auth_id.strip():
        return "Approval context is missing authorization_id"
    if context_auth_id != approver.authorization_id:
        return "Approval record is bound to a different authorization"

    context_artifact_sha = strict_sha256(context.get("artifact_sha256"))
    if context_artifact_sha is None:
        return "Approval context is missing or invalid artifact_sha256"
    if context_artifact_sha != approver.artifact_sha256:
        return "Approval record is bound to a different artifact digest"

    context_bundle_sha = context.get("bundle_sha256")
    if approver.bundle_sha256 is not None:
        if strict_sha256(context_bundle_sha) != approver.bundle_sha256:
            return "Approval record is bound to a different bundle digest"
    elif context_bundle_sha is not None:
        return f"Approver registry entry is missing bundle_sha256 binding: {approver_id}"
    return None
