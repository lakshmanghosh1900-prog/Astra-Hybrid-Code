from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
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
    authorization_id: str | None
    artifact_sha256: str | None
    not_before: datetime | None
    not_after: datetime | None


def _load_registry(env_name: str, section: str) -> dict[str, Any]:
    raw_path = os.environ.get(env_name)
    if not raw_path:
        return {}
    path = Path(raw_path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(document, dict):
        return {}
    records = document.get(section)
    if not isinstance(records, dict):
        return {}
    return records


def _parse_optional_time(value: Any) -> tuple[datetime | None, bool]:
    if value is None:
        return None, True
    parsed = parse_aware_utc(value)
    return parsed, parsed is not None


def load_trusted_keys() -> dict[str, TrustedKey]:
    records = _load_registry(_TRUSTED_KEYS_ENV, "keys")
    result: dict[str, TrustedKey] = {}
    for key_id, raw in records.items():
        if not isinstance(key_id, str) or not key_id.strip():
            continue
        if not isinstance(raw, dict):
            continue
        public_key = raw.get("public_key_pem")
        if not isinstance(public_key, str) or not public_key.strip():
            continue
        if raw.get("status") != "ACTIVE":
            continue
        not_before, before_ok = _parse_optional_time(raw.get("not_before"))
        not_after, after_ok = _parse_optional_time(raw.get("not_after"))
        if not before_ok or not after_ok:
            continue
        result[key_id] = TrustedKey(
            key_id=key_id,
            public_key=public_key.encode("utf-8"),
            status="ACTIVE",
            not_before=not_before,
            not_after=not_after,
        )
    return result


def load_trusted_approvers() -> dict[str, TrustedApprover]:
    records = _load_registry(_APPROVERS_ENV, "approvers")
    result: dict[str, TrustedApprover] = {}
    for approver_id, raw in records.items():
        if not isinstance(approver_id, str) or not approver_id.strip():
            continue
        if not isinstance(raw, dict):
            continue
        if raw.get("status") != "ACTIVE" or raw.get("role") != "HUMAN_APPROVER":
            continue
        not_before, before_ok = _parse_optional_time(raw.get("not_before"))
        not_after, after_ok = _parse_optional_time(raw.get("not_after"))
        if not before_ok or not after_ok:
            continue
        raw_actions = raw.get("allowed_actions")
        if isinstance(raw_actions, list) and all(isinstance(a, str) for a in raw_actions):
            allowed_actions = frozenset(raw_actions)
        elif raw_actions is None:
            allowed_actions = frozenset()
        else:
            continue
        authorization_id = raw.get("authorization_id")
        if authorization_id is not None and not isinstance(authorization_id, str):
            continue
        artifact_sha256 = strict_sha256(raw.get("artifact_sha256"))
        if raw.get("artifact_sha256") is not None and artifact_sha256 is None:
            continue
        result[approver_id] = TrustedApprover(
            approver_id=approver_id,
            role="HUMAN_APPROVER",
            status="ACTIVE",
            allowed_actions=allowed_actions,
            authorization_id=authorization_id,
            artifact_sha256=artifact_sha256,
            not_before=not_before,
            not_after=not_after,
        )
    return result


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
    approver = load_trusted_approvers().get(approver_id)
    if approver is None:
        return f"Unknown or untrusted approver_id: {approver_id}"
    if not approver_is_active(approver, reference):
        return f"Approver is not active: {approver_id}"
    if not approver.allowed_actions or action not in approver.allowed_actions:
        return f"Approver is not authorized for action: {action}"
    if (
        approver.authorization_id is not None
        and context.get("authorization_id") != approver.authorization_id
    ):
        return "Approval record is bound to a different authorization"
    if (
        approver.artifact_sha256 is not None
        and context.get("artifact_sha256") != approver.artifact_sha256
    ):
        return "Approval record is bound to a different artifact digest"
    return None
