"""Execution receipt builder and hash-chained audit log writer."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

_EVENT_SHA_RE = re.compile(r"[0-9a-f]{64}")
_EVENT_REQUIRED_KEYS = (
    "event_id",
    "event_type",
    "stage",
    "actor_type",
    "actor_identity",
    "authorization_id",
    "timestamp_utc",
    "decision",
    "evidence_reference",
    "previous_event_hash",
    "event_sha256",
)
_ACTOR_TYPES = frozenset({"HUMAN_OPERATOR", "SYSTEM_VERIFIER"})
_DECISIONS = frozenset({"PENDING", "APPROVED", "REJECTED", "REVOKED"})


def build_execution_receipt(
    *,
    receipt_id: str,
    receipt_kind: Literal["AUDIT_ONLY", "EXECUTION"],
    license_reference: str,
    resolution_status: Literal["RESOLVED", "UNRESOLVED", "FAILED"],
    resolved_target: str | None,
    digest_status: Literal["VERIFIED", "MISMATCH", "UNVERIFIED"],
    actual_sha256: str | None,
    expected_sha256: str | None,
    decision: Literal["ALLOW", "DENY", "ESCALATE"],
    authority: str,
    anchor_ref: str,
    signed: bool,
    key_id: str | None,
    revoked: bool = False,
    ntp_drift_seconds: float = 0.0,
    monotonic_sequence: int = 1,
    recorded_at_utc: str | None = None,
    expires_at_utc: str = "2027-05-18T00:00:00Z",
    handle_id: str = "vbh-stage05b-001",
) -> dict[str, Any]:
    """Build a dictionary conforming to docs/schemas/execution-receipt.schema.json."""
    if receipt_kind == "EXECUTION" and (not signed or revoked):
        raise ValueError("EXECUTION receipt requires signed=True and revoked=False")
    if not (-2.0 <= ntp_drift_seconds <= 2.0):
        raise ValueError("ntp_drift_seconds must be within [-2, 2]")
    if monotonic_sequence < 1:
        raise ValueError("monotonic_sequence must be >= 1")

    ts = recorded_at_utc or datetime.now(UTC).isoformat()
    return {
        "receipt_id": receipt_id,
        "receipt_kind": receipt_kind,
        "recorded_at_utc": ts,
        "ntp_drift_seconds": ntp_drift_seconds,
        "monotonic_sequence": monotonic_sequence,
        "license_reference": license_reference,
        "verified_byte_handle": {
            "handle_id": handle_id,
            "immutable": True,
            "retention_days": 180,
            "expires_at_utc": expires_at_utc,
        },
        "obligations": {
            "reference_resolution": {
                "status": resolution_status,
                "resolved_target": resolved_target,
            },
            "sha256_digest_verification": {
                "status": digest_status,
                "actual_sha256": actual_sha256,
                "expected_sha256": expected_sha256,
            },
            "license_decision": {
                "decision": decision,
                "authority": authority,
                "decided_at_utc": ts,
            },
        },
        "anchor_record": {
            "append_only": True,
            "dual_authority_recovery": True,
            "anchor_ref": anchor_ref,
        },
        "signature": {
            "signed": signed,
            "key_id": key_id if signed else None,
            "key_rotation_days_max": 90,
            "revoked": revoked,
        },
    }


def _canonical_event_hash(event: Mapping[str, Any]) -> str:
    """SHA-256 over the event with event_sha256 excluded, deterministic JSON."""
    payload = {k: v for k, v in event.items() if k != "event_sha256"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_event_chain(events: Any) -> list[dict[str, Any]]:
    """Validate audit-log event structure and the full hash chain.

    Rejects non-list events, malformed entries, duplicate event ids, broken
    previous_event_hash links, and stored event_sha256 values that do not match
    the recomputed canonical hash. The first event must have a null
    previous_event_hash (genesis rule used by this writer). Raises ValueError
    on any defect; returns the verified event list otherwise.
    """
    if not isinstance(events, list):
        raise ValueError("audit log events must be a list")
    verified: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    prev_hash: str | None = None
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"audit log event at index {index} is not an object")
        missing = [k for k in _EVENT_REQUIRED_KEYS if k not in event]
        if missing:
            raise ValueError(
                f"audit log event at index {index} is missing required fields: {missing}"
            )
        event_id = event["event_id"]
        if not isinstance(event_id, str) or not event_id:
            raise ValueError(f"audit log event at index {index} has invalid event_id")
        if event_id in seen_ids:
            raise ValueError(f"audit log contains duplicate event_id: {event_id}")
        seen_ids.add(event_id)
        if event["stage"] != "05b":
            raise ValueError(f"audit log event at index {index} has invalid stage")
        if event["actor_type"] not in _ACTOR_TYPES:
            raise ValueError(f"audit log event at index {index} has invalid actor_type")
        if event["decision"] not in _DECISIONS:
            raise ValueError(f"audit log event at index {index} has invalid decision")

        stored_prev = event["previous_event_hash"]
        if index == 0:
            if stored_prev is not None:
                raise ValueError("audit log first event must have null previous_event_hash")
        elif stored_prev != prev_hash:
            raise ValueError(f"audit log chain link broken at event index {index}")

        stored = event["event_sha256"]
        if not isinstance(stored, str) or not _EVENT_SHA_RE.fullmatch(stored):
            raise ValueError(f"audit log event at index {index} has invalid event_sha256 format")
        recomputed = _canonical_event_hash(event)
        if recomputed != stored:
            raise ValueError(
                f"audit log chain verification failed at event index {index}: "
                "stored event_sha256 does not match recomputed hash"
            )
        prev_hash = stored
        verified.append(event)
    return verified


def _atomic_write_json(target: Path, doc: dict[str, Any]) -> None:
    """Write the full JSON document via temp file + os.replace (atomic replace).

    This is not byte-level append-only: the document is re-serialized whole.
    Prior event objects and their verified hashes are preserved unchanged, and
    the replace is atomic on the same filesystem.
    """
    payload = json.dumps(doc, indent=2) + "\n"
    tmp = target.with_name(target.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def append_audit_event(
    log_path: Path | str,
    *,
    event_id: str,
    event_type: str,
    actor_type: Literal["HUMAN_OPERATOR", "SYSTEM_VERIFIER"],
    actor_identity: str | None,
    authorization_id: str | None,
    decision: Literal["PENDING", "APPROVED", "REJECTED", "REVOKED"],
    evidence_reference: str | None,
    timestamp_utc: str | None = None,
    repository: str = "lakshmanghosh1900-prog/Astra-Hybrid-Code",
) -> dict[str, Any]:
    """Append a SHA-256 hash-chained event matching authorization-log.schema.json.

    The entire existing chain is re-verified (structure, links, recomputed
    hashes) before anything is written; a failed verification raises ValueError
    and leaves the file untouched. integrity.verified is set to true only after
    the complete chain, including the new event, has been verified.
    """
    target = Path(log_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        try:
            raw = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"audit log could not be read ({type(exc).__name__})") from exc
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("audit log is not valid JSON") from exc
        if not isinstance(doc, dict):
            raise ValueError("audit log root must be a JSON object")
        if "events" not in doc:
            raise ValueError("audit log is missing the events field")
        verified_events = verify_event_chain(doc.get("events"))
    else:
        doc = {
            "schema_version": "1.0.0",
            "artifact_type": "ASTRA_CODER_AUTHORIZATION_AUDIT_LOG",
            "repository": repository,
            "events": [],
            "integrity": {
                "append_only": True,
                "tamper_evident": True,
                "hash_algorithm": "SHA-256",
                "verified": True,
            },
        }
        verified_events = []

    prev_hash = verified_events[-1]["event_sha256"] if verified_events else None
    ts = timestamp_utc or datetime.now(UTC).isoformat()

    event_payload = {
        "event_id": event_id,
        "event_type": event_type,
        "stage": "05b",
        "actor_type": actor_type,
        "actor_identity": actor_identity,
        "authorization_id": authorization_id,
        "timestamp_utc": ts,
        "decision": decision,
        "evidence_reference": evidence_reference,
        "previous_event_hash": prev_hash,
    }
    full_event = {**event_payload, "event_sha256": _canonical_event_hash(event_payload)}

    candidate_events = [*verified_events, full_event]
    verify_event_chain(candidate_events)

    doc["events"] = candidate_events
    doc["integrity"] = {
        "append_only": True,
        "tamper_evident": True,
        "hash_algorithm": "SHA-256",
        "verified": True,
    }

    _atomic_write_json(target, doc)
    return full_event
