"""Execution receipt builder and hash-chained audit log writer."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal


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
) -> dict:
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
) -> dict:
    """Append a SHA-256 hash-chained event matching authorization-log.schema.json."""
    target = Path(log_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        doc = json.loads(target.read_text(encoding="utf-8"))
        events = list(doc.get("events") or [])
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
        events = []

    prev_hash = events[-1]["event_sha256"] if events else None
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
    canonical = json.dumps(event_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event_sha = hashlib.sha256(canonical).hexdigest()

    full_event = {**event_payload, "event_sha256": event_sha}
    events.append(full_event)
    doc["events"] = events
    doc["integrity"] = {
        "append_only": True,
        "tamper_evident": True,
        "hash_algorithm": "SHA-256",
        "verified": True,
    }

    target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return full_event
