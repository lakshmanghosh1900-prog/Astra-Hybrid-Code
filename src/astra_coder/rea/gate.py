"""Fail-closed REA runtime gate enforcing R1, R2, R3, and RBAC."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    InvalidSignature = Exception  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    _HAS_CRYPTOGRAPHY = False

from astra_coder.license import (
    evaluate_license_decision,
    resolve_license_reference,
    verify_sha256_digest,
)

from .rbac import evaluate_rbac

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ReaGateResult:
    allowed: bool
    stage: str
    checks: dict[str, bool]
    blocking_reasons: list[str]
    evaluated_at_utc: str


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _strict_sha256(value: Any) -> str | None:
    """Return value only if it is exactly 64 lowercase hex characters (no normalization)."""
    if isinstance(value, str) and _SHA256_RE.fullmatch(value):
        return value
    return None


def _load_json_object(path: Path, label: str) -> tuple[dict[str, Any] | None, str | None]:
    """Load a JSON object; returns (object, None) or (None, category error reason)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"{label} could not be read ({type(exc).__name__})"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None, f"{label} is not valid JSON"
    if not isinstance(data, dict):
        return None, f"{label} root must be a JSON object"
    return data, None


def _parse_utc(ts: Any) -> datetime | None:
    """Strictly parse a timestamp: string, timezone-aware, valid calendar value.

    Returns None for missing, non-string, malformed, empty, or timezone-naive input.
    Naive timestamps are ambiguous and are never coerced to UTC.
    A trailing Z is accepted as an explicit UTC offset.
    """
    if not isinstance(ts, str):
        return None
    normalized = ts.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() is None:
        return None
    return dt.astimezone(UTC)


def _resolve_expiry(auth_data: dict[str, Any]) -> tuple[datetime | None, str | None]:
    """Resolve the R1 expiry instant.

    Canonical location: authorization.expires_at_utc, as required by
    docs/schemas/authorization.schema.json. A root-level expires_at_utc is not
    part of the schema; it is never used as a source of truth. If both locations
    are present they must both parse strictly and denote the same instant,
    otherwise the artifact is denied as conflicting. Exactly one of
    (expiry, error) is non-None.
    """
    nested_block = auth_data.get("authorization")
    nested_present = "expires_at_utc" in (nested_block if isinstance(nested_block, dict) else {})
    if "authorization" in auth_data and not isinstance(nested_block, dict):
        return None, "authorization block must be a JSON object"
    if not nested_present:
        return None, "missing required expiry (authorization.expires_at_utc)"

    nested_expiry = _parse_utc(
        nested_block.get("expires_at_utc") if isinstance(nested_block, dict) else None
    )
    if nested_expiry is None:
        return None, (
            "malformed, non-string, or timezone-naive expiry (authorization.expires_at_utc)"
        )

    if "expires_at_utc" in auth_data:
        root_expiry = _parse_utc(auth_data.get("expires_at_utc"))
        if root_expiry is None:
            return None, "malformed, non-string, or timezone-naive root-level expires_at_utc"
        if root_expiry != nested_expiry:
            return None, "conflicting expires_at_utc values at root and authorization levels"

    return nested_expiry, None


def _decode_pem_or_raw_public_key(raw: bytes) -> bytes:
    text = raw.decode("utf-8", errors="ignore").strip()
    if "BEGIN PUBLIC KEY" in text:
        loaded = serialization.load_pem_public_key(raw)
        return loaded.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    if len(raw) == 32:
        return raw
    return base64.b64decode(text)


def _verify_r1_signature(
    auth_data: dict[str, Any], public_key_pem: bytes | None
) -> tuple[bool, str]:
    """Verify the top-level Ed25519 signature block, failing closed on every path.

    Expected block: auth_data["signature"] with base64 value under
    "signature_base64" or "value", over the canonical JSON of all other fields.
    binascii.Error (malformed base64/padding) subclasses ValueError and is
    therefore handled by the ValueError branch.
    """
    sig_block = auth_data.get("signature")
    if not isinstance(sig_block, dict):
        return False, "Missing R1 signature block"
    sig_b64 = sig_block.get("signature_base64") or sig_block.get("value")
    if not isinstance(sig_b64, str) or not sig_b64.strip():
        return False, "Missing R1 Ed25519 signature value"
    if not _HAS_CRYPTOGRAPHY or Ed25519PublicKey is None:
        return False, "cryptography dependency unavailable for R1 signature verification"
    if public_key_pem is None:
        return False, "Missing Ed25519 public key for R1 verification"

    payload_copy = {k: v for k, v in auth_data.items() if k != "signature"}
    canonical_bytes = json.dumps(payload_copy, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(_decode_pem_or_raw_public_key(public_key_pem))
        sig_bytes = base64.b64decode(sig_b64, validate=True)
        pub_key.verify(sig_bytes, canonical_bytes)
    except InvalidSignature:
        return False, "R1 signature verification failed: signature does not match payload"
    except (ValueError, TypeError) as exc:
        return False, (
            "R1 signature verification failed: malformed signature or key material "
            f"({type(exc).__name__}: {exc})"
        )
    except Exception as exc:  # noqa: BLE001 - unexpected defects deny and stay distinguishable
        return False, f"R1 signature verification failed: unexpected {type(exc).__name__}"
    return True, "R1 Ed25519 signature verified"


def _resolve_contained_file(root: Path, raw: Any, label: str) -> tuple[Path | None, str | None]:
    """Resolve a repository-relative path and enforce containment within root.

    The resolved (symlink-following) path must stay inside root; parent
    traversal, absolute external paths, and symlinks escaping the repository are
    rejected. Returns (path, None) on success or (None, deny reason).
    This check is not race-free: a swap between resolution and the later read
    is not detected.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, f"{label} path must be a non-empty string"
    try:
        resolved = (root / raw).resolve()
    except (OSError, ValueError):
        return None, f"{label} path could not be resolved: {raw}"
    if not resolved.is_relative_to(root):
        return None, f"{label} path escapes repository root: {raw}"
    if not resolved.exists():
        return None, f"{label} file missing on disk: {raw}"
    if not resolved.is_file():
        return None, f"{label} path is not a regular file: {raw}"
    return resolved, None


def enforce_rea_gate(
    *,
    repo_root: Path | str,
    actor_id: str,
    role: str,
    action: str = "RUN_REA_EXECUTION",
    public_key_pem: bytes | None = None,
    now_utc: datetime | None = None,
    approver_id: str | None = None,
    self_certified: bool = False,
) -> ReaGateResult:
    """Enforce R1 authorization, R2 license gate, R3 input manifest, and RBAC.

    Expiry boundary: an authorization is expired iff now > expires_at_utc; the
    expiry instant itself is still valid. approver_id and self_certified are
    propagated to evaluate_rbac; EXECUTOR/AGENT execution or approval without an
    identified independent approver is denied (no permissive default bypass).
    """
    root = Path(repo_root).resolve()
    now = (now_utc or datetime.now(UTC)).astimezone(UTC)
    checks: dict[str, bool] = {
        "rbac_ok": False,
        "r1_present_and_valid": False,
        "r2_license_approved": False,
        "r3_manifest_and_hashes_ok": False,
    }
    reasons: list[str] = []

    rbac = evaluate_rbac(
        actor_id=actor_id,
        role=role,
        action=action,
        approver_id=approver_id,
        self_certified=self_certified,
    )
    checks["rbac_ok"] = rbac.allowed
    if not rbac.allowed:
        reasons.append(f"RBAC denied: {rbac.reason}")

    auth_path = root / "authorization.json"
    lic_path = root / "license-check.json"
    man_path = root / "rea-input-manifest.json"

    for label, p in [
        ("R1 authorization.json", auth_path),
        ("R2 license-check.json", lic_path),
        ("R3 rea-input-manifest.json", man_path),
    ]:
        if not p.exists() or not p.is_file():
            reasons.append(f"Missing required gate artifact: {label}")

    if reasons:
        return ReaGateResult(
            allowed=False,
            stage="05b",
            checks=checks,
            blocking_reasons=reasons,
            evaluated_at_utc=now.isoformat(),
        )

    auth_data, auth_err = _load_json_object(auth_path, "R1 authorization.json")
    lic_data, lic_err = _load_json_object(lic_path, "R2 license-check.json")
    man_data, man_err = _load_json_object(man_path, "R3 rea-input-manifest.json")
    load_errors = [e for e in (auth_err, lic_err, man_err) if e is not None]
    if load_errors:
        reasons.extend(load_errors)
        return ReaGateResult(
            allowed=False,
            stage="05b",
            checks=checks,
            blocking_reasons=reasons,
            evaluated_at_utc=now.isoformat(),
        )
    assert auth_data is not None and lic_data is not None and man_data is not None

    expiry_dt, expiry_err = _resolve_expiry(auth_data)
    sig_ok, sig_msg = _verify_r1_signature(auth_data, public_key_pem)
    expired = expiry_dt is not None and now > expiry_dt
    if expiry_err is not None:
        reasons.append(f"R1 {expiry_err}")
    if expired:
        reasons.append("R1 authorization has expired")
    if not sig_ok:
        reasons.append(sig_msg)
    r1_ok = expiry_err is None and not expired and sig_ok
    checks["r1_present_and_valid"] = r1_ok

    result_obj = lic_data.get("result")
    lic_status: Any = None
    stage_approved = False
    if isinstance(result_obj, dict):
        lic_status = result_obj.get("status")
        stage_approved = result_obj.get("approved_for_stage_05b") is True
    else:
        reasons.append("R2 license-check.json result block missing or not an object")

    lic_ref_str = lic_data.get("license_reference") or "SPDX:Apache-2.0"
    res_obj = resolve_license_reference(lic_ref_str, repo_root=root)

    evidence_raw = lic_data.get("evidence")
    if evidence_raw is not None and not isinstance(evidence_raw, dict):
        reasons.append("R2 license-check.json evidence block missing or not an object")
        evidence: dict[str, Any] = {}
    else:
        evidence = evidence_raw if isinstance(evidence_raw, dict) else {}
    sbom_rel = evidence.get("sbom_path") or "reports/sbom-requirements.txt"
    sbom_expected = evidence.get("sbom_sha256")
    sbom_file, sbom_err = _resolve_contained_file(root, sbom_rel, "R2 SBOM")
    if sbom_err is not None:
        reasons.append(sbom_err)
    dig_obj = verify_sha256_digest(sbom_file, sbom_expected)
    dec_obj = evaluate_license_decision(res_obj, dig_obj, authority="rea-gate")

    r2_ok = (lic_status == "PASS") and stage_approved and (dec_obj.decision == "ALLOW")
    if not r2_ok:
        reasons.append(
            f"R2 license gate failed: status={lic_status}, "
            f"approved_for_stage_05b={stage_approved}, decision={dec_obj.decision}"
        )
    checks["r2_license_approved"] = r2_ok

    auth_sha = _sha256_file(auth_path)
    lic_sha = _sha256_file(lic_path)
    auth_ref_blk = man_data.get("authorization_reference")
    lic_ref_blk = man_data.get("license_reference")
    if not isinstance(auth_ref_blk, dict) or not isinstance(lic_ref_blk, dict):
        reasons.append("R3 manifest authorization/license reference block missing or not an object")
        ref_match_ok = False
    else:
        man_auth_sha = _strict_sha256(auth_ref_blk.get("sha256"))
        man_lic_sha = _strict_sha256(lic_ref_blk.get("sha256"))
        if man_auth_sha is None or man_lic_sha is None:
            reasons.append(
                "R3 manifest cross-reference sha256 missing or not strict lowercase 64-hex"
            )
            ref_match_ok = False
        else:
            ref_match_ok = (man_auth_sha == auth_sha) and (man_lic_sha == lic_sha)
            if not ref_match_ok:
                reasons.append("R3 cross-reference SHA-256 mismatch with R1 or R2")

    inputs_raw = man_data.get("inputs")
    if not isinstance(inputs_raw, list):
        reasons.append("R3 manifest inputs must be a list")
        inputs_list: list[Any] = []
        all_inputs_ok = False
    else:
        inputs_list = inputs_raw
        all_inputs_ok = len(inputs_list) > 0
        if not inputs_list:
            reasons.append("R3 manifest inputs list is empty")

    for item in inputs_list:
        if not isinstance(item, dict):
            all_inputs_ok = False
            reasons.append("R3 manifest input entry must be an object")
            continue
        rel = item.get("source_path_or_uri")
        expected_sha = item.get("sha256")
        if not rel or not expected_sha:
            all_inputs_ok = False
            reasons.append("R3 input missing source_path_or_uri or sha256")
            continue
        expected = _strict_sha256(expected_sha)
        if expected is None:
            all_inputs_ok = False
            reasons.append(f"R3 SHA-256 for {rel} is not strict lowercase 64-hex")
            continue
        target_file, path_err = _resolve_contained_file(root, rel, "R3 input")
        if target_file is None:
            all_inputs_ok = False
            reasons.append(path_err or f"R3 input path could not be resolved: {rel}")
            continue
        actual_sha = _sha256_file(target_file)
        if actual_sha != expected:
            all_inputs_ok = False
            reasons.append(f"R3 SHA-256 mismatch for {rel}")

    r3_ok = all_inputs_ok and ref_match_ok
    checks["r3_manifest_and_hashes_ok"] = r3_ok

    allowed = all(checks.values()) and len(reasons) == 0
    return ReaGateResult(
        allowed=allowed,
        stage="05b",
        checks=checks,
        blocking_reasons=reasons,
        evaluated_at_utc=now.isoformat(),
    )
