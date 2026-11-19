"""Fail-closed REA runtime gate enforcing R1, R2, R3, and RBAC."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

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


@dataclass(frozen=True)
class ReaGateResult:
    allowed: bool
    stage: str
    checks: dict[str, bool]
    blocking_reasons: list[str]
    evaluated_at_utc: str


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_utc(ts: str | None) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    normalized = ts.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _verify_r1_signature(auth_data: dict, public_key_pem: bytes | None) -> tuple[bool, str]:
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
        return True, "R1 Ed25519 signature verified"
    except (InvalidSignature, ValueError, Exception) as exc:
        return False, f"R1 signature verification failed: {exc}"


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


def enforce_rea_gate(
    *,
    repo_root: Path | str,
    actor_id: str,
    role: str,
    action: str = "RUN_REA_EXECUTION",
    public_key_pem: bytes | None = None,
    now_utc: datetime | None = None,
) -> ReaGateResult:
    """Enforce R1 authorization, R2 license gate, R3 input manifest, and RBAC."""
    root = Path(repo_root).resolve()
    now = (now_utc or datetime.now(UTC)).astimezone(UTC)
    checks: dict[str, bool] = {
        "rbac_ok": False,
        "r1_present_and_valid": False,
        "r2_license_approved": False,
        "r3_manifest_and_hashes_ok": False,
    }
    reasons: list[str] = []

    rbac = evaluate_rbac(actor_id=actor_id, role=role, action=action)
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

    auth_data = json.loads(auth_path.read_text(encoding="utf-8"))
    lic_data = json.loads(lic_path.read_text(encoding="utf-8"))
    man_data = json.loads(man_path.read_text(encoding="utf-8"))

    # R1 checks
    expires_dt = _parse_utc(auth_data.get("expires_at_utc"))
    sig_ok, sig_msg = _verify_r1_signature(auth_data, public_key_pem)
    r1_ok = sig_ok and (expires_dt is None or now <= expires_dt)
    if expires_dt is not None and now > expires_dt:
        r1_ok = False
        reasons.append("R1 authorization has expired")
    if not sig_ok:
        reasons.append(sig_msg)
    checks["r1_present_and_valid"] = r1_ok

    # R2 checks + Obligation 1-3 integration
    lic_status = lic_data.get("result", {}).get("status")
    stage_approved = lic_data.get("result", {}).get("approved_for_stage_05b") is True
    lic_ref_str = lic_data.get("license_reference") or "SPDX:Apache-2.0"
    res_obj = resolve_license_reference(lic_ref_str, repo_root=root)
    sbom_rel = lic_data.get("evidence", {}).get("sbom_path") or "reports/sbom-requirements.txt"
    sbom_expected = lic_data.get("evidence", {}).get("sbom_sha256")
    sbom_file = root / sbom_rel
    dig_obj = verify_sha256_digest(sbom_file if sbom_file.exists() else None, sbom_expected)
    dec_obj = evaluate_license_decision(res_obj, dig_obj, authority="rea-gate")

    r2_ok = (lic_status == "PASS") and stage_approved and (dec_obj.decision == "ALLOW")
    if not r2_ok:
        reasons.append(
            f"R2 license gate failed: status={lic_status}, "
            f"approved_for_stage_05b={stage_approved}, decision={dec_obj.decision}"
        )
    checks["r2_license_approved"] = r2_ok

    # R3 checks
    auth_sha = _sha256_file(auth_path)
    lic_sha = _sha256_file(lic_path)
    man_auth_sha = man_data.get("authorization_reference", {}).get("sha256")
    man_lic_sha = man_data.get("license_reference", {}).get("sha256")
    inputs_list = man_data.get("inputs") or []
    all_inputs_ok = len(inputs_list) > 0

    for item in inputs_list:
        rel = item.get("source_path_or_uri")
        expected_sha = item.get("sha256")
        if not rel or not expected_sha:
            all_inputs_ok = False
            reasons.append("R3 input missing source_path_or_uri or sha256")
            continue
        target_file = (root / rel).resolve()
        if not target_file.exists() or not target_file.is_file():
            all_inputs_ok = False
            reasons.append(f"R3 input file missing on disk: {rel}")
            continue
        actual_sha = _sha256_file(target_file)
        if actual_sha != expected_sha.lower():
            all_inputs_ok = False
            reasons.append(f"R3 SHA-256 mismatch for {rel}")

    ref_match_ok = (man_auth_sha == auth_sha) and (man_lic_sha == lic_sha)
    if not ref_match_ok:
        reasons.append("R3 cross-reference SHA-256 mismatch with R1 or R2")

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
