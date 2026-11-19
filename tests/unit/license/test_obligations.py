"""Unit tests for license_reference runtime obligations and receipt schema presence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from astra_coder.license import (
    evaluate_license_decision,
    resolve_license_reference,
    verify_sha256_digest,
)


def test_resolve_spdx_and_repo_file(tmp_path: Path) -> None:
    spdx_res = resolve_license_reference("SPDX:Apache-2.0", repo_root=tmp_path)
    assert spdx_res.status == "RESOLVED"
    assert spdx_res.resolved_target == "spdx://Apache-2.0"

    license_file = tmp_path / "LICENSE.txt"
    license_file.write_text("MIT License Text", encoding="utf-8")
    file_res = resolve_license_reference("LICENSE.txt", repo_root=tmp_path)
    assert file_res.status == "RESOLVED"
    assert file_res.resolved_target == str(license_file.resolve())


def test_resolve_rejects_empty_and_path_traversal(tmp_path: Path) -> None:
    empty_res = resolve_license_reference("   ", repo_root=tmp_path)
    assert empty_res.status == "FAILED"
    assert empty_res.resolved_target is None

    escape_res = resolve_license_reference("../outside.txt", repo_root=tmp_path)
    assert escape_res.status == "FAILED"
    assert escape_res.resolved_target is None


def test_digest_verification_and_decision_flow(tmp_path: Path) -> None:
    payload = "Apache-2.0 sample content"
    expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    res = resolve_license_reference("SPDX:Apache-2.0", repo_root=tmp_path)
    digest_ok = verify_sha256_digest(payload, expected_hash)
    assert digest_ok.status == "VERIFIED"
    assert digest_ok.actual_sha256 == expected_hash

    decision_allow = evaluate_license_decision(
        res,
        digest_ok,
        authority="governance-test",
        decided_at_utc="2026-11-19T12:00:00Z",
    )
    assert decision_allow.decision == "ALLOW"
    assert decision_allow.license_reference == "SPDX:Apache-2.0"
    assert decision_allow.authority == "governance-test"

    digest_bad = verify_sha256_digest("tampered content", expected_hash)
    assert digest_bad.status == "MISMATCH"
    decision_deny = evaluate_license_decision(res, digest_bad)
    assert decision_deny.decision == "DENY"


def test_execution_receipt_schema_valid_json() -> None:
    schema_path = (
        Path(__file__).resolve().parents[3]
        / "docs"
        / "schemas"
        / "execution-receipt.schema.json"
    )
    assert schema_path.exists()
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    assert data["title"] == "Astra Coder Execution & Audit Receipt"
    assert "license_reference" in data["properties"]
    assert "obligations" in data["properties"]
