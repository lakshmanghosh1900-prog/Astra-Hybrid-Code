"""Unit tests for RBAC, REA gate, execution receipt, and audit log."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from astra_coder.rea import (
    append_audit_event,
    build_execution_receipt,
    enforce_rea_gate,
    evaluate_rbac,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_rbac_enforces_roles_and_blocks_self_certification() -> None:
    res_ok = evaluate_rbac(actor_id="ops-1", role="HUMAN_APPROVER", action="APPROVE_STAGE_05B")
    assert res_ok.allowed is True

    res_agent = evaluate_rbac(actor_id="agent-1", role="AGENT", action="APPROVE_STAGE_05B")
    assert res_agent.allowed is False

    res_self = evaluate_rbac(
        actor_id="exec-1",
        role="EXECUTOR",
        action="RUN_REA_EXECUTION",
        self_certified=True,
    )
    assert res_self.allowed is False


def test_rea_gate_blocks_without_valid_signature_and_allows_with_valid_signature(
    tmp_path: Path,
) -> None:
    crypto = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert crypto is not None

    gate_files = ["authorization.json", "license-check.json", "rea-input-manifest.json"]
    for fname in gate_files:
        src_file = REPO_ROOT / fname
        (tmp_path / fname).write_text(src_file.read_text(encoding="utf-8"), encoding="utf-8")

    for rel in [
        "src/astra_coder/license/__init__.py",
        "src/astra_coder/license/resolve_reference.py",
        "src/astra_coder/license/verify_digest.py",
        "src/astra_coder/license/decision.py",
        "reports/sbom-requirements.txt",
    ]:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((REPO_ROOT / rel).read_bytes())

    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    auth_path = tmp_path / "authorization.json"
    auth_obj = json.loads(auth_path.read_text(encoding="utf-8"))
    payload_bytes = json.dumps(
        {k: v for k, v in auth_obj.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sig_b64 = base64.b64encode(priv.sign(payload_bytes)).decode("ascii")
    auth_obj["signature"] = {
        "algorithm": "Ed25519",
        "key_id": "test-key-01",
        "signature_base64": sig_b64,
    }
    auth_path.write_text(json.dumps(auth_obj, indent=2) + "\n", encoding="utf-8")

    man_path = tmp_path / "rea-input-manifest.json"
    man_obj = json.loads(man_path.read_text(encoding="utf-8"))
    for item in man_obj.get("inputs") or []:
        rel = item.get("source_path_or_uri")
        if rel and (tmp_path / rel).exists():
            item["sha256"] = hashlib.sha256((tmp_path / rel).read_bytes()).hexdigest()

    man_obj["authorization_reference"]["sha256"] = hashlib.sha256(
        auth_path.read_bytes()
    ).hexdigest()
    man_obj["license_reference"]["sha256"] = hashlib.sha256(
        (tmp_path / "license-check.json").read_bytes()
    ).hexdigest()
    man_path.write_text(json.dumps(man_obj, indent=2) + "\n", encoding="utf-8")

    blocked = enforce_rea_gate(
        repo_root=tmp_path, actor_id="agent-1", role="AGENT", public_key_pem=pub_pem
    )
    assert blocked.allowed is False

    allowed = enforce_rea_gate(
        repo_root=tmp_path,
        actor_id="ops-1",
        role="HUMAN_APPROVER",
        public_key_pem=pub_pem,
    )
    assert allowed.allowed is True
    assert allowed.blocking_reasons == []


def test_receipt_and_audit_log_conform_to_schemas(tmp_path: Path) -> None:
    jsonschema_mod = pytest.importorskip("jsonschema")
    validator_cls = jsonschema_mod.Draft202012Validator

    rcpt_schema_path = REPO_ROOT / "docs/schemas/execution-receipt.schema.json"
    log_schema_path = REPO_ROOT / "docs/schemas/authorization-log.schema.json"
    receipt_schema = json.loads(rcpt_schema_path.read_text(encoding="utf-8"))
    log_schema = json.loads(log_schema_path.read_text(encoding="utf-8"))

    sample_hash = "90bdb412b86bcc6790b5c9e4107634c96be133f65a0070ce52e483f603d4f614"
    receipt = build_execution_receipt(
        receipt_id="rcpt-001",
        receipt_kind="EXECUTION",
        license_reference="SPDX:Apache-2.0",
        resolution_status="RESOLVED",
        resolved_target="spdx://Apache-2.0",
        digest_status="VERIFIED",
        actual_sha256=sample_hash,
        expected_sha256=sample_hash,
        decision="ALLOW",
        authority="human-approver-1",
        anchor_ref="anchor://stage05b/001",
        signed=True,
        key_id="key-ed25519-01",
        recorded_at_utc="2026-11-19T15:00:00Z",
    )
    validator_cls(receipt_schema).validate(receipt)

    log_file = tmp_path / "auth-log.json"
    ev1 = append_audit_event(
        log_file,
        event_id="evt-001",
        event_type="STAGE_05B_GATE_EVALUATED",
        actor_type="SYSTEM_VERIFIER",
        actor_identity="rea-gate",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference="rcpt-001",
        timestamp_utc="2026-11-19T15:00:01Z",
    )
    ev2 = append_audit_event(
        log_file,
        event_id="evt-002",
        event_type="STAGE_05B_RECEIPT_RECORDED",
        actor_type="HUMAN_OPERATOR",
        actor_identity="lakshmanghosh1900-prog",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference="anchor://stage05b/001",
        timestamp_utc="2026-11-19T15:00:02Z",
    )
    assert ev2["previous_event_hash"] == ev1["event_sha256"]

    log_doc = json.loads(log_file.read_text(encoding="utf-8"))
    validator_cls(log_schema).validate(log_doc)
