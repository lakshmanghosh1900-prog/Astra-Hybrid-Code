"""Unit tests for RBAC, REA gate, execution receipt, and audit log."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from astra_coder.license import verify_sha256_digest
from astra_coder.rea import (
    append_audit_event,
    build_execution_receipt,
    enforce_rea_gate,
    evaluate_rbac,
    verify_event_chain,
)
from astra_coder.rea.gate import _resolve_expiry

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXED_NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=UTC)


def _write_trusted_key(pub_pem: bytes) -> None:
    key_path = Path(os.environ["ASTRA_REA_TRUSTED_KEYS_PATH"])
    key_path.write_text(
        json.dumps(
            {
                "keys": {
                    "test-key-01": {
                        "public_key_pem": pub_pem.decode("ascii"),
                        "status": "ACTIVE",
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def test_rbac_enforces_roles_and_blocks_self_certification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_trusted_approver(tmp_path, monkeypatch, approver_id="ops-1")
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_trusted_approver(tmp_path, monkeypatch, approver_id="ops-1")
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
    _write_trusted_key(pub_pem)

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


def _write_trusted_approver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    approver_id: str = "ops-1",
    allowed_actions: list[str] | None = None,
    status: str = "ACTIVE",
    role: str = "HUMAN_APPROVER",
) -> Path:
    actions = (
        ["APPROVE_STAGE_05B", "RUN_REA_EXECUTION"] if allowed_actions is None else allowed_actions
    )
    reg_path = tmp_path / "trusted-approvers.json"
    reg_path.write_text(
        json.dumps(
            {
                "approvers": {
                    approver_id: {
                        "role": role,
                        "status": status,
                        "allowed_actions": actions,
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTRA_REA_APPROVER_REGISTRY_PATH", str(reg_path))
    return reg_path


def _build_gate_fixture(
    tmp_path: Path,
    *,
    auth_mutator: Callable[[dict[str, Any]], None] | None = None,
    lic_mutator: Callable[[dict[str, Any]], None] | None = None,
    sign: bool = True,
    repo_name: str = "repo",
) -> tuple[Path, bytes | None]:
    root = tmp_path / repo_name
    root.mkdir()
    for fname in ["authorization.json", "license-check.json", "rea-input-manifest.json"]:
        (root / fname).write_text((REPO_ROOT / fname).read_text(encoding="utf-8"), encoding="utf-8")
    for rel in [
        "src/astra_coder/license/__init__.py",
        "src/astra_coder/license/resolve_reference.py",
        "src/astra_coder/license/verify_digest.py",
        "src/astra_coder/license/decision.py",
        "reports/sbom-requirements.txt",
    ]:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((REPO_ROOT / rel).read_bytes())

    pub_pem: bytes | None = None
    auth_path = root / "authorization.json"
    auth_obj = json.loads(auth_path.read_text(encoding="utf-8"))
    if auth_mutator is not None:
        auth_mutator(auth_obj)
    if sign:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pytest.importorskip("cryptography")
        priv = Ed25519PrivateKey.generate()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _write_trusted_key(pub_pem)
        payload = {k: v for k, v in auth_obj.items() if k != "signature"}
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig_b64 = base64.b64encode(priv.sign(payload_bytes)).decode("ascii")
        auth_obj["signature"] = {
            "algorithm": "Ed25519",
            "key_id": "test-key-01",
            "signature_base64": sig_b64,
        }
    auth_path.write_text(json.dumps(auth_obj, indent=2) + "\n", encoding="utf-8")

    lic_path = root / "license-check.json"
    if lic_mutator is not None:
        lic_obj = json.loads(lic_path.read_text(encoding="utf-8"))
        lic_mutator(lic_obj)
        lic_path.write_text(json.dumps(lic_obj, indent=2) + "\n", encoding="utf-8")

    man_path = root / "rea-input-manifest.json"
    man_obj = json.loads(man_path.read_text(encoding="utf-8"))
    for item in man_obj.get("inputs") or []:
        rel = item.get("source_path_or_uri")
        if isinstance(rel, str) and (root / rel).exists() and (root / rel).is_file():
            item["sha256"] = hashlib.sha256((root / rel).read_bytes()).hexdigest()
    man_obj["authorization_reference"]["sha256"] = hashlib.sha256(
        auth_path.read_bytes()
    ).hexdigest()
    man_obj["license_reference"]["sha256"] = hashlib.sha256(lic_path.read_bytes()).hexdigest()
    man_path.write_text(json.dumps(man_obj, indent=2) + "\n", encoding="utf-8")
    return root, pub_pem


def _edit_manifest(root: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    man_path = root / "rea-input-manifest.json"
    doc = json.loads(man_path.read_text(encoding="utf-8"))
    mutate(doc)
    man_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def _run_gate(root: Path, pub: bytes | None, **kwargs: Any) -> Any:
    params: dict[str, Any] = {
        "repo_root": root,
        "actor_id": "ops-1",
        "role": "HUMAN_APPROVER",
        "public_key_pem": pub,
        "now_utc": FIXED_NOW,
    }
    params.update(kwargs)
    return enforce_rea_gate(**params)


def test_t_r1_a_missing_expiry_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        auth_mutator=lambda a: a["authorization"].pop("expires_at_utc", None),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("missing required expiry" in r for r in res.blocking_reasons)
    assert not any("signature verification failed" in r for r in res.blocking_reasons)


@pytest.mark.parametrize(
    "bad_expiry",
    [
        "not-a-date",
        "2026-13-99T99:99:99Z",
        "",
        123,
        None,
        "2026-12-19T13:06:00",
        "2026-12-19",
    ],
)
def test_t_r1_b_malformed_expiry_denies_gate(tmp_path: Path, bad_expiry: Any) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        auth_mutator=lambda a, v=bad_expiry: a["authorization"].update(expires_at_utc=v),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("expiry" in r.lower() for r in res.blocking_reasons)
    assert not any("signature verification failed" in r for r in res.blocking_reasons)


def test_t_r1_c_expired_authorization_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        auth_mutator=lambda a: a["authorization"].update(expires_at_utc="2020-01-01T00:00:00Z"),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("R1 authorization has expired" in r for r in res.blocking_reasons)
    assert not any("signature verification failed" in r for r in res.blocking_reasons)


def test_t_r1_d_nested_shipped_expiry_resolves(tmp_path: Path) -> None:
    shipped = json.loads((REPO_ROOT / "authorization.json").read_text(encoding="utf-8"))
    expiry, err = _resolve_expiry(shipped)
    assert err is None
    assert expiry == datetime(2026, 12, 19, 13, 6, 0, tzinfo=UTC)

    root, pub = _build_gate_fixture(tmp_path, sign=False)
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("signature" in r.lower() for r in res.blocking_reasons)
    assert not any("expiry" in r.lower() for r in res.blocking_reasons)


def test_t_r1_e_conflicting_expiry_locations_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        auth_mutator=lambda a: a.update(expires_at_utc="2030-01-01T00:00:00Z"),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("conflicting expires_at_utc" in r for r in res.blocking_reasons)


def test_t_r1_f_expiry_boundary_is_inclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_trusted_approver(tmp_path, monkeypatch, approver_id="ops-1")
    root, pub = _build_gate_fixture(tmp_path)
    at_expiry = _run_gate(root, pub, now_utc=datetime(2026, 12, 19, 13, 6, 0, tzinfo=UTC))
    assert at_expiry.allowed is True
    assert at_expiry.blocking_reasons == []
    past_expiry = _run_gate(root, pub, now_utc=datetime(2026, 12, 19, 13, 6, 1, tzinfo=UTC))
    assert past_expiry.allowed is False
    assert any("R1 authorization has expired" in r for r in past_expiry.blocking_reasons)


def test_t_r3_a_parent_traversal_denied_with_correct_hash(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    outside = tmp_path / "outside-secret.txt"
    outside.write_bytes(b"top secret outside repository")

    def _retarget(m: dict[str, Any]) -> None:
        item = m["inputs"][0]
        item["source_path_or_uri"] = "../outside-secret.txt"
        item["sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()

    _edit_manifest(root, _retarget)
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("escapes repository root" in r for r in res.blocking_reasons)
    assert not any("SHA-256 mismatch" in r for r in res.blocking_reasons)


def test_t_r3_b_absolute_external_path_denied_with_correct_hash(
    tmp_path: Path,
) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    outside = tmp_path / "absolute-external.txt"
    outside.write_bytes(b"absolute path outside repository")

    def _retarget(m: dict[str, Any]) -> None:
        item = m["inputs"][0]
        item["source_path_or_uri"] = str(outside.resolve())
        item["sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()

    _edit_manifest(root, _retarget)
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("escapes repository root" in r for r in res.blocking_reasons)
    assert not any("SHA-256 mismatch" in r for r in res.blocking_reasons)


def test_t_r3_c_symlink_escape_denied_with_correct_hash(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    payload = outside_dir / "payload.txt"
    payload.write_bytes(b"symlink target outside repository")
    link = root / "escape-link"

    created = False
    skip_reason = ""
    try:
        link.symlink_to(outside_dir, target_is_directory=True)
        created = True
    except (OSError, NotImplementedError) as exc:
        skip_reason = f"symlink: {exc}"
    if not created:
        try:
            import _winapi

            _winapi.CreateJunction(str(outside_dir), str(link))
            created = True
        except (ImportError, OSError) as exc:
            skip_reason += f"; junction: {exc}"
    if not created:
        pytest.skip(f"link creation unavailable on this platform: {skip_reason}")

    def _retarget(m: dict[str, Any]) -> None:
        item = m["inputs"][0]
        item["source_path_or_uri"] = "escape-link/payload.txt"
        item["sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()

    _edit_manifest(root, _retarget)
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("escapes repository root" in r for r in res.blocking_reasons)
    assert not any("SHA-256 mismatch" in r for r in res.blocking_reasons)


def test_t_log_a_tampered_history_rejected_and_file_unchanged(tmp_path: Path) -> None:
    log_file = tmp_path / "auth-log.json"
    append_audit_event(
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
    append_audit_event(
        log_file,
        event_id="evt-002",
        event_type="STAGE_05B_RECEIPT_RECORDED",
        actor_type="HUMAN_OPERATOR",
        actor_identity="operator-1",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference="anchor://stage05b/001",
        timestamp_utc="2026-11-19T15:00:02Z",
    )
    doc = json.loads(log_file.read_text(encoding="utf-8"))
    doc["events"][0]["decision"] = "REJECTED"
    log_file.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    tampered_bytes = log_file.read_bytes()

    with pytest.raises(ValueError, match="chain verification failed at event index 0"):
        append_audit_event(
            log_file,
            event_id="evt-003",
            event_type="STAGE_05B_GATE_EVALUATED",
            actor_type="SYSTEM_VERIFIER",
            actor_identity="rea-gate",
            authorization_id="auth-05b",
            decision="APPROVED",
            evidence_reference="rcpt-003",
            timestamp_utc="2026-11-19T15:00:03Z",
        )
    assert log_file.read_bytes() == tampered_bytes


def test_t_log_b_prior_events_preserved_on_append(tmp_path: Path) -> None:
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
        actor_identity="operator-1",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference="anchor://stage05b/001",
        timestamp_utc="2026-11-19T15:00:02Z",
    )
    before = json.loads(log_file.read_text(encoding="utf-8"))
    prior_events = before["events"]

    ev3 = append_audit_event(
        log_file,
        event_id="evt-003",
        event_type="STAGE_05B_GATE_EVALUATED",
        actor_type="SYSTEM_VERIFIER",
        actor_identity="rea-gate",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference="rcpt-003",
        timestamp_utc="2026-11-19T15:00:03Z",
    )

    after = json.loads(log_file.read_text(encoding="utf-8"))
    assert after["events"][:2] == prior_events
    assert ev1["event_sha256"] == prior_events[0]["event_sha256"]
    assert ev2["event_sha256"] == prior_events[1]["event_sha256"]
    assert ev3["previous_event_hash"] == ev2["event_sha256"]
    assert after["events"][2]["event_id"] == "evt-003"
    assert after["integrity"]["verified"] is True
    verify_event_chain(after["events"])


def test_t_r2_a_missing_license_status_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path, lic_mutator=lambda lic: lic["result"].pop("status", None)
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("R2 license gate failed" in r and "status=None" in r for r in res.blocking_reasons)


def test_t_r2_b_missing_stage_approval_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        lic_mutator=lambda lic: lic["result"].pop("approved_for_stage_05b", None),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any(
        "R2 license gate failed" in r and "approved_for_stage_05b=False" in r
        for r in res.blocking_reasons
    )


def test_t_r2_c_deny_decision_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        lic_mutator=lambda lic: lic["evidence"].update(sbom_sha256="0" * 64),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("decision=DENY" in r for r in res.blocking_reasons)


def test_t_r2_d_escalate_decision_denies_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path, lic_mutator=lambda lic: lic["evidence"].pop("sbom_sha256", None)
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("decision=ESCALATE" in r for r in res.blocking_reasons)


def test_t_rbac_a_same_actor_approver_denied_via_gate(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    res = _run_gate(root, pub, actor_id="exec-1", role="EXECUTOR", approver_id="exec-1")
    assert res.allowed is False
    assert any(
        "Self-authorization by executor/agent/operator is prohibited" in r
        for r in res.blocking_reasons
    )
    res2 = _run_gate(
        root,
        pub,
        actor_id="agent-1",
        role="AGENT",
        action="APPROVE_STAGE_05B",
        approver_id="agent-1",
    )
    assert res2.allowed is False
    assert any("Only HUMAN_APPROVER may approve Stage 05b" in r for r in res2.blocking_reasons)


def test_t_rbac_b_gate_level_self_certification_denied(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    res = _run_gate(
        root,
        pub,
        actor_id="exec-1",
        role="EXECUTOR",
        approver_id="approver-1",
        self_certified=True,
    )
    assert res.allowed is False
    assert any("cannot self-certify" in r for r in res.blocking_reasons)

    res2 = _run_gate(root, pub, actor_id="exec-1", role="EXECUTOR")
    assert res2.allowed is False
    assert any("Independent trusted approver required" in r for r in res2.blocking_reasons)

    res3 = _run_gate(
        root,
        pub,
        actor_id="exec-1",
        role="EXECUTOR",
        approver_id="approver-1",
        self_certified=False,
    )
    assert res3.allowed is True
    assert res3.blocking_reasons == []


@pytest.mark.parametrize(
    ("fname", "content"),
    [
        ("authorization.json", "{not valid json"),
        ("authorization.json", "[1, 2, 3]"),
        ("license-check.json", "null"),
        ("rea-input-manifest.json", '"just a string"'),
    ],
)
def test_malformed_gate_artifact_json_fails_closed(
    tmp_path: Path, fname: str, content: str
) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    (root / fname).write_text(content, encoding="utf-8")
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert len(res.blocking_reasons) > 0


def test_malformed_license_result_fails_closed(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path, lic_mutator=lambda lic: lic.update(result=None))
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("result block missing or not an object" in r for r in res.blocking_reasons)


@pytest.mark.parametrize("bad_inputs", ["not-a-list", [42]])
def test_malformed_manifest_inputs_fail_closed(tmp_path: Path, bad_inputs: Any) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    _edit_manifest(root, lambda m: m.update(inputs=bad_inputs))
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("R3 manifest input" in r for r in res.blocking_reasons)


@pytest.mark.parametrize("bad_path", [123, None, ["nested/path.py"]])
def test_malformed_manifest_path_type_fails_closed(tmp_path: Path, bad_path: Any) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    _edit_manifest(root, lambda m: m["inputs"][0].update(source_path_or_uri=bad_path))
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any(
        "source_path_or_uri or sha256" in r or "non-empty string" in r for r in res.blocking_reasons
    )


@pytest.mark.parametrize("bad_hash", [123, None, "A" * 64, "g" * 64, "abc123"])
def test_malformed_manifest_hash_type_fails_closed(tmp_path: Path, bad_hash: Any) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    _edit_manifest(root, lambda m: m["inputs"][0].update(sha256=bad_hash))
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any(
        "missing source_path_or_uri or sha256" in r or "strict lowercase 64-hex" in r
        for r in res.blocking_reasons
    )


def test_r3_uppercase_hash_rejected_without_normalization(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)

    def _upper(m: dict[str, Any]) -> None:
        item = m["inputs"][0]
        item["sha256"] = str(item["sha256"]).upper()

    _edit_manifest(root, _upper)
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("strict lowercase 64-hex" in r for r in res.blocking_reasons)


@pytest.mark.parametrize("evidence_value", [None, [1, 2], "not-an-object"])
def test_malformed_license_evidence_fails_closed(tmp_path: Path, evidence_value: Any) -> None:
    root, pub = _build_gate_fixture(
        tmp_path, lic_mutator=lambda lic: lic.update(evidence=evidence_value)
    )
    res = _run_gate(root, pub)
    assert res.allowed is False


@pytest.mark.parametrize(
    "tamper",
    [
        "invalid_json",
        "root_array",
        "missing_events",
        "events_not_list",
        "entry_not_object",
        "duplicate_id",
        "broken_link",
        "bad_hex",
        "first_prev_not_null",
        "stored_hash_mismatch",
    ],
)
def test_malformed_or_tampered_audit_log_rejected(tmp_path: Path, tamper: str) -> None:
    log_file = tmp_path / "auth-log.json"
    append_audit_event(
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
    append_audit_event(
        log_file,
        event_id="evt-002",
        event_type="STAGE_05B_RECEIPT_RECORDED",
        actor_type="HUMAN_OPERATOR",
        actor_identity="operator-1",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference="anchor://stage05b/001",
        timestamp_utc="2026-11-19T15:00:02Z",
    )

    if tamper == "invalid_json":
        log_file.write_text("{broken json", encoding="utf-8")
    elif tamper == "root_array":
        log_file.write_text("[1, 2, 3]", encoding="utf-8")
    else:
        doc = json.loads(log_file.read_text(encoding="utf-8"))
        if tamper == "missing_events":
            doc.pop("events", None)
        elif tamper == "events_not_list":
            doc["events"] = "not-a-list"
        elif tamper == "entry_not_object":
            doc["events"][0] = "oops"
        elif tamper == "duplicate_id":
            doc["events"][1]["event_id"] = doc["events"][0]["event_id"]
        elif tamper == "broken_link":
            doc["events"][1]["previous_event_hash"] = "0" * 64
        elif tamper == "bad_hex":
            doc["events"][0]["event_sha256"] = "ZZ" * 32
        elif tamper == "first_prev_not_null":
            doc["events"][0]["previous_event_hash"] = "0" * 64
        elif tamper == "stored_hash_mismatch":
            doc["events"][0]["decision"] = "REJECTED"
        log_file.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    before = log_file.read_bytes()
    with pytest.raises(ValueError):
        append_audit_event(
            log_file,
            event_id="evt-003",
            event_type="STAGE_05B_GATE_EVALUATED",
            actor_type="SYSTEM_VERIFIER",
            actor_identity="rea-gate",
            authorization_id="auth-05b",
            decision="APPROVED",
            evidence_reference="rcpt-003",
            timestamp_utc="2026-11-19T15:00:03Z",
        )
    assert log_file.read_bytes() == before


def test_attacker_supplied_key_cannot_authorize(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    root, _ = _build_gate_fixture(tmp_path)
    attacker = Ed25519PrivateKey.generate()
    attacker_pub = attacker.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    auth_path = root / "authorization.json"
    auth_obj = json.loads(auth_path.read_text(encoding="utf-8"))
    payload = {k: v for k, v in auth_obj.items() if k != "signature"}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    auth_obj["signature"]["signature_base64"] = base64.b64encode(
        attacker.sign(payload_bytes)
    ).decode("ascii")
    auth_path.write_text(json.dumps(auth_obj, indent=2) + "\n", encoding="utf-8")
    _edit_manifest(
        root,
        lambda m: m["authorization_reference"].update(
            sha256=hashlib.sha256(auth_path.read_bytes()).hexdigest()
        ),
    )

    res = _run_gate(root, attacker_pub)
    assert res.allowed is False
    assert any("signature does not match payload" in r for r in res.blocking_reasons)


def test_unknown_key_id_is_denied(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    root, _ = _build_gate_fixture(tmp_path)
    attacker = Ed25519PrivateKey.generate()
    attacker_pub = attacker.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    auth_path = root / "authorization.json"
    auth_obj = json.loads(auth_path.read_text(encoding="utf-8"))
    payload = {k: v for k, v in auth_obj.items() if k != "signature"}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    auth_obj["signature"] = {
        "algorithm": "Ed25519",
        "key_id": "attacker-key",
        "signature_base64": base64.b64encode(attacker.sign(payload_bytes)).decode("ascii"),
    }
    auth_path.write_text(json.dumps(auth_obj, indent=2) + "\n", encoding="utf-8")
    _edit_manifest(
        root,
        lambda m: m["authorization_reference"].update(
            sha256=hashlib.sha256(auth_path.read_bytes()).hexdigest()
        ),
    )

    res = _run_gate(root, attacker_pub)
    assert res.allowed is False
    assert any("Unknown R1 key_id: attacker-key" in r for r in res.blocking_reasons)


def test_signed_rejected_decision_is_denied(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(
        tmp_path,
        auth_mutator=lambda a: a["authorization"].update(approval_decision="REJECTED"),
    )
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("approval_decision must be APPROVED" in r for r in res.blocking_reasons)


def test_fabricated_approver_is_denied(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    res = _run_gate(
        root,
        pub,
        actor_id="exec-1",
        role="EXECUTOR",
        approver_id="fabricated-999",
    )
    assert res.allowed is False
    assert any("Unknown or untrusted approver_id" in r for r in res.blocking_reasons)


def test_non_string_rbac_inputs_denied_without_attribute_error() -> None:
    result = evaluate_rbac(
        actor_id=123,  # type: ignore[arg-type]
        role=[],  # type: ignore[arg-type]
        action={},  # type: ignore[arg-type]
        approver_id=42,  # type: ignore[arg-type]
        self_certified="yes",  # type: ignore[arg-type]
        approver_context=[],  # type: ignore[arg-type]
    )
    assert result.allowed is False
    assert result.reason == "Invalid RBAC input types"


def test_naive_now_denied(tmp_path: Path) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    res = _run_gate(root, pub, now_utc=datetime(2026, 11, 20, 12, 0, 0))
    assert res.allowed is False
    assert any("timezone-aware" in r for r in res.blocking_reasons)


def test_caller_supplied_now_requires_test_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, pub = _build_gate_fixture(tmp_path)
    monkeypatch.delenv("ASTRA_REA_TEST_CLOCK", raising=False)
    res = _run_gate(root, pub)
    assert res.allowed is False
    assert any("Caller-supplied now_utc is not permitted" in r for r in res.blocking_reasons)


def test_strict_digest_policy_rejects_normalization() -> None:
    content = b"digest-input"
    valid = hashlib.sha256(content).hexdigest()
    assert verify_sha256_digest(content, valid).status == "VERIFIED"
    for bad in [valid.upper(), f" {valid}", f"{valid}\n", valid[:-1], f"{valid}0", 123]:
        assert verify_sha256_digest(content, bad).status == "UNVERIFIED"


def _append_concurrent_event(log_file: Path, event_id: str) -> None:
    append_audit_event(
        log_file,
        event_id=event_id,
        event_type="STAGE_05B_GATE_EVALUATED",
        actor_type="SYSTEM_VERIFIER",
        actor_identity="rea-gate",
        authorization_id="auth-05b",
        decision="APPROVED",
        evidence_reference=event_id,
        timestamp_utc="2026-11-19T15:00:01Z",
    )


def test_concurrent_appends_preserve_every_event(tmp_path: Path) -> None:
    log_file = tmp_path / "concurrent-log.json"
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(_append_concurrent_event, log_file, f"evt-{index:03d}")
            for index in range(1, 9)
        ]
        for future in futures:
            future.result()

    doc = json.loads(log_file.read_text(encoding="utf-8"))
    assert len(doc["events"]) == 8
    assert [event["sequence"] for event in doc["events"]] == list(range(1, 9))
    verify_event_chain(doc["events"])


def test_idempotency_replay_returns_existing_event(tmp_path: Path) -> None:
    log_file = tmp_path / "idempotent-log.json"
    kwargs = {
        "event_id": "evt-001",
        "event_type": "STAGE_05B_GATE_EVALUATED",
        "actor_type": "SYSTEM_VERIFIER",
        "actor_identity": "rea-gate",
        "authorization_id": "auth-05b",
        "decision": "APPROVED",
        "evidence_reference": "rcpt-001",
        "idempotency_key": "gate-run-001",
        "operation_id": "attempt-001",
    }
    first = append_audit_event(log_file, timestamp_utc="2026-11-19T15:00:01Z", **kwargs)
    replay = append_audit_event(log_file, timestamp_utc="2026-11-19T15:00:09Z", **kwargs)
    assert replay == first

    doc = json.loads(log_file.read_text(encoding="utf-8"))
    assert len(doc["events"]) == 1

    with pytest.raises(ValueError, match="reused with a different operation"):
        append_audit_event(
            log_file,
            timestamp_utc="2026-11-19T15:00:10Z",
            **{**kwargs, "evidence_reference": "rcpt-different"},
        )


def test_explicit_sequence_must_match_next_position(tmp_path: Path) -> None:
    log_file = tmp_path / "sequence-log.json"
    with pytest.raises(ValueError, match="sequence must be 1"):
        append_audit_event(
            log_file,
            event_id="evt-001",
            event_type="STAGE_05B_GATE_EVALUATED",
            actor_type="SYSTEM_VERIFIER",
            actor_identity="rea-gate",
            authorization_id="auth-05b",
            decision="APPROVED",
            evidence_reference="rcpt-001",
            sequence=2,
        )


def test_v03_unregistered_human_approver_role_spoof_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty_reg = tmp_path / "empty-approvers.json"
    empty_reg.write_text(json.dumps({"approvers": {}}), encoding="utf-8")
    monkeypatch.setenv("ASTRA_REA_APPROVER_REGISTRY_PATH", str(empty_reg))

    res_approve = evaluate_rbac(
        actor_id="spoofed-approver",
        role="HUMAN_APPROVER",
        action="APPROVE_STAGE_05B",
    )
    assert res_approve.allowed is False

    res_exec = evaluate_rbac(
        actor_id="spoofed-approver",
        role="HUMAN_APPROVER",
        action="RUN_REA_EXECUTION",
    )
    assert res_exec.allowed is False


def test_v03_empty_allowed_actions_denies_approval_and_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_trusted_approver(
        tmp_path,
        monkeypatch,
        approver_id="restricted-approver",
        allowed_actions=[],
    )
    res_exec = evaluate_rbac(
        actor_id="exec-1",
        role="EXECUTOR",
        action="RUN_REA_EXECUTION",
        approver_id="restricted-approver",
    )
    assert res_exec.allowed is False
