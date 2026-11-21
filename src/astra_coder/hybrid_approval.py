"""External human-key binding layered alongside unchanged REA trust."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from .hybrid_skill import Contract, ExecutionPlan, PatchRequest, plan_digest
from .rea.filelock import exclusive_file_lock
from .rea.trust import (
    key_is_active,
    load_trusted_approvers_detailed,
    load_trusted_keys_detailed,
    validate_trusted_approver,
)


class ApprovalEnvelope(Contract):
    authorization_id: str = Field(min_length=1)
    approver_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    diff_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_paths: list[str] = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=16)
    signature_base64: str = Field(min_length=1)


def approval_payload(envelope: ApprovalEnvelope) -> bytes:
    return json.dumps(
        envelope.model_dump(mode="json", exclude={"signature_base64"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def verify_approval(
    envelope: ApprovalEnvelope,
    *,
    executor: str,
    plan: ExecutionPlan,
    request: PatchRequest,
    repo_root: Path,
) -> None:
    """No identifier equality inference; ownership comes only from human registry."""
    try:
        now = datetime.now(UTC)
        if (
            envelope.issued_at.tzinfo is None
            or envelope.expires_at.tzinfo is None
            or not envelope.issued_at <= now < envelope.expires_at
        ):
            raise ValueError("approval time invalid")
        if executor == envelope.approver_id:
            raise ValueError("self approval")
        if envelope.plan_id != plan.plan_id or envelope.plan_sha256 != plan_digest(plan):
            raise ValueError("plan binding")
        if envelope.diff_sha256 != request.diff_sha256:
            raise ValueError("patch binding")
        steps = [s for s in plan.steps if s.step_id == request.step_id]
        if len(steps) != 1 or envelope.target_paths != [steps[0].target_path]:
            raise ValueError("target binding")
        registry = json.loads(Path(os.environ["ASTRA_REA_APPROVER_REGISTRY_PATH"]).read_text())
        record = registry["approvers"][envelope.approver_id]
        ids = record.get("approval_signing_key_ids")
        if (
            not isinstance(ids, list)
            or not ids
            or any(not isinstance(i, str) or not i for i in ids)
            or len(ids) != len(set(ids))
            or envelope.key_id not in ids
        ):
            raise ValueError("missing or ambiguous human-key binding")
        # A key cannot be attributed to two human identities in this contract.
        for identity, other in registry["approvers"].items():
            if identity != envelope.approver_id and envelope.key_id in other.get(
                "approval_signing_key_ids", []
            ):
                raise ValueError("ambiguous key ownership")
        keys = load_trusted_keys_detailed()
        approvers = load_trusted_approvers_detailed()
        if keys.error or approvers.error:
            raise ValueError("trust registry invalid")
        key = keys.keys[envelope.key_id]
        if not key_is_active(key, now):
            raise ValueError("inactive key")
        import hashlib

        auth_bytes = (repo_root / "authorization.json").read_bytes()
        auth = json.loads(auth_bytes)
        if auth["authorization"]["authorization_id"] != envelope.authorization_id:
            raise ValueError("authorization binding")
        error = validate_trusted_approver(
            envelope.approver_id,
            "RUN_REA_EXECUTION",
            {
                "authorization_id": envelope.authorization_id,
                "artifact_sha256": hashlib.sha256(auth_bytes).hexdigest(),
                "bundle_sha256": auth.get("bundle_sha256"),
            },
            now,
        )
        if error is not None:
            raise ValueError("approver trust denied")
        raw = key.public_key
        if b"BEGIN PUBLIC KEY" in raw:
            public = serialization.load_pem_public_key(raw)
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("not Ed25519")
        else:
            public = Ed25519PublicKey.from_public_bytes(
                raw if len(raw) == 32 else base64.b64decode(raw, validate=True)
            )
        public.verify(
            base64.b64decode(envelope.signature_base64, validate=True), approval_payload(envelope)
        )
    except Exception:
        # Never echo envelope, signature, key bytes or registry contents.
        raise PermissionError("authenticated approval denied") from None


class ApprovalStore:
    """Externally located fail-closed single-use journal; host protects integrity."""

    def __init__(self, path: Path, repo_root: Path) -> None:
        if path.resolve().is_relative_to(repo_root.resolve()):
            raise ValueError("approval journal must be external")
        self.path = path

    def consume(self, envelope: ApprovalEnvelope) -> None:
        with exclusive_file_lock(self.path.with_suffix(".lock")):
            # Missing journals are denied; explicit human/host provisioning required.
            with self.path.open("r+", encoding="utf-8") as stream:
                records = json.load(stream)
                if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
                    raise ValueError("invalid approval journal")
                if any(
                    r.get("authorization_id") == envelope.authorization_id
                    or r.get("nonce") == envelope.nonce
                    for r in records
                ):
                    raise PermissionError("approval already consumed")
                records.append(
                    {"authorization_id": envelope.authorization_id, "nonce": envelope.nonce}
                )
                stream.seek(0)
                json.dump(records, stream)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
