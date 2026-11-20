"""Obligation 2: SHA-256 digest verification."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

DigestStatus = Literal["VERIFIED", "MISMATCH", "UNVERIFIED"]
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_sha256_hex(value: Any) -> str | None:
    if isinstance(value, str) and _HEX64_RE.fullmatch(value):
        return value
    return None


@dataclass(frozen=True)
class DigestVerificationResult:
    status: DigestStatus
    actual_sha256: str | None
    expected_sha256: str | None
    reason: str


def compute_sha256_hex(content: bytes | str | Path) -> str:
    if isinstance(content, Path):
        content = content.read_bytes()
    data = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def verify_sha256_digest(
    content: bytes | str | Path | None,
    expected_sha256: str | None,
) -> DigestVerificationResult:
    """Verify content SHA-256 digest against expected lowercase 64-hex digest."""
    normalized_expected = parse_sha256_hex(expected_sha256)

    if isinstance(content, Path):
        try:
            content = content.read_bytes()
        except OSError:
            return DigestVerificationResult(
                status="UNVERIFIED",
                actual_sha256=None,
                expected_sha256=normalized_expected,
                reason="Unable to read content from path",
            )

    if normalized_expected is not None and not _HEX64_RE.match(normalized_expected):
        return DigestVerificationResult(
            status="UNVERIFIED",
            actual_sha256=None,
            expected_sha256=None,
            reason="Invalid expected SHA-256 format",
        )

    if content is None:
        return DigestVerificationResult(
            status="UNVERIFIED",
            actual_sha256=None,
            expected_sha256=normalized_expected,
            reason="No content available to compute SHA-256",
        )

    actual = compute_sha256_hex(content)
    if normalized_expected is None:
        return DigestVerificationResult(
            status="UNVERIFIED",
            actual_sha256=actual,
            expected_sha256=None,
            reason="No expected SHA-256 digest provided",
        )

    if actual == normalized_expected:
        return DigestVerificationResult(
            status="VERIFIED",
            actual_sha256=actual,
            expected_sha256=normalized_expected,
            reason="SHA-256 digest matched",
        )

    return DigestVerificationResult(
        status="MISMATCH",
        actual_sha256=actual,
        expected_sha256=normalized_expected,
        reason="SHA-256 digest mismatch",
    )
