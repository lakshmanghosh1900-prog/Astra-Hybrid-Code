"""Obligation 3: Separate license decision record."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from .resolve_reference import ReferenceResolutionResult
from .verify_digest import DigestVerificationResult

DecisionOutcome = Literal["ALLOW", "DENY", "ESCALATE"]


@dataclass(frozen=True)
class LicenseDecisionRecord:
    license_reference: str
    decision: DecisionOutcome
    authority: str
    decided_at_utc: str
    reason: str


def evaluate_license_decision(
    resolution: ReferenceResolutionResult,
    digest: DigestVerificationResult,
    authority: str = "astra-license-policy-engine",
    decided_at_utc: str | None = None,
) -> LicenseDecisionRecord:
    """Produce a separate license decision artifact without mutating the reference."""
    timestamp = decided_at_utc or datetime.now(UTC).isoformat()

    if resolution.status == "FAILED" or digest.status == "MISMATCH":
        return LicenseDecisionRecord(
            license_reference=resolution.license_reference,
            decision="DENY",
            authority=authority,
            decided_at_utc=timestamp,
            reason=f"Denied due to resolution={resolution.status}, digest={digest.status}",
        )

    if resolution.status == "RESOLVED" and digest.status == "VERIFIED":
        return LicenseDecisionRecord(
            license_reference=resolution.license_reference,
            decision="ALLOW",
            authority=authority,
            decided_at_utc=timestamp,
            reason="Reference resolved and SHA-256 digest verified",
        )

    return LicenseDecisionRecord(
        license_reference=resolution.license_reference,
        decision="ESCALATE",
        authority=authority,
        decided_at_utc=timestamp,
        reason=f"Escalated for review: resolution={resolution.status}, digest={digest.status}",
    )
