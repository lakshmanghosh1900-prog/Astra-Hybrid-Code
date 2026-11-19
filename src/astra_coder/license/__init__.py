"""Runtime implementation of license_reference process obligations."""

from .decision import LicenseDecisionRecord, evaluate_license_decision
from .resolve_reference import ReferenceResolutionResult, resolve_license_reference
from .verify_digest import DigestVerificationResult, verify_sha256_digest

__all__ = [
    "ReferenceResolutionResult",
    "resolve_license_reference",
    "DigestVerificationResult",
    "verify_sha256_digest",
    "LicenseDecisionRecord",
    "evaluate_license_decision",
]
