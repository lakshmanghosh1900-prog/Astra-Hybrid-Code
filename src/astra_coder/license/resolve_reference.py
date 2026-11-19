"""Obligation 1: License reference resolution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ResolutionStatus = Literal["RESOLVED", "UNRESOLVED", "FAILED"]


@dataclass(frozen=True)
class ReferenceResolutionResult:
    license_reference: str
    status: ResolutionStatus
    resolved_target: str | None
    reason: str


def resolve_license_reference(
    license_reference: str,
    repo_root: Path | str | None = None,
) -> ReferenceResolutionResult:
    """Resolve SPDX or repository-relative license reference without mutating state."""
    if not isinstance(license_reference, str) or not license_reference.strip():
        return ReferenceResolutionResult(
            license_reference=license_reference if isinstance(license_reference, str) else "",
            status="FAILED",
            resolved_target=None,
            reason="Empty or non-string license_reference",
        )

    ref = license_reference.strip()

    if ref.startswith("SPDX:"):
        license_id = ref.removeprefix("SPDX:").strip()
        if not license_id:
            return ReferenceResolutionResult(
                license_reference=ref,
                status="FAILED",
                resolved_target=None,
                reason="Missing SPDX identifier after SPDX:",
            )
        return ReferenceResolutionResult(
            license_reference=ref,
            status="RESOLVED",
            resolved_target=f"spdx://{license_id}",
            reason="Resolved SPDX license identifier",
        )

    base = Path(repo_root) if repo_root is not None else Path.cwd()
    base = base.resolve()
    candidate = (base / ref).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return ReferenceResolutionResult(
            license_reference=ref,
            status="FAILED",
            resolved_target=None,
            reason="Path escapes repository root",
        )

    if candidate.exists() and candidate.is_file():
        return ReferenceResolutionResult(
            license_reference=ref,
            status="RESOLVED",
            resolved_target=str(candidate),
            reason="Resolved existing repository file",
        )

    return ReferenceResolutionResult(
        license_reference=ref,
        status="UNRESOLVED",
        resolved_target=None,
        reason="Target file not found",
    )
