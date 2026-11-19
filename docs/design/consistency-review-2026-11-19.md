# Schema-to-Projection Consistency Review (2026-11-19)

- **Target Policy:** docs/design/source-policy.md (129 lines, 5585 bytes, VERIFIED)
- **Codebase Root:** C:\Users\User\Desktop\ASTRA CODER\src\astra_coder
- **Existing Schemas:**
  - docs/schemas/authorization-log.schema.json
  - docs/schemas/authorization.schema.json
  - docs/schemas/license-check.schema.json
  - docs/schemas/rea-input-manifest.schema.json
  - docs/schemas/execution-receipt.schema.json (NEW)
- **Governance Constraints:** No PR #11 merge, no git push, no deployment without explicit separate instruction.

## 1. R1 Constraints ↔ source-policy.md Matrix

- **Source Constraint Location:** docs/design/source-policy.md §1 (source-type policy matrix); docs/schemas/rea-input-manifest.schema.json (source_type, data_classification, permitted_purpose inputs).
- **Alignment Check:** Six source types in policy (REPO_FILE, EXTERNAL_URL, SBOM, SCAN_RESULT, CONTAINER_IMAGE, BUILD_ARTIFACT) are accepted as source_type strings. EXTERNAL_URL excludes RESTRICTED per decision #2; all other five retain RESTRICTED. Purpose allowlists match policy table.
- **Status:** ALIGNED (design + schema). Runtime enforcement remains in REA adapter (not implemented here).

## 2. R2 Constraints ↔ Provenance Fields

- **Source Constraint Location:** docs/design/source-policy.md §2; docs/schemas/rea-input-manifest.schema.json inputs (version_or_commit, provenance, sha256).
- **Alignment Check:** Provenance fields (source_identity, acquisition_origin, publisher_or_repository, version_or_commit, acquired_at_utc, provenance_evidence_reference, provenance_evidence_sha256) map to manifest input fields sha256/version_or_commit/provenance. Nullability conditions preserved for nullable fields.
- **Status:** ALIGNED (projection). Full field-level runtime binding deferred to REA adapter.

## 3. R3 Constraints ↔ license_reference Obligations

- **Source Constraint Location:** docs/design/source-policy.md §3; src/astra_coder/license/*; docs/schemas/execution-receipt.schema.json obligations.
- **Alignment Check:**
  - Obligation 1 (Reference Resolution): src/astra_coder/license/resolve_reference.py implements SPDX and repository-relative resolution with fail-closed path traversal checks. Receipt projection: obligations.reference_resolution {status, resolved_target}.
  - Obligation 2 (SHA-256 Digest Verification): src/astra_coder/license/verify_digest.py computes and compares lowercase 64-hex digests. Receipt projection: obligations.sha256_digest_verification {status, actual_sha256, expected_sha256}.
  - Obligation 3 (License Decision): src/astra_coder/license/decision.py emits a separate LicenseDecisionRecord (decision, authority, decided_at_utc, reason) without mutating license_reference. Receipt projection: obligations.license_decision {decision, authority, decided_at_utc}.
- **Status:** RUNTIME IMPLEMENTED + SCHEMA ALIGNED.

## 4. Receipt Projection ↔ Ratified Decisions (8/8)

- **Target Schema:** docs/schemas/execution-receipt.schema.json (created).
- **Alignment Check:**
  1. Allowlists conditional: represented via license-check policy fields.
  2. EXTERNAL_URL no RESTRICTED: enforced in source-policy matrix.
  3. Allowlist authority: Human Governance Approver (not agent).
  4. Audit-only unsigned allowed: receipt_kind=AUDIT_ONLY permits signed=false; EXECUTION requires signed=true.
  5. Executor key: key_rotation_days_max=90, revoked boolean, key_id nullable.
  6. Anchor storage: append_only=true, dual_authority_recovery=true.
  7. Timestamp/clock: ntp_drift_seconds [-2,2], monotonic_sequence >=1, recorded_at_utc date-time.
  8. Verified-byte handle: retention_days=180, immutable=true.
- **Status:** SCHEMA CREATED + ALIGNED.

## 5. Validation Evidence

- **Receipt schema (Test-Json, PowerShell 7.7.0):**
  - audit-only unsigned => True (decision #4)
  - execution signed => True
  - execution unsigned => False (execution receipts must be signed)
  - ntp_drift_seconds 3.0 => False (decision #7, drift <= 2s)
  - retention_days 30 => False (decision #8, retention 180)
  - empty license_reference => False (minLength 1)
  - missing license_reference => False (required)
- **Python tests:** 398 passed, 2 skipped (full suite); tests/unit/license 4 passed.
- **Lint/type:** ruff clean (src/astra_coder/license, tests/unit/license); mypy strict clean (4 source files).
- **Schema JSON:** all docs/schemas/*.json parse as valid JSON.

## 6. Open Blockers & Notes

- R1/R2 runtime enforcement in REA adapter remains outside this scope.
- No PR #11 merge, push, or deployment performed.
- Tests: tests/unit/license/test_obligations.py (4 passed).

(End of file)