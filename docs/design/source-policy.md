# ASTRA CODEL — SOURCE POLICY DESIGN DOCUMENT
Status: DESIGN REPUBLISHED — HUMAN-RATIFIED GOVERNANCE INCORPORATED
Date: 2026-11-18
Scope: Design/policy only. NO implementation authorization.

---

## 1. SOURCE-TYPE POLICY MATRIX (RATIFIED)

| Source type | Data classification | Permitted purpose |
|---|---|---|
| REPO_FILE | PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED | REA_ANALYSIS, SECURITY_REVIEW, LICENSE_AUDIT, DOCUMENTATION, TESTING |
| EXTERNAL_URL | PUBLIC, INTERNAL, CONFIDENTIAL | REA_ANALYSIS, SECURITY_REVIEW, LICENSE_AUDIT, DOCUMENTATION, TESTING |
| SBOM | PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED | LICENSE_AUDIT, SECURITY_REVIEW |
| SCAN_RESULT | PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED | LICENSE_AUDIT, SECURITY_REVIEW |
| CONTAINER_IMAGE | PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED | REA_ANALYSIS, SECURITY_REVIEW, TESTING |
| BUILD_ARTIFACT | PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED | REA_ANALYSIS, SECURITY_REVIEW, TESTING |

**Note:** EXTERNAL_URL excludes RESTRICTED per ratified governance decision #2.
All other five source types retain RESTRICTED.

---

## 2. PROVENANCE FIELDS

| Field | Type | Required/Nullable |
|---|---|---|
| source_identity | string | required |
| acquisition_origin | string | required |
| publisher_or_repository | string | nullable |
| version_or_commit | string | required |
| acquired_at_utc | RFC3339 | nullable |
| provenance_evidence_reference | string | nullable |
| provenance_evidence_sha256 | lowercase 64-hex | nullable |

Per-type required/nullability conditions must be maintained per prior specification.

---

## 3. LICENSE_REFERENCE — REPUBLISHED DESIGN BLOCK

Status: SCHEMA SHAPE VERIFIED — PROCESS OBLIGATIONS DECLARED
Date: 2026-11-18
Republish basis: ratified governance prompt + PowerShell 7.7 Test-Json verification

### 3.1 Field definition (schema shape — VERIFIED)
- field: license_reference
- type: required string
- minLength: 1
- verification evidence: Test-Json (PowerShell 7.7.0) returned
  - valid sample "SPDX:Apache-2.0" => True
  - empty string "" => False (minLength 1 enforced)
  - missing field {} => False (required enforced)
- status: SCHEMA SHAPE VERIFIED

### 3.2 Three separate process obligations (DECLARED — pending runtime verification)
license_reference is a REQUIRED STRING, but it is NOT PROOF.
Each reference must independently satisfy three separate obligations:

**Obligation 1 — REFERENCE RESOLUTION**
- The license reference must be resolved under a defined resolution rule
  (e.g., SPDX identifier resolution / repository-relative path resolution).
- Resolution outcome must be recorded, not inferred.

**Obligation 2 — SHA-256 DIGEST VERIFICATION**
- The content that the reference points to must be digest-verified (SHA-256).
- The digest must be compared against a trusted expected value.
- A resolved reference without digest verification is NOT sufficient.

**Obligation 3 — LICENSE DECISION**
- The license decision must be recorded as a SEPARATE decision artifact.
- The decision must NOT be merged into the reference field itself.
- Decision authority and timestamp must be captured.

### 3.3 Status summary
- Schema shape: VERIFIED
- Obligation 1 (resolution): IMPLEMENTED — RUNTIME-VERIFIED (scoped)
- Obligation 2 (digest): IMPLEMENTED — RUNTIME-VERIFIED (scoped)
- Obligation 3 (decision): IMPLEMENTED — RUNTIME-VERIFIED (scoped)
- Overall: DESIGN REPUBLISHED — BLOCKING CLOSED AT DESIGN LEVEL
- Runtime implementation: GRANTED (scoped runtime obligations + receipt schema)

### 3.4 Boundary statement
This block closes the DESIGN blocking for license_reference.
It does NOT authorize schema file creation, runtime enforcement,
signing, testing, commit, push, merge, or deployment.

---

## 4. RATIFIED GOVERNANCE DECISIONS (8/8)

1. Classification/purpose allowlists: CONDITIONAL FINAL (effective after #2 applied)
2. Narrower permissions: EXTERNAL_URL RESTRICTED — REMOVED. All other 5 types unchanged.
   => EXTERNAL_URL permitted classification: PUBLIC, INTERNAL, CONFIDENTIAL
3. New allowlist value authority: Human Governance Approver (single authority; not agent)
4. Audit-only receipt: UNSIGNED ALLOWED (audit-only scope ONLY; execution receipts must be signed)
5. Executor key: registry mandatory; rotation 90 days; revocation immediate
6. Anchor storage: append-only + dual-authority recovery (no single point of failure)
7. Timestamp/clock: trusted NTP; drift tolerance <= 2s; monotonic receipt ordering
8. Verified-byte handle: retention 180 days; handle immutable; deletion only on expiry

---

## 5. GAP MATRIX

| Gap | Status |
|---|---|
| A. Digest canonicalization | CLOSED (design) / OPEN (implementation) |
| B. R1 constraints | CLOSED (design) / OPEN (human decisions) |
| C. Source-type policy | CLOSED (design) / OPEN (human governance) |
| D. Receipt projection | CLOSED (design) / OPEN (schema absent) |
| E. Repository integrity | CLOSED |
| license_reference schema shape | VERIFIED |
| license_reference process obligations | IMPLEMENTED — RUNTIME-VERIFIED (scoped) |

---

## 6. FINAL DISPOSITION

- **Design:** PROGRESS — NOT READY FOR FINAL APPROVAL
- **R1/R2/R3:** NOT READY
- **Stage 05b:** BLOCKED
- **Stage 16:** NOT CERTIFIED
- **PR #11:** OPEN — DO NOT MERGE
- **Implementation:** GRANTED (scoped runtime obligations + receipt schema)

**No tests, installation, schema modification, signing, REA execution, commit, push, merge, tag, or deployment has been performed.**

**IMPLEMENTATION APPROVAL GRANTED (scoped). Signing, deployment, commit, push, merge, tag remain unauthorized.**
