# Stage 05b Read-Only Audit Findings - 2026-11-19

- Scope: gate.py, receipt.py, rbac.py, test_rea_enforcement.py, schemas, authorization.json, license-check.json, rea-input-manifest.json
- Method: read-only only, no file modification, no REA execution, no signing
- Verdict: PARTIAL - NOT CERTIFIED

## High
- F-R1-01: gate.py:47-59, 157-159 - malformed/missing expiry treated as no-expiry
- F-R1-02: gate.py:157 vs authorization.json:12 - gate reads top-level expires_at_utc, shipped artifact has nested authorization.expires_at_utc
- F-R3-01: gate.py:201-205 - no path containment check, ../ / absolute / symlink escape not blocked
- F-LOG-01: receipt.py:103-105, 121 - prior chain not verified before append
- F-LOG-02: receipt.py:149, 142-147 - full file rewrite with write_text, integrity.verified True hardcoded

## Medium
- F-RBAC-01: gate.py:126 vs rbac.py:94-116 - gate never passes self_certified / approver_id
- F-EXC-01: gate.py:152-154, 168-169 - malformed JSON / non-dict result may raise instead of fail-closed

## Low
- F-R3-02: gate.py:207, 211 - hash .lower() normalization vs strict check
- F-SIG-01: gate.py:89-90 - except (InvalidSignature, ValueError, Exception) redundant
- F-R2-01: gate.py:168-178 - R2 fail-closed by code, zero negative tests
- F-SCH-01: authorization-log.schema.json:88-97 - nullable event_sha256, non-const verified

## NOT Proven
- R1 expiry, R3 containment, R3 hash strictness, audit tamper rejection, signature failure modes, R2 negatives, shipped artifact evaluation

## Boundary
- PR #17 HOLD, DO NOT MERGE
- PR #11 OPEN, DO NOT MERGE
- No implementation in this audit
