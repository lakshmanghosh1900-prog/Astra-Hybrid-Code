# Stage 05b Adversarial Test Spec - Read-Only, No Implementation

- Verdict: PARTIAL - NOT CERTIFIED
- Purpose: ki test korle gap proman hobe, tar description matro. Kono code fix na.

## Priority 1 - R1 expiry
- T1: expires_at_utc missing -> gate deny hobe kina
- T2: expires_at_utc malformed / invalid format -> gate deny hobe kina
- T3: expires_at_utc past -> gate deny hobe kina
- T4: shipped authorization.json nested expiry diye gate evaluate -> nested expiry karjokor kina

## Priority 2 - R3 path containment
- T5: manifest e ../ traversal path -> gate deny hobe kina
- T6: manifest e absolute path -> gate deny hobe kina
- T7: manifest e repo-r bairer symlink target -> gate deny hobe kina

## Priority 3 - Audit log integrity
- T8: ager event er body / event_sha256 tamper kore append -> reject hobe kina
- T9: append er age / pore ager event er bytes same ache kina
- T10: tampered log e integrity.verified false / reject hoy kina

## Priority 4 - R2 + RBAC + Exception
- T11: lic_status missing / approved_for_stage_05b missing / decision DENY-ESCALATE -> gate deny kina
- T12: gate diye EXECUTOR nijeke approve -> deny kina, self_certified / approver_id path soho
- T13: invalid JSON, list bodole object, result missing, unreadable file -> clean deny, exception na
- T14: wrong key, malformed base64, missing key -> alada failure outcome kina

## Boundary
- PR #17 HOLD, DO NOT MERGE
- PR #11 OPEN, DO NOT MERGE
- No implementation, no signing, no REA execution in this spec
