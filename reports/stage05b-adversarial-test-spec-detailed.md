# Stage 05b Adversarial Test Spec - Detailed - Read-Only

- Verdict: PARTIAL - NOT CERTIFIED
- Source: read-only audit of gate.py, receipt.py, rbac.py, schemas, shipped artifacts
- Status: specification only, no execution, no code fix

## R1 expiry - gate.py:47-59, 157-159
- T-R1-A missing: expires_at_utc key nei, valid signature, fixed now_utc -> deny expected
- T-R1-B malformed: 2026-13-99T99:99:99Z / not-a-date -> deny expected
- T-R1-C expired: top-level expiry past, now_utc er cheye age -> deny, R1 authorization has expired
- T-R1-D nested: shipped authorization.json unchanged, expiry authorization.expires_at_utc te -> gate top-level khujle miss korbe

## R3 path containment - gate.py:201-205
- T-R3-A traversal: manifest e ../outside.txt, bairer file er sothik hash -> deny expected
- T-R3-B absolute: manifest e absolute path, sothik hash -> deny expected, root / absolute = absolute
- T-R3-C symlink: repo-r vitore symlink, target bairer file -> post-resolve containment e deny expected

## Audit log - receipt.py:103-121, 149
- T-LOG-A tampered history: 2 event likhe 1st event er payload bodle, 3rd append -> reject expected
- T-LOG-B preservation: compact JSON diye seed kore append, ager bytes same ache kina byte-compare

## R2 license - gate.py:168-178
- T-R2-A missing status: result.status nei -> deny
- T-R2-B missing approval: approved_for_stage_05b nei -> deny
- T-R2-C DENY: sbom_sha256 vul / sbom_path missing -> DENY -> deny
- T-R2-D ESCALATE: sbom_sha256 nei / license_reference unresolvable -> ESCALATE -> deny

## RBAC - rbac.py:94-116, gate.py:126
- T-RBAC-A same-actor: evaluate_rbac actor_id=exec-1, approver_id=exec-1, EXECUTOR + AGENT -> deny expected
- T-RBAC-B gate-level: valid artifacts diye enforce_rea_gate actor_id=exec-1, role=EXECUTOR -> gate self_certified / approver_id pass kore kina check

## Boundary
- PR #17 HOLD, DO NOT MERGE
- PR #11 OPEN, DO NOT MERGE
- No implementation, no signing, no REA execution
