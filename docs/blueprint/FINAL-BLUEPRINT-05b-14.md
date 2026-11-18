# ASTRA CODER — FINAL BLUEPRINT 05b-14

## Locked architecture — 8 layers
1. Intake / Interface
2. Orchestrator + deterministic Policy
3. Repository Intelligence
4. Bounded Agent Loop
5. Hybrid Model Gateway
6. Typed Tool Mesh
7. Docker Sandbox
8. Verification, Evidence, Audit & Recovery

Non-negotiable: no code/patch/rollback without test/lint/type-check/security scan + evidence.
Approval chara write/execute na. Rollback-e user uncommitted change harabe na. No false SUCCESS.
Model routing: local-first, tarpor low-cost API, tarpor premium fallback. Retry max 3.

## REA / Claude Code policy — LOCKED
- REA = bounded, evidence-based analysis. Only user-owned / authorized targets.
- Claude Code = named reference for feature/workflow analysis. NO 1:1 clone, NO proprietary source/prompt recovery, NO copied source, NO unrestricted reverse engineering.
- Mandatory: authorization.json + license/permission check + authorization log. Missing = BLOCKED.
- Isolated MCP adapter. Output: spec.md + evidence-index.json + unknowns.json.
- ASTRA Policy/Approval = final authority. REA: no code edit, no Git op, no deploy, no escalation.

## Stage 05b — R1-R8 gates
R1 authorization.json, R2 license-check.json, R3 rea-input-manifest.json, R4 evidence-index.json,
R5 spec.md, R6 unknowns.json, R7 rea-policy-review.json, R8 rea-verification.json.
Any gate fail/unavailable = REA BLOCKED. 05b implementation NOT AUTHORIZED yet.

## Stage status
- D5: CLOSED (PR #5 9d48b22, PR #6 40cd3f5) — do not reopen
- 05b: SPEC ONLY, NOT IMPLEMENTED
- 06-13: DOCUMENTED IMPLEMENTED — needs integration audit, not certified
- 14: IMPLEMENTED, RECONCILED in PR #8 — Next.js 15.5.28, 7 dashboard tests, audit 0, Next 16 advisory caveat remains
- 15: Harness IMPLEMENTED, baseline 0/70 — preserve honestly
- 16: NOT CERTIFIED — historical FINAL_REPORT sign-off is history, not current-HEAD certification

## PR #7 / PR #8
- PR #7: MERGED as 468a14b — feature only, not stage closure
- PR #8: MERGED as 625c797703f3620476ac4c81e618298f2ba90cda — remediation only
    - Retry 10 -> 3
    - ThreadPoolExecutor -> _DaemonExecutor, abandoned tracking
    - Memory audit sink, worker advisory memory
    - Stage 14 docs reconciled

## Known limitations — follow-up required
- Timeout = daemon quarantine, hard kill still out-of-process
- Memory audit = optional sink, separate SQLite DB, NOT transactional with StateStore
- AstraOrchestrator / AstraSelfHealingProxy still NOT wired into TaskWorker
- Follow-up: executor shutdown drain + audit outbox / reconciliation
- No production / autonomous coding claim from PR #7 / PR #8
