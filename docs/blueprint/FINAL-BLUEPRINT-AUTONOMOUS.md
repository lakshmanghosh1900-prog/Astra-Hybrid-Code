# ASTRA CODER — FINAL BLUEPRINT AUTONOMOUS (05b-16)
# Extends: docs/blueprint/FINAL-BLUEPRINT-05b-14.md @ 721e91a — DO NOT DELETE OR REWRITE THAT FILE

## 0. HUMAN AUTHORIZATION — THIS FILE IS THE AUTHORIZATION
- Repo: lakshmanghosh1900-prog/Astra-Hybrid-Code
- Local: C:\Users\User\Desktop\ASTRA CODER
- Agent is AUTHORIZED to run stages 05b -> 16 autonomously, one stage = one branch = one PR = one merge.
- Agent must NOT ask any question during execution. If ambiguous -> choose safest option: NO change + BLOCKED + log reason.
- Anything outside stages below, or outside limits in Sec 7, = BLOCKED. No guessing, no silent skip.
- TAG / DEPLOY = NOT AUTHORIZED by this file. Tag/deploy needs separate line: TAG_DEPLOY_AUTHORIZED=YES. Without that line, agent must STOP after merge and report READY FOR TAG/DEPLOY.

## 1. LOCKED ARCHITECTURE — 8 LAYERS (unchanged from PR #9)
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
Model routing: local-first, then low-cost API, then premium fallback. Retry max 3.

## 2. REA / CLAUDE CODE POLICY — LOCKED
- REA = bounded, evidence-based analysis. Only user-owned / authorized targets.
- Claude Code = named reference only. NO 1:1 clone, NO proprietary source/prompt recovery, NO copied source, NO unrestricted reverse engineering.
- Mandatory: authorization.json + license/permission check + authorization log. Missing = BLOCKED.
- Isolated MCP adapter. Output: spec.md + evidence-index.json + unknowns.json.
- ASTRA Policy/Approval = final authority. REA: no code edit, no Git op, no deploy, no escalation.

## 3. LOCKED HISTORY — DO NOT REOPEN
- D5: CLOSED (PR #5 9d48b22, PR #6 40cd3f5)
- PR #7: MERGED 468a14b — feature only, not closure
- PR #8: MERGED 625c797 — remediation only, with qualifications
- PR #9: MERGED 721e91a — Blueprint Final docs-only
- Stage 16: NOT CERTIFIED until Sec 5 Stage 16 PASS is verified on main.

## 4. AUTONOMOUS FAIL / PASS RULE — SAME FOR EVERY STAGE
PASS = ALL must be true:
- [ ] pytest PASS (no skipped-as-pass, no fake pass)
- [ ] lint PASS (ruff)
- [ ] type-check PASS (mypy / pyright where configured)
- [ ] security scan PASS (gitleaks, no new secrets)
- [ ] CI on PR: 0 failing, 0 pending, all SUCCESS
- [ ] gh pr view: mergeStateStatus=CLEAN, mergeable=MERGEABLE
- [ ] Diff = ONLY that stage scope. No other stage file, no protected file.
- [ ] No false SUCCESS string in logs/reports. Evidence files present.
FAIL = ANY one fails.
FIX LOOP: FAIL -> fix minimal -> re-verify. Max 3 fix loops per stage.
After 3rd FAIL -> Stage = BLOCKED. Agent must: 1) create reports/<stage>-BLOCKED.md with failing command + log + reason, 2) commit ONLY that report on stage branch, 3) create PR with title "[BLOCKED] <stage>", 4) DO NOT MERGE, 5) STOP that stage, log BLOCKED and move to NEXT stage ONLY if next stage does not depend on blocked stage. If dependent -> STOP ALL and report FINAL BLOCKED.

## 5. STAGE-WISE AUTONOMOUS SCOPE — IN ORDER, NO SKIPPING
### Stage 05b — REA Implementation
- Entry: R1 authorization.json, R2 license-check.json, R3 rea-input-manifest.json must exist. Any missing = BLOCKED, no code.
- Scope: Isolated REA adapter + R4 evidence-index.json, R5 spec.md, R6 unknowns.json, R7 rea-policy-review.json, R8 rea-verification.json.
- Exit: R1-R8 all present + Sec 4 PASS. No REA code outside adapter.
### Stage 06 — Integration Audit 06-14
- Scope: READ-ONLY audit first. Compare docs/stages/*.md vs src/ code vs tests. Output: reports/stage06-gap-matrix.md.
- Fix ONLY gaps found in matrix. No new feature.
- Exit: Gap matrix + all gaps either FIXED with test or marked BLOCKED with reason + Sec 4 PASS.
### Stage 07 — Orchestrator Wiring (PR #8 leftover)
- Scope: Wire AstraOrchestrator + AstraSelfHealingProxy into TaskWorker. Remove "not wired" limitation honestly if wired, else BLOCKED.
- Exit: Worker uses orchestrator/proxy in code + test proves wiring + Sec 4 PASS.
### Stage 08 — Executor Shutdown Drain + Audit Outbox (PR #10 follow-up)
- Scope: _DaemonExecutor shutdown drain + memory audit outbox/reconciliation. Memory audit must become transactional OR documented as non-transactional with outbox retry.
- Exit: Drain test + outbox test + Sec 4 PASS. Hard-kill still out-of-process must stay documented if not fixed.
### Stage 09 — Docker / Sandbox Hardening
- Scope: Audit Dockerfile, compose, sandbox limits. Fix only proven gaps.
- Exit: Docker verify + Sec 4 PASS.
### Stage 10 — Security / Policy / Secrets
- Scope: PolicyEngine, redaction, gitleaks allowlist audit. No secret in code/logs.
- Exit: gitleaks PASS + policy tests PASS + Sec 4 PASS.
### Stage 11 — Stage 14 Re-verify (Dashboard)
- Scope: Next.js 15.5.28 dashboard, 7 tests, audit 0. Next 16 advisory caveat stays unless proven fixed.
- Exit: Dashboard tests PASS + Sec 4 PASS.
### Stage 12 — Docs Reconciliation 05b-14
- Scope: docs/stages/*.md + FINAL-BLUEPRINT must match code on main. Fix docs only.
- Exit: Docs match code, no code change in this stage + Sec 4 PASS.
### Stage 13 — Full Regression + Evidence Freeze
- Scope: Full test suite + freeze evidence list. Verify protected files untouched (hash check).
- Exit: Full suite PASS + Sec 4 PASS.
### Stage 14 — Pre-Certification Audit
- Scope: Re-run G1-G5 style gates on current main. G1-G5 must be PASS with real CI run IDs + logs, not config files.
- Exit: G1-G5 PASS report + Sec 4 PASS. Any gate FAIL -> BLOCKED, no certification.
### Stage 15 — Harness 0/70 -> PASS
- Scope: Harness baseline was 0/70 honestly. Fix harness until all 70 PASS with real evidence. No fake PASS, no test deletion to inflate score.
- Exit: 70/70 PASS + Sec 4 PASS.
### Stage 16 — CERTIFICATION
- Scope: ONLY after 05b-15 all PASS on main. Create reports/stage16-certification.md with: every stage merge commit + CI run ID + G1-G5 + harness 70/70.
- Exit: Certification file merged. ONLY then agent may write "Stage 16 CERTIFIED". Before that, always write "Stage 16 NOT CERTIFIED".

## 6. AUTONOMOUS EXECUTION LOOP — NO QUESTIONS
For each stage, agent MUST do in order, without asking:
1. git checkout main + git pull --ff-only
2. git checkout -b <stage-branch> (example: feat/05b-rea, fix/08-audit-outbox, docs/12-reconciliation)
3. Audit snapshot -> write reports/<stage>-audit.md
4. Implement minimal scope ONLY
5. Run locally: python -m pytest -q ; ruff check . ; mypy src/ ; gitleaks detect --no-git -v (or repo configured scan)
6. If FAIL -> fix loop max 3 (Sec 4). If PASS -> continue.
7. git add ONLY stage files. NEVER add: audit-upload/, coverage.json, coverage.xml, gitleaks-artifact/, gitleaks-findings.json, reports/worker-smoke.json (fingerprint lines), reports/d54-dockerfile-verify-20261025.md (lines 38/117).
8. git commit -m "<type>: <stage> <what>" ; git push -u origin <stage-branch>
9. gh pr create --base main --head <stage-branch> --title "<stage>: ..." --body "Stage <X>. Evidence: ... CI: ... No tag/deploy."
10. Poll: gh pr checks <N> until 0 pending. If FAIL -> fix loop (max 3 total including local loops).
11. If Sec 4 PASS + CLEAN + MERGEABLE -> gh pr merge <N> --merge --auto --body "Merge <stage> with evidence. ..."
12. NEVER use --admin. NEVER squash/rebase. Merge commit ONLY.
13. Verify: git fetch origin ; git checkout main ; git pull --ff-only ; git log -1 ; gh pr view <N> --json state,mergeCommit
14. Delete branch: git branch -d <stage-branch> ; git push origin --delete <stage-branch>
15. Log stage result in reports/AUTONOMOUS-RUN-LOG.md (stage, PASS/BLOCKED, merge commit, CI run IDs) and go to NEXT stage.
- If agent is unsure -> BLOCKED + log, NOT question, NOT guess.

## 7. HARD LIMITS — AUTONOMOUS MEANS NO BYPASS
- No --admin merge. No squash/rebase. No force push to main.
- No delete of protected evidence. No modify of fingerprint lines.
- No tag, no deploy, no release, no production claim.
- No new feature outside stage scope. No scope creep.
- No claiming PASS/CERTIFIED without CI run ID + logs + files on main.
- No treating workflow config as CI PASS. No treating user-reported test as verified without artifacts.
- If repo is dirty with protected untracked files, do NOT git add -A. Add explicit files only.

## 8. SELF-UPGRADE LOOP — AFTER STAGE 16 CERTIFIED ONLY
- After 16 CERTIFIED, agent may loop: Audit -> Propose 1 improvement -> Same Sec 4 + Sec 6 loop -> One PR -> Merge if PASS.
- Each loop = one PR. No batching. If loop FAILs 3 times -> BLOCKED, stop loop, report.
