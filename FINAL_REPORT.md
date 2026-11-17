# ASTRA CODER v1.0.0 — Release Qualification & Ratification Report (SIGNED OFF)

> SIGNED OFF. Operator ratified Stage 16 for the v1.0.0 release. This document
> records Stage 16 as CLOSED PASS WITH QUALIFICATIONS. No KF-1 fix was applied
> and no tests were rerun for this report.

- REPO HEAD (gate HEAD, unchanged): `3bb8b5e589ba90f1849b666e038885c13ffb7745`
- Evidence dir: `C:\Users\User\AppData\Local\Temp\astra-clean-linux-gate-20261115-1`
- Generated: 2026-11-15

## 1. Gates (clean pinned-Linux, isolated `clean-src`)

| Gate | Result | Exact evidence |
| --- | --- | --- |
| ruff check (`src tests`) | PASS | `EXIT:0`, "All checks passed!" — `02-linux-python.log` |
| ruff format --check (`src tests`) | PASS | `EXIT:0`, "44 files already formatted" — `02-linux-python.log` |
| mypy (`src`, canonical scope) | PASS | `EXIT:0`, "Success: no issues found in 24 source files" — `02-linux-python.log` |
| pytest (Linux) | PASS | `EXIT:0`, **217 passed** (progress dots 72+72+72+1, 100%) — `02-linux-python.log` |
| Semgrep | PASS | `EXIT:0`, **0 findings / 46 targets**, 2 rules — `02-linux-semgrep.log` |
| Dashboard npm ci | PASS | `EXIT:0`, "found 0 vulnerabilities" — `03-linux-dashboard.log` |
| Dashboard lint | PASS | `EXIT:0`, "No ESLint warnings or errors" — `03-linux-dashboard.log` |
| Dashboard tsc --noEmit | PASS | `EXIT:0` — `03-linux-dashboard.log` |
| Dashboard test | PASS | `EXIT:0`, **7 passed (7)** across 3 files — `03-linux-dashboard.log` |
| Dashboard build | PASS | `EXIT:0`, "Compiled successfully" — `03-linux-dashboard.log` |
| Dashboard audit --audit-level=high | PASS | `EXIT:0`, "found 0 vulnerabilities" — `03-linux-dashboard.log` |

Pinned toolchains used:
- Python gate: image `astracoder-worker:d5-17-1`, runtime **Python 3.12.2**, git 2.39.5.
- Semgrep gate: `semgrep/semgrep:1.181.0-nonroot`, runtime 1.181.0.
- Dashboard gate: `node:24.22.2-bookworm-slim@sha256:01d566e8...`, runtime node v24.22.2.

## 2. Preservation (unchanged)

- HEAD: `3bb8b5e589ba90f1849b666e038885c13ffb7745` (unchanged).
- Canonical report `reports/worker-smoke.json`: `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` (unchanged).
- Lock `dashboard/package-lock.json`: `738F54E6736EE30DE28BD4583E5C583F38FB9983173FF85CB0A10132AE9A21B0` (unchanged).
- Docker: 0 running / 8 total; before/after ID diff = none (`01-docker-before.txt`, `04-docker-after.txt`, `04-post.txt`).
- Git status: pre 66 lines = post 66 lines; bytes equal; current == pre (`pre-status.txt`, `post-status.txt`, `04-post.txt`).
- .gitignore post-gate change: only 2 lines added (.security-venv-win/ + /omnirush) to exclude local venv/binary, no code/test/Dockerfile change.
- .env.example:28,29 operator-confirmed dummy examples (server-side-api-token / server-side-login-token), commented-out, safe to commit.

## 3. Image identity

- Worker: `astracoder-worker:d5-17-1` — Image ID/RepoDigest `sha256:3a27032a442f2e6ed1a3041cf91b58653014a4c515e3705dddd338b1ef37c055` (Q1-CLOSURE SHA-256 `40C2173D...9914A1`).
- Semgrep: `semgrep/semgrep:1.181.0-nonroot` — Image ID `sha256:4c37ae86...7ea879`.
- Node: `node:24.22.2-bookworm-slim@sha256:01d566e8...e9` — Dockerfile digest = local ID = RepoDigest MATCH.

## 4. KF-1 (sole qualification)

- Location: `demo/verification/test_contract.py:18`
  `    assert os.getuid() == 10001  # type: ignore[attr-defined]`
- `mypy .` → **EXIT 1**, exactly **1** error: unused-ignore (`demo/verification/test_contract.py:18`).
- The file is a **Linux-only sandbox contract by design** (`os.getuid()` exists only on POSIX; no `sys.platform`/Windows guard).
- **NO fix in v1.0.0.** Fix deferred to the next release.
- Not claimed here: Windows pytest 215/2, gitleaks, or "CERTIFIED & PASSED".

## 5. Evidence SHAs

- MANIFEST.txt: `F7AAD106AAD1633DF3F452077DBEDC99A3469795084B7FF3A97D83E023006699`
- FINAL_RATIFICATION.txt: `24D990EADE10563224E9FC2B5ECD5FEA040AB8ED7823909EB21CECEF8D0AF8D5`
- Q1-CLOSURE.txt: `40C2173D07E6DC90CE3930862CDB0636388AE5C9D78A80666D803B6F929914A1`

## 6. Post-v1.0.0 backlog

- Stage 04b / Stage 05b are **separate work**, NOT part of v1.0.0.

---
Status: Stage 16 CLOSED PASS WITH QUALIFICATIONS — Operator Signed Off for v1.0.0 Release (KF-1 deferred to v1.0.1; Stage 04b/05b scoped to post-v1.0.0).

---

## 7. v1.0.1 — Stage 04b (free cascade) qualification (CERTIFIED)

This section covers ONLY the v1.0.1 Stage 04b work on `feat/v1.0.1-free-cascade`; it does not alter
the v1.0.0 sign-off above.

- Branch: `feat/v1.0.1-free-cascade`; base `main` @ `30be0c025be7f786f5763cb2085f44cada38f812`.
- Protected report `reports/worker-smoke.json`:
  `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` (unchanged).
- Commits: `72fd7a1` Stage 04b wired, `d66f7ba` CI runner pin to ubuntu-24.04, `d89449a` CI format fix,
  `cf47246` gitleaks allowlist, `98f4e06` FINAL_REPORT update with RUN 44154077310.
- Tests: local Windows PASS 328 passed + 2 skipped (`pytest.log`, `--strict-markers`); Linux CI `make test`: 330 passed. The two local skips are `tests/test_docker_tools.py:378` and `tests/test_tools.py:53`, both "symlinks unavailable on this filesystem"; they are environment skips, not failures (328 + 2 = 330 collected).
- Coverage: total 86.95%; free_cascade 99%; gateway 88%; policy 98% (`coverage.xml`).
- ruff / mypy / format: PASS in local and in CI (0 findings, 50 files formatted).
- semgrep: PASS in CI, 0 findings / 52 targets / 5 rules (post-Q2 coverage in main; supersedes the earlier 29 targets / 2 rules figure).
- gitleaks: PASS in CI RUN 44155145765 and post-Q1 in main CI RUN 44171352485, `no leaks found`. The 2
  earlier findings were PRE-EXISTING in base `30be0c0`, in `reports/d54-dockerfile-verify-20261025.md`,
  generic-api-key on Docker image IDs, container IDs and SHA-256 verification hashes at lines 38 and 117.
  Q1 fix in PR #2: removed the whole-file `paths` allowlist, restored `[extend] useDefault = true`, and
  suppressed only the two exact fingerprints in `.gitleaksignore`. No redaction, no history rewrite.
- Security: NETWORK evaluated before gateway; T4 recorded approval; secret redaction; mandatory
  audit sink; TaskLimits preflight; global OpenRouter `:free` invariant; startup cascade validation.
- Gates: G1 PASS, G2 PASS, G3 PASS, G4 PASS, G5 PASS.
- CI evidence:
    - RUN 44152068725: FAIL, setup-python, Python 3.12.2 not found for Ubuntu 26.04, infra issue.
    - RUN 44153277996: FAIL, make format, Makefile:18, exit 2.
    - RUN 44154077310: FAIL, 7 of 8 steps PASS, only gitleaks FAIL on 2 pre-existing leaks above.
    - RUN 44155145765: SUCCESS, 1m12s, full CI PASS, test plus lint plus format plus typecheck plus
    semgrep plus gitleaks all PASS. This is the certifying run.
- Historical status: pushed, full CI PASS, CERTIFIED on feat branch.
- Final verdict is recorded in docs/stages/04b.md. Merge, tag and deploy required separate explicit approval.

### 7.1 Post-PR #2 documentation reconciliation (Q1/Q2/Q3 closed in main)

This subsection reconciles the record after PR #2 was merged. It is documentation only: no code,
workflow, security config, or evidence file is changed by this update.

- Q1 Gitleaks: CLOSED in main at `34d81bcbab28a44830563aaaeac325c653a12f88`. Evidence: PR #2 and main CI
  run 44171352485 SUCCESS (gitleaks `no leaks found`). Two finding-level fingerprints in `.gitleaksignore`;
  no file-level path allowlist.
- Q2 Semgrep: CLOSED in main at `34d81bcbab28a44830563aaaeac325c653a12f88`. Evidence: PR #2 and CI
  44171352485. Coverage corrected to 52 targets / 5 rules / 0 findings (supersedes 29 / 2); tests are scanned.
- Q3 CI runtime: CLOSED in main at `34d81bcbab28a44830563aaaeac325c653a12f88`. Evidence: PR #2 and CI
  44171352485. Actions on Node 24 (`checkout@v6`, `setup-python@v6`, `gitleaks-action@v3`), no Node.js 20
  deprecation.
- Test-count reconciliation: local Windows 328 passed + 2 skipped; Linux CI 330 passed. The two skips are
  `tests/test_docker_tools.py:378` and `tests/test_tools.py:53`, both "symlinks unavailable on this
  filesystem"; environment-dependent, not failures.
- D5: CLOSED, closed by PR #5 merge commit `9d48b22cd61772d68103bf0a0d5b8bfd517b0318`.
- Worker conflict: RESOLVED by isolated rerun.
- Full-profile evidence SHA-256: `54C4A56AC494865896F2E7C4F9BEF62BB7876703E6C95DAE3361D88ED9E024E5`.
  Protected report hash unchanged: `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8`.
- PR #5 CI runs: `44192723668` (push) SUCCESS, `44192760613` (pull_request) SUCCESS; main CI run
  `44193923749` SUCCESS.
- D54 fingerprints preserved: line 38 `d743c19c...`, line 117 `9f8f0aa7...`, verified by Python bytes hash.
- Stage 16: NOT CERTIFIED. No production readiness claim.
- Tag: `v1.0.1` still points to `b81226a`; no new tag created by this work.
