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

## 7. v1.0.1 — Stage 04b (free cascade) qualification (working tree, pending push)

This section covers ONLY the v1.0.1 Stage 04b work on `feat/v1.0.1-free-cascade`; it does not alter
the v1.0.0 sign-off above.

- Branch: `feat/v1.0.1-free-cascade`; base `main` @ `30be0c025be7f786f5763cb2085f44cada38f812`.
- Protected report `reports/worker-smoke.json`:
  `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` (unchanged).
- Tests: PASS 328 passed, 2 skipped (`pytest.log`, `--strict-markers`).
- Coverage: total 86.95%; free_cascade 99%; gateway 88%; policy 98% (`coverage.xml`).
- ruff / mypy: PASS (0 findings).
- semgrep: PASS, 0 findings / 29 targets (`semgrep.log`).
- gitleaks: 2 findings, both PRE-EXISTING in base commit `30be0c0`
  (`reports/d54-dockerfile-verify-20261025.md`, a Docker verification image tag), none in this
  diff (`gitleaks-findings.json`). Not hidden; out of Stage 04b scope.
- Security: NETWORK evaluated before gateway; T4 recorded approval; secret redaction; mandatory
  audit sink; TaskLimits preflight; global OpenRouter `:free` invariant; startup cascade validation.
- Status: implemented + wired, one reviewed commit prepared, NOT pushed, real CI pending.
- Final verdict is recorded in docs/stages/04b.md after push/CI; do not treat v1.0.1 as certified
  until real CI passes on the pushed branch.
