# Stage 07 Phase 1 review package

Status: PARTIAL IMPLEMENTATION / NOT CERTIFIED. Independent second-party review PENDING; human sign-off PENDING. This package is implementation-side evidence only and does not claim second-party approval.

Baseline: f576e4d51876542397c24556aeb412861aeeae17. Initial commit/HEAD before this package: 9f6395d1d35b199b718d3c14763b607cbe1fce8d. Branch: feat/stage07-rea-skill-hybrid-braining. No push/merge authorized.

## Exact changed-file list (5 paths relative to HEAD 9f6395d)

- M docs/design/stage07-hybrid-rea-skill.md
- M src/astra_coder/hybrid_skill.py
- M tests/unit/test_stage07_hybrid.py
- ?? reports/security/stage07-phase1-security.md
- ?? reports/stage07-phase1-review.md

No caches, .next artifacts, generated keys, or unrelated files are staged or included.

## Architecture and implementation changes

Existing Stage 05b REA authority is reused unchanged. EXECUTOR is the default execution role and is policy-compatible with RUN_REA_EXECUTION; SYSTEM_VERIFIER appears only as the audit-event receipt actor label, not as an RBAC role. Independent trusted approver plus signed R1 bundle_sha256 binds plan/step/patch; R3 and trusted-approver bindings are checked by unchanged enforcement. The parser applies exact-byte, single-file unified patches (LF/CRLF framing, final-newline markers, multi-hunk, insert/delete/replace). External audit intent is hash-chained, bound to authorization ID, and consumed once per operation; a same-log lock serializes wrapper calls. Completion/failure receipts and crash recovery remain host responsibilities. No authenticated approval store, provider routing, or application entry point is claimed.

## Parser coverage and results

Permanent tests in tests/unit/test_stage07_hybrid.py cover:

- test_parser_exact: LF and CRLF framing; source with/without final newline; `\ No newline at end of file`; single/multiple/adjacent hunks; insertions and deletions; optional count-one hunk syntax.
- test_parser_rejects: empty patch, invalid offsets, count mismatches, context mismatch, unsupported patch lines, garbage, GIT binary patch, rename headers, overlapping repeats, unterminated body, multi-file payload.
- test_parser_headers: missing/mismatched headers, /dev/null creation/deletion, extra Git headers.
- test_paths: path traversal, absolute Windows path, protected evidence and REA internals rejected at the executor boundary; file marked sample.txt.
- test_allowed / test_denies: mocked isolation tests for digest, approval, gate, audit and step failures with no target mutation.

Command: `.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider -q tests/unit/test_stage07_hybrid.py`
Result: 70 passed, exit code 0 (verified twice). With `-o addopts=--strict-markers`: `70 passed`, exit 0.

## Real REA/RBAC test evidence (unmocked)

The `real_case` fixture reuses existing REA fixture builders, generates keys in memory, and patches `require_stage05b_execution` back to the real implementation. Mocked isolation tests are separate from these.

- test_real_execution: real R1/R2/R3 + RBAC scope binding, trusted approver, all checks true, exact resulting bytes, audit chain `[STAGE_05B_GATE_EVALUATED, STAGE07_PATCH_INTENT]`, authorization_id `auth-05b-20261119-01`.
- test_real_signed_patch_context_denial: signed invalid context raises ValueError; only the gate event exists; target unchanged.
- test_real_denials (19 cases): unknown/agent role, missing authorization, signature, expiry, R1 state, R2 license, R3 hash, approver registry, self-certification, approval digest, patch digest, bundle mismatch, unauthorized/traversal/protected paths, audit failure, rejected patch, replay.
- test_real_concurrent_execution: two concurrent executions yield exactly one success; target patched once.

No file in src/astra_coder/rea/ was modified to make tests pass.

## Full regression results (commands and exit codes)

| Command | Result | Exit |
|---|---|---|
| `.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider -q tests/unit/test_stage07_hybrid.py` | 70 passed | 0 |
| `.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider -q tests/unit/rea/test_rea_enforcement.py` | 88 passed | 0 |
| `.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider -q tests/unit` | 162 passed | 0 |
| `.venv\Scripts\python.exe -B -m ruff check src tests` | All checks passed | 0 |
| `.venv\Scripts\python.exe -B -m ruff format --check src tests` | 75 files already formatted | 0 |
| `.venv\Scripts\python.exe -B -m mypy --cache-dir=<TEMP> src` | 45 source files, no issues | 0 |
| schema validation (`test_schemas`, Draft202012Validator) | 1 passed / 69 deselected | 0 |
| `git diff --check` | clean | 0 |

Counts were confirmed with `-o addopts=--strict-markers` (the plain doubled `-q` suppresses the summary line but still exits 0 with all dots).

## Gitleaks reconciliation

Executable note: the given `.tools\gitleaks.exe` path is a directory on this checkout; the actual PE binary is `.tools\gitleaks.exe\gitleaks.exe`. That leaf path was used. No directory or malformed path was invoked. All scans used `--redact`; no secret values are printed. No baseline file is configured; `.gitleaks.toml` extends the default rules and `.gitleaksignore` supplies exact fingerprint suppressions.

| Scan | Exact command | Exit | Findings | Errors | Completed | Exclusions/baseline |
|---|---|---:|---:|---:|---|---|
| Git history | `detect --source . --redact --report-format json --report-path <TEMP>\gl-history.json --no-banner` | 0 | 0 | 0 | yes, 100 commits, 1.66 MB | repo .gitleaks.toml + .gitleaksignore; no baseline |
| Whole working directory | `detect --source . --no-git --redact --report-format json --report-path <TEMP>\gl-dir.json --no-banner` | 1 | 28 | 0 | yes, 378.92 MB | repo .gitleaks.toml + .gitleaksignore; no baseline |
| Tracked files | `git archive HEAD` to `<TEMP>\gl-archive.tar`, extract 213 files, then `detect --source <TEMP>\gl-tracked --no-git --redact --config .gitleaks.toml --gitleaks-ignore-path . --report-format json --report-path <TEMP>\gl-tracked.json --no-banner` | 1 | 2 | 0 | yes, 1.23 MB | explicit config + ignore path; no baseline |
| Stage 07 deliverables | 8 authorized files copied to `<TEMP>\gl-stage07`, then `detect --source <TEMP>\gl-stage07 --no-git --redact --config .gitleaks.toml --gitleaks-ignore-path . --report-format json --report-path <TEMP>\gl-stage07.json --no-banner` | 0 | 0 | 0 | yes, 53.10 KB | explicit config + ignore path; no baseline |

`SCANS [('tracked files', 1, 2), ...]` tuple fields are interpreted as `(scan label, exit code, findings count)`; this is inferred by correlation with the scanner table above and the earlier security report, not from a preserved script. Exit 1 means findings were encountered, not that the scan failed.

Reconciliation of the 28 whole-directory findings (22 verified false positives + 6 generated-key HOLD):

- 16 dependency false positives in `.venv` / `.security-venv-win` site-packages (identifiers/constants).
- 2 historical report false positives (`reports/d54-dockerfile-verify-20261025.md`, Docker tags) — these are the 2 tracked-file findings.
- 2 compiled test-fixture false positives (`tests/__pycache__/test_stage04b_security.*.pyc`, constant-folded source line 464).
- 2 SARIF commitSha false positives (`gitleaks-artifact/.../results.sarif`).
- 6 generated preview-key detections (`dashboard/.next/cache/.previewinfo:1` x2, `dashboard/.next/prerender-manifest.json:58/59`, `dashboard/.next/standalone/.next/prerender-manifest.json:58/59`) — SECURITY HOLD.

No suppressions were added and no genuine finding was hidden. A clean git-history or deliverable scan does not establish deployment safety.

## Preview-key security disposition

See reports/security/stage07-phase1-security.md. Banner: `GENERATED BUILD MATERIAL — DEPLOYMENT EXPOSURE UNRESOLVED — SECURITY HOLD`. Six preview findings are documented with standalone-runtime inclusion and unverified deployment exposure. No key values printed; no rotation, deletion, image build, deployment, or external validation performed. Docker CLI is unavailable, so image layers and deployment exposure remain unresolved. This uncertainty is preserved, not accepted as harmless.

## Protected integrity

- reports/worker-smoke.json: 3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8 (matches).
- authorization.json: 0E6E6B0296D6120511BF89E3CC0B7261134969DF754471921E6B55FBD7F22EED (matches).
- `git diff --exit-code origin/main -- src/astra_coder/rea evidence-index.json rea-verification.json authorization.json reports/worker-smoke.json` = 0.
- origin/main = f576e4d51876542397c24556aeb412861aeeae17.
- PR #11: OPEN, head 2d48828ce5881c64121f5f50105c31f2b37267d7, base main (unchanged).
- C:\astramind-dev not accessed.

## Remaining limitations

External deployment uncertainty for generated preview keys; no authenticated approval store; trusted host must provision signed bundles/registries, choose one authoritative external audit log, exclude hostile filesystem writers, and reconcile consumed intents; completion/failure receipts and crash recovery are out of scope; no live provider routing or Phase 2 work. Independent security review and human sign-off remain required.
