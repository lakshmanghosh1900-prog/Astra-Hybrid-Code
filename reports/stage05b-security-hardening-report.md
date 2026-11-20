# Stage 05b Security Hardening Report

**Date:** 2026-11-20
**Branch / HEAD:** `fix/stage05b-security-hardening` @ `dcc0509efb8bbc98d0bb8c844f3e756098293847` (PR base `main...dcc0509`, merge-base `f6e1ba4`: 18 files, +2397/−168).
**Status:** `HOLD — NOT CERTIFIABLE` / `NOT READY`. PR #18/#17/#11 remain OPEN; no PR or Git mutation actions. The reconciliation and remediation in §0A/§0B are **uncommitted working-tree changes**; no commit/push was performed.
**Source findings:** `reports/stage05b-readonly-audit-findings.md` (F-R1-01/02, F-R2-01, F-R3-01/02, F-LOG-01/02, F-RBAC-01, F-EXC-01, F-SCH-01, F-SIG-01), `reports/stage05b-adversarial-test-spec-detailed.md` (15 mandatory adversarial tests), plus principal-defined `F-03A`/`F-03B`/`F-09`/`F-07` (absent from repo files; definitions supplied by the authorizing principal).
**Verification:** see §0A and §0B — results there were produced by direct execution in this working tree; historical `aa064b4` claims are retained only as context and are **NOT VERIFIED** for current HEAD.

---

## 0B. Authorized Execution Addendum — 2026-11-20 (R1 Option B / R3 baseline / evidence)

This addendum records principal-authorized actions executed on 2026-11-20 by explicit decision of Lakshman Ghosh (Human Sovereign Root). It **supersedes** any conflicting statement in §0A or the numbered historical sections. Final status remains `HOLD — NOT CERTIFIABLE` / `NOT READY`.

| Item | Authorized decision | Executed evidence |
|---|---|---|
| Scope / drift ratification | Formal ratification of the expanded working tree and `tests/unit/rea/conftest.py` synthetic fixture drift | Tree after execution: **16 modified tracked + 1 untracked** (`src/astra_coder/rea/enforcement.py`), now including `authorization.json` and `rea-input-manifest.json`. No commit, push, merge, tag, or PR action. |
| R1 (Option B) | Replace `<repo_root>/authorization.json` with the authorized gate-compatible signed artifact; rebind the external approver registry | `authorization.json` replaced by a byte-identical copy of `C:\Users\User\astra-rea-trust\signed\authorization-signed.json` (1743 bytes, byte-for-byte verified). SHA-256 transition: `A383F8773DEB0CB95474B50A6512CD5F1ED20631BB2CE2FAB57DE3661CDDDA0C` → `0E6E6B0296D6120511BF89E3CC0B7261134969DF754471921E6B55FBD7F22EED`. External `approvers.json` `artifact_sha256` = `0e6e6b0296d6120511bf89e3cc0b7261134969df754471921e6b55fbd7f22eed`, `allowed_actions` = [`RUN_REA_EXECUTION`, `APPROVE_STAGE_05B`], `authorization_id` = `auth-05b-20261119-01`. The signed file carries top-level `signature` (`key_id` `key-05b-prod-01`, base64 `signature_base64`) matching `trusted-keys.json`. |
| R3 manifest baseline | Rebaseline `rea-input-manifest.json` to the signed authorization digest and actual `dcc0509` license-file digests | `authorization_reference.sha256` = `0e6e6b0296d6120511bf89e3cc0b7261134969df754471921e6b55fbd7f22eed`; `inputs`: `__init__.py` `0d0ffed286a2682c907c20c966918b18aa764d8220beb1b2bb89c1d94bdc75eb`, `resolve_reference.py` `7fa59756b39ba2e1267a7d1ae261e1bbfac8a0c5297ef01a2fc5e0245f41c974`, `verify_digest.py` `ec129fc51a18985e62b378ed84a90cc343df03bf3fd0c5a03a0c473cd10374ac`, `decision.py` `b2b01a867c26040b919dae3f6b67d93de607fad76829f498e12b51bce6238789`. `license_reference.sha256` `863dc2698950a1bd4a4cbde24f29bb92253222dc863febd2bf004c284625708d` unchanged and verified. |
| Gitleaks evidence | Record verified scan result and re-run cleanly without writing files into the repo | `.tools/gitleaks.exe/gitleaks.exe` v8.30.1; `gitleaks git --no-banner --verbose` → **78 commits scanned, no leaks found**, exit 0. No report file written into the repo. |
| Semgrep | Isolated venv install; no Application Control bypass | Venv `C:\Users\User\astra-rea-trust\semgrep-venv2`; semgrep 1.186.0 installed **venv-only**; invocation blocked before scanning by a startup dependency `ImportError` (`cannot import name '_ExtendedAttributes' from 'opentelemetry.util.types'`) and, on re-run, by Windows Application Control (`WinError 4551`). **BLOCKED** — no bypass attempted. Global pins unchanged (opentelemetry-api 1.29.0, pydantic 2.10.6, pydantic-core 2.27.2, starlette 0.41.3, jsonschema 4.26.0, structlog 25.1.0, click 8.1.8). |
| CI evidence | Distinguish committed vs uncommitted | `dcc0509` push `44630356731` / pull_request `44630364224` — **VERIFIED**; uncommitted working tree — **NOT VERIFIED**. |
| Protected artifact | Untouched | `reports/worker-smoke.json` SHA-256 `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` — **UNCHANGED**. |

**Post-R1 test-fixture alignment (disclosure):** because the baseline `authorization.json` now carries a top-level `signature`, `tests/unit/rea/test_rea_enforcement.py::_build_gate_fixture` was adjusted to strip `signature` when `sign=False`, so negative fixtures genuinely lack a signature block. All test assertions are unchanged; no fail-closed check was weakened. Re-measured after the change: targeted REA **88 passed**, full suite **486 passed / 2 skipped / 1 warning**, ruff check/format and mypy all exit 0, `validate_r1_r3.py` all three artifacts (`authorization.json`, `license-check.json`, `rea-input-manifest.json`) VALID, and the external-registry `rea-gate` returned `allowed: true` with all four checks green.

No private keys, secrets, or trust-registry JSON files were stored inside the repository. `C:\astramind-dev` was not touched. PR #18/#17/#11 remain OPEN and untouched. Independent second-party review and final explicit human sign-off remain outstanding.

---

## 0A. Reconciliation Addendum — `main...dcc0509` + Uncommitted Remediation

All numbered sections below are retained as historical `aa064b4` evidence and are **superseded** wherever they conflict with this addendum.

### Scope (measured)
- PR diff `main...dcc0509`: **18 files, +2397/−168**, merge-base `f6e1ba4`.
- Direct commit `dcc0509`: **12 files, +1052/−231**.
- Working tree: **16 modified tracked files + 1 untracked file** (`src/astra_coder/rea/enforcement.py`) after the authorized R1/R3 updates, comprising uncommitted remediation across gate/rbac/trust/clock/receipt, new `rea/enforcement.py`, CLI/worker wiring, schemas, `sign_authorization.py`, REA tests, `authorization.json`, `rea-input-manifest.json`, and this report. No commit or push was performed. Full scope and `conftest.py` drift were formally ratified on 2026-11-20 (§0B and Principal ratification below); final certification remains pending.

### Finding mapping (principal-defined IDs; absent from repo files)
| ID | Definition (from authorization) | Code evidence after remediation |
|---|---|---|
| F-03A | Authenticated principal binding / `key_id` / `public_key_pem` | `public_key_pem` was removed from `enforce_rea_gate` / signature entry API (passing it raises `TypeError`); it remains only as a field in trusted-key registry records (`trust.py`). `_verify_r1_signature` requires `key_id`, resolves the key from the registry, and fails closed on active-key / strict-base64 failures; `trust.py` detailed loaders emit explicit registry-unavailable / no-active-keys diagnostics. |
| F-03B | Separation of duties / approver context / trusted approver registry | `rbac.py` denies `self_certified` for all `_APPROVAL_REQUIRED_ROLES` (EXECUTOR, AGENT, OPERATOR); same-actor and HUMAN_APPROVER-only rules unchanged; `trust.py` surfaces approver-registry errors. |
| F-09 | Signed authorization scope / `authorization_id` & `artifact_sha256` binding | `gate.py` requires non-empty signed `authorization_id` and enforces `authorization.approved_actions` scope for approval actions; `enforcement.py` calls the gate with `require_scope_binding=True`, making registry `authorization_id`/`artifact_sha256` bindings mandatory in production. |
| F-07 | Production gate wiring / shipped artifact / env registries | `enforcement.py::require_stage05b_execution` calls gate + audit append and fails closed on audit failure; wired into `cli.py` (`rea-gate` command) and `worker_main.py`, which invokes it **unconditionally as a mandatory pre-execution gate**. `clock.py` permits caller-supplied `now_utc` only when `ASTRA_REA_ENV=test` **and** `ASTRA_REA_TEST_CLOCK=1`. Shipped `authorization.json` was replaced on 2026-11-20 under authorized R1 Option B with a gate-compatible signed artifact (§0B); the legacy unsigned digest `A383F877…` was transitioned to `0E6E6B02…`. |

- **Conditional `bundle_sha256` binding:** `gate.py` scans the R1 authorization and R3 manifest, including their nested `authorization`/`manifest` containers, for any `bundle_sha256` field. Every present value must be strict lowercase 64-hex and all present values must agree; the code does not require both R1 and R3 to carry the digest. The resulting optional context digest is then checked against the approver registry: if the registry entry supplies `bundle_sha256`, the context must match it; if the registry entry omits it while the context supplies one, validation fails closed; if neither supplies one, bundle binding is not required. Invalid or conflicting signed digests deny fail-closed (`trust.py:175-188,262-267`; `gate.py:85-104`).
- **Audit append is conditional:** `require_stage05b_execution` always evaluates the gate, but when `audit_log_path` is `None` it returns without appending an audit event. When a path is provided, `append_audit_event` failure (`OSError`/`ValueError`) is converted into a denied `ReaGateResult` with an `R4 audit append failed closed:` reason (`enforcement.py:21-57`). `worker_main.py` and the `rea-gate` CLI pass an audit path only when configured.

### Audit-log version & byte-level check
- `verify_event_chain(..., schema_version=...)` validates v1.0.0 with legacy required keys and v1.1.0 with full keys.
- Append rejects any existing `schema_version != "1.1.0"` with an explicit `not appendable` error — no silent version mismatch. Schema description updated accordingly.
- `T-LOG-B` now compares raw bytes of each prior event object (via `JSONDecoder.raw_decode`) in addition to parsed objects and chain integrity.

### Verification — MEASURED (post-§0A alignment, current tree; exact commands and outputs)
| Command | Result | Status |
|---|---|---|
| `python -m pytest tests/unit/rea/test_rea_enforcement.py -p no:cacheprovider --override-ini addopts="--strict-markers" -q` | `88 passed` | **MEASURED (post-§0A alignment, current tree)** |
| `python -m pytest -p no:cacheprovider --override-ini addopts="--strict-markers" -q` | `486 passed, 2 skipped, 1 warning` | **MEASURED (post-§0A alignment, current tree)** |
| `python -m ruff check --no-cache src tests` | `All checks passed!` | **MEASURED (post-§0A alignment, current tree)** |
| `python -m ruff format --check --no-cache src tests` | `72 files already formatted` | **MEASURED (post-§0A alignment, current tree)** |
| `python -m mypy --cache-dir=<temp> src` | `Success: no issues found in 43 source files` | **MEASURED (post-§0A alignment, current tree)** |
| `semgrep --config semgrep.yml --error --metrics=off --disable-version-check --include "*.py" src tests scripts demo` | exit 1 before scanning: `ImportError: cannot import name '_ExtendedAttributes' from 'opentelemetry.util.types'` on one invocation; `OSError: [WinError 4551] An Application Control policy has blocked this file` on re-run | **BLOCKED** |
| `gitleaks git --no-banner --verbose` (`.tools/gitleaks.exe/gitleaks.exe` v8.30.1) | `78 commits scanned`; `no leaks found`; exit 0 | **VERIFIED (2026-11-20)** — §0B |

These results are from the post-§0A-alignment verification run on the current working tree, with no parallel edits during that run; they supersede earlier pre-reconciliation counts. Exit codes: targeted pytest 0, full pytest 0, ruff check 0, ruff format 0, mypy 0. Semgrep is installed in an isolated venv but **BLOCKED** before any rule executed by Windows Application Control (`WinError 4551` class; no bypass attempted); gitleaks is **VERIFIED** (78 commits scanned, no leaks found). CI for the uncommitted working tree is **NOT VERIFIED**; committed `dcc0509` CI runs succeeded (§12). Status remains `HOLD — NOT CERTIFIABLE` / `NOT READY`.

The two skips are pre-existing platform-related symlink tests; the warning is a pre-existing Starlette/anyio deprecation.

### Principal ratification (2026-11-20)
- **Scope expansion — RATIFIED.** Lakshman Ghosh (Human Sovereign Root) formally ratifies the 12-modified + 1-untracked working-tree scope: `src/astra_coder/rea/{gate,rbac,trust,clock,receipt,__init__}.py`, new `src/astra_coder/rea/enforcement.py`, `src/astra_coder/cli.py`, `src/astra_coder/worker_main.py`, `docs/schemas/authorization-log.schema.json`, `tests/unit/rea/{conftest.py,test_rea_enforcement.py}`, and this report reconciliation (including F-07 gate/CLI/worker wiring).
- **`conftest.py` drift — RATIFIED.** The synthetic `authorization_id`, `artifact_sha256`, and `ASTRA_REA_ENV=test` fixture values in `tests/unit/rea/conftest.py` are formally ratified for test purposes; no production secret, private key, or registry file is embedded in the repository.
- **Expanded current scope — RATIFIED (2026-11-20).** Lakshman Ghosh formally ratifies the expanded tree including `docs/schemas/authorization.schema.json` and `scripts/sign_authorization.py`, plus the authorized R1/R3 updates to `authorization.json` and `rea-input-manifest.json` (16 modified + 1 untracked at execution time; §0B).
- **R1 Option B and R3 baseline — RATIFIED / EXECUTED (2026-11-20).** The `A383F877…` → `0E6E6B02…` transition, external approver `artifact_sha256` rebinding, and `dcc0509` license-file digest rebaselining were authorized and executed (§0B).
- This ratification covers repo-local scope and the explicitly authorized R1/R3 actions. Independent second-party review, uncommitted-tree CI, and final human merge/certification approval remain tracked below and are **NOT** granted by this ratification.

### Residual / still blocked
- **Scope expansion and `conftest.py` drift — RATIFIED (2026-11-20):** the authorizing principal formally ratified the 12-modified + 1-untracked scope expansion and the synthetic conftest fixture drift (see Principal ratification above). This ratification is repo-local only and does **not** certify the tree, approve merge, or substitute for the external steps below.
- **Current-scope ratification — RATIFIED (2026-11-20):** the changes to `docs/schemas/authorization.schema.json` and `scripts/sign_authorization.py`, together with the authorized R1/R3 updates, are covered by the principal ratification (§0B); the tree is 16 modified + 1 untracked. An independent second-party ratification artifact remains **PENDING**.
- Independent second-party human review remains **PENDING**; the Step 3A/4 read-only audit is not a human certification and found unresolved blockers.
- External trusted-key/approver registries are provisioned outside the repo (`C:\Users\User\astra-rea-trust\registry\*`); the approver `artifact_sha256` was rebound to `0e6e6b02…` under R1 Option B (§0B). No registry files or secrets are embedded in the repository.
- Shipped `authorization.json` signing correction was executed under authorized R1 Option B (§0B); the in-repo artifact is now the gate-compatible signed file. Replacing it again would break the external `artifact_sha256` binding.
- Worker gate wiring is unconditional: `worker_main.py` invokes `require_stage05b_execution(...)` as a mandatory pre-execution gate; no `ASTRA_REA_ENFORCE` opt-in flag exists in code.
- Certification remains `HOLD — NOT CERTIFIABLE` pending human authorization.
- Readiness evidence: semgrep **BLOCKED** (Application Control, no bypass); gitleaks **VERIFIED** (78 commits scanned, no leaks found); current-tree CI **NOT VERIFIED**; external registries **PROVISIONED / RATIFIED**; signing evidence **APPLIED (R1 Option B)**; independent review **PENDING**; final human sign-off **PENDING**.

### Human-side external steps (tracked, not performed)
1. **Trusted-key registry:** create an external JSON file outside the repo with shape `{"keys": {"<key_id>": {"public_key_pem": "<PEM>", "status": "ACTIVE", "not_before": "...", "not_after": "..."}}}`, set `ASTRA_REA_TRUSTED_KEYS_PATH` to its absolute path, restrict file permissions to the runtime account, and never commit the file or key material.
2. **Trusted-approver registry:** create a second external JSON file outside the repo with shape `{"approvers": {"<approver_id>": {"role": "HUMAN_APPROVER", "status": "ACTIVE", "allowed_actions": ["RUN_REA_EXECUTION", "APPROVE_STAGE_05B"], "authorization_id": "<id>", "artifact_sha256": "<64 lowercase hex>", "bundle_sha256": "<64 lowercase hex when bundle scope applies>", "not_before": "...", "not_after": "..."}}}`, set `ASTRA_REA_APPROVER_REGISTRY_PATH`, and keep it outside version control.
3. **Sign `authorization.json` outside the repo — SUPERSEDED by authorized R1 Option B (§0B):** the historical guidance not to edit the shipped artifact was replaced by explicit principal authorization on 2026-11-20. The gate-compatible signed artifact (`0E6E6B02…`) was copied byte-for-byte into `<repo_root>/authorization.json`, and the external approver `artifact_sha256` was rebound to that exact digest. The legacy unsigned digest was `A383F8773DEB0CB95474B50A6512CD5F1ED20631BB2CE2FAB57DE3661CDDDA0C`. The authorization schema's optional top-level `signature` block and the signing script were ratified with the expanded scope (§0B).
4. **Independent assurance:** obtain independent scanner/CI evidence for `dcc0509` plus the uncommitted tree (gitleaks and a working semgrep invocation), then obtain final human merge/certification approval. Until then, status remains `HOLD — NOT CERTIFIABLE`.

---

## 0. Baseline (before any modification)

| Item | Value |
|---|---|
| HEAD | `9f987ffe27a6bc48a43af75f3f3f676608373aa7` |
| Working tree | clean |
| Protected `reports/worker-smoke.json` SHA-256 | `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` — verified OK |
| PR #11 (`feat/05b-rea`) | OPEN |
| PR #17 (`docs/stage05b-closure-report`) | OPEN |
| PR #16 merge | `f6e1ba4` present in history |
| Full suite (baseline) | 401 passed, 2 skipped |
| REA enforcement tests (baseline) | 3 passed, 0 skipped |
| Environment | Python 3.12.8; ruff 0.9.7; mypy 1.15.0; pytest 8.3.4; semgrep 1.181.0; cryptography 50.0.2; jsonschema 4.26.0 |

---

## 1. Findings and root causes

| ID | Root cause | Fix |
|---|---|---|
| F-R1-01 (expiry location) | Gate read root-level `expires_at_utc`; shipped `authorization.json` stores expiry only under nested `authorization.expires_at_utc` per `docs/schemas/authorization.schema.json` | `_resolve_expiry()` in `gate.py`: canonical = nested `authorization.expires_at_utc`; root-level never a source of truth; both present must parse strictly and denote the same instant or deny "conflicting" |
| F-R1-02 (expiry parsing) | Missing/malformed/naive expiry could be skipped (`expires_dt is None` short-circuited) | Missing, non-string, malformed, empty, or timezone-naive expiry → deny. Naive timestamps never coerced to UTC. Boundary: expired iff `now > expires` (inclusive of the expiry instant itself) |
| F-R1-03 (signature robustness) | Single `except (InvalidSignature, ValueError, Exception)` swallowed all exceptions without distinguishing; no guaranteed fail-closed on unexpected defects | `_verify_r1_signature()`: `InvalidSignature` → deny; `(ValueError, TypeError)` (includes `binascii.Error`) → deny with type name; broad `Exception` → deny as "unexpected". All paths fail closed |
| F-R3-01 (path containment) | `(root / rel).resolve()` followed by `exists()`/`is_file()` with no containment check; parent traversal, absolute external paths, and symlink/junction escapes could reach files outside the repo | `_resolve_contained_file()`: resolve (symlink-following), require `resolved.is_relative_to(root)`, require regular file; deny traversal/absolute/escaping links. Race caveat documented in docstring (not claimed race-free) |
| F-R3-02 (hash strictness) | `expected_sha.lower()` normalized arbitrary input (uppercase hex, etc.) accepted | `_strict_sha256()`: exact fullmatch `[0-9a-f]{64}`; no normalization of expected hash |
| F-LOG-01 (chain verification) | `append_audit_event` loaded events, appended, wrote — never verified existing chain; stored `event_sha256` could be wrong and would be chained over | `verify_event_chain()` public: structure, enums, unique ids, genesis null `previous_event_hash`, strict 64-hex stored hash, recompute-and-compare. Full existing chain verified **before** any write; candidate chain verified before write; any defect raises `ValueError`, file untouched |
| F-LOG-02 (integrity metadata) | `integrity.verified: true` written unconditionally | `verified: true` only set after the complete chain (including the new event) passes `verify_event_chain()` |
| F-LOG-03 (atomicity) | `target.write_text(...)` non-atomic; partial write could corrupt log | `_atomic_write_json()`: temp file + `flush` + `os.fsync` + `os.replace` (atomic same-filesystem). Full-document re-serialization — **not** claimed as byte-level append-only |
| F-RBAC-01 (gate-level gap) | `enforce_rea_gate` called `evaluate_rbac` without `approver_id`/`self_certified`; gate could not express self-certification denial at gate level | `enforce_rea_gate(approver_id=..., self_certified=...)` keyword params propagated to `evaluate_rbac` |
| F-RBAC-02 (missing approver) | EXECUTOR/AGENT could run `RUN_REA_EXECUTION`/`APPROVE_STAGE_05B` with empty `approver_id` (no independent-approver requirement) | New rule in `evaluate_rbac` after self-certify/same-actor checks: EXECUTOR/AGENT + `{APPROVE_STAGE_05B, RUN_REA_EXECUTION}` + blank `approver_id` → deny |
| Malformed-input fail-closed | `json.loads` unguarded (crash on invalid JSON / non-object root); `result`/`evidence` assumed dicts; `inputs` assumed list; input entries assumed dicts | `_load_json_object()` category errors (unreadable / invalid JSON / non-object root) → deny with reason; `isinstance` guards on `result`, `evidence`, `inputs`, input entries; manifest reference blocks must be objects; all failures deny and append reasons |

Note: this historical table swaps the `F-R1-01` / `F-R1-02` definitions relative to `stage05b-readonly-audit-findings.md`. The principal-defined IDs `F-03A` / `F-03B` / `F-09` / `F-07` are **not pre-existing repository IDs**; they were defined for review by the authorizing principal. Their mapping, provenance, and current code evidence are in §0A, together with audit-log v1.0.0/v1.1.0 and `T-LOG-B` reconciliation.

---

## 2. Files changed (measured scope)

Committed on the branch: `main...dcc0509` (merge-base `f6e1ba4`) = **18 files, +2397/−168**; direct commit `dcc0509` = **12 files, +1052/−231**. The historical `aa064b4` figure of "5 files, +963/−64" is **superseded** and no longer describes this branch.

| File | Status | Role |
|---|---|---|
| `docs/schemas/authorization-log.schema.json` | M | Version enum 1.0.0/1.1.0, lowercase-hex patterns, new required event fields, compatibility description |
| `docs/templates/authorization-log.template.json` | M | Bumped to 1.1.0 with new fields |
| `reports/stage05b-readonly-audit-findings.md` | A | Audit findings register |
| `reports/stage05b-adversarial-test-spec.md` | A | Earlier test spec |
| `reports/stage05b-adversarial-test-spec-detailed.md` | A | Detailed 15-test spec |
| `reports/stage05b-closure-report.md` | A | Closure report |
| `reports/stage05b-security-hardening-report.md` | A | Hardening / self-review report |
| `src/astra_coder/license/verify_digest.py` | M | `parse_sha256_hex`; removal of strip/lower normalization |
| `src/astra_coder/rea/__init__.py` | M | Export `verify_event_chain` |
| `src/astra_coder/rea/clock.py` | A | `resolve_clock`, test-clock gate, skew policy |
| `src/astra_coder/rea/filelock.py` | A | Cross-platform exclusive lock (msvcrt/fcntl) |
| `src/astra_coder/rea/gate.py` | M | Expiry resolution, signature verification, containment, strict hashes, scope checks |
| `src/astra_coder/rea/rbac.py` | M | Trusted-approver validation, OPERATOR in approval-required roles |
| `src/astra_coder/rea/receipt.py` | M | Chain verification, idempotency/sequence, atomic write |
| `src/astra_coder/rea/trust.py` | A | Env-var trusted key + approver registries, binding checks |
| `src/astra_coder/rea/validation.py` | A | Strict UTC parsing, strict SHA-256 |
| `tests/unit/rea/conftest.py` | A | Autouse fixture: test clock + synthetic trust registries |
| `tests/unit/rea/test_rea_enforcement.py` | M | 15 mandatory adversarial tests + malformed/trust/idempotency/concurrency suites |

Uncommitted working-tree remediation (present locally, **not committed**; the expanded scope — including the two additional files — and `conftest.py` drift were formally ratified on 2026-11-20 per §0B): `gate.py`, `rbac.py`, `trust.py`, `clock.py`, `receipt.py`, new `src/astra_coder/rea/enforcement.py`, `cli.py` (`rea-gate`), `worker_main.py` (unconditional `require_stage05b_execution(...)` gate), `docs/schemas/authorization-log.schema.json` description, `docs/schemas/authorization.schema.json` (optional top-level `signature`), `scripts/sign_authorization.py` (gate-compatible canonical payload), REA tests, and this report. `authorization.json` and `rea-input-manifest.json` were updated under authorized R1 Option B / R3 baseline (§0B); `worker-smoke.json` was not modified. `.security-venv-win/` is git-ignored and not committed.

---

## 3. Before/after security behavior

| Scenario | Before | After |
|---|---|---|
| Nested `authorization.expires_at_utc` only (shipped artifact shape) | Silently skipped expiry check (`expires_dt is None` → not expired) — **fail-open** | Canonical expiry enforced; missing/malformed → deny |
| Naive timestamp `2026-11-20T12:00:00` | Coerced to UTC (`replace(tzinfo=UTC)`) | Deny (ambiguous) |
| Expiry present + `now == expires` | Not expired | Not expired (boundary unchanged, now explicitly tested) |
| Malformed base64 signature | Caught by generic `Exception` | Distinguishable deny with type name; all paths deny |
| Manifest path `../../etc/passwd` with correct hash | Resolved and hashed if file existed outside repo | Deny: escapes repository root |
| Absolute external path with correct hash | Accepted if file readable | Deny: escapes repository root |
| Symlink/junction to outside with correct hash | Followed silently | Deny: resolved path outside root |
| Expected hash `ABCDEF...` (uppercase) | Lowercased and compared — accepted | Deny: not strict lowercase 64-hex |
| Tampered audit history | Loaded, chained over, written; `verified: true` written | `ValueError` before write; file byte-identical |
| Existing log with wrong stored `event_sha256` | Chained over silently | `ValueError` before write |
| EXECUTOR/AGENT, no approver_id, gate-level | RBAC allowed (no approver context) | Deny: independent approver required |
| Gate-level self-certification | Could not be expressed | Denied via `self_certified=True` / empty `approver_id` propagation |
| Invalid JSON / non-object root in any input | Unhandled exception (crash) | Category deny with reason; gate returns `allowed=False` with blocking reason |

---

## 4. Test IDs and results (REA enforcement file)

Historical `aa064b4` claim: `python -m pytest tests/unit/rea/test_rea_enforcement.py -p no:cacheprovider -q` → **55 passed, 0 skipped** — **CLAIMED / NOT VERIFIED** for current HEAD.

Current working tree (measured, see §0A): `python -m pytest tests/unit/rea/test_rea_enforcement.py -p no:cacheprovider --override-ini addopts="--strict-markers" -q` → **88 passed** — **PASS**.

Mandatory 15 — all present in the diff. The PASS labels in the table below are historical `aa064b4` results (**CLAIMED / NOT VERIFIED**); current execution status is **PASS** per the measured targeted run above.

| ID | Test | Result |
|---|---|---|
| T-R1-A | `test_t_r1_a_missing_expiry_denies_gate` | PASS |
| T-R1-B | `test_t_r1_b_malformed_expiry_denies_gate` (parametrized: garbage, empty, non-string, naive datetime, invalid calendar) | PASS |
| T-R1-C | `test_t_r1_c_expired_authorization_denies_gate` | PASS |
| T-R1-D | `test_t_r1_d_nested_shipped_expiry_resolves` (extracts nested expiry from shipped shape; records signature-block limitation) | PASS |
| T-R1-E | `test_t_r1_e_conflicting_expiry_locations_denies_gate` | PASS |
| T-R1-F | `test_t_r1_f_expiry_boundary_is_inclusive` (`now == expires` passes; `now > expires` denies) | PASS |
| T-R3-A | `test_t_r3_a_parent_traversal_denied_with_correct_hash` (`../../`) | PASS |
| T-R3-B | `test_t_r3_b_absolute_external_path_denied_with_correct_hash` | PASS |
| T-R3-C | `test_t_r3_c_symlink_escape_denied_with_correct_hash` (junction fallback locally; see §8) | PASS |
| T-LOG-A | `test_t_log_a_tampered_history_rejected_and_file_unchanged` (bytes unchanged) | PASS |
| T-LOG-B | `test_t_log_b_prior_events_preserved_on_append` | PASS |
| T-R2-A | `test_t_r2_a_missing_license_status_denies_gate` | PASS |
| T-R2-B | `test_t_r2_b_missing_stage_approval_denies_gate` | PASS |
| T-R2-C | `test_t_r2_c_deny_decision_denies_gate` | PASS |
| T-R2-D | `test_t_r2_d_escalate_decision_denies_gate` | PASS |
| T-RBAC-A | `test_t_rbac_a_same_actor_approver_denied_via_gate` | PASS |
| T-RBAC-B | `test_t_rbac_b_gate_level_self_certification_denied` (EXECUTOR, AGENT, empty approver) | PASS |

Additional malformed-input tests (all passed): invalid gate JSON, invalid license result type, manifest non-object refs, manifest `inputs` type, manifest input entry non-object, non-string input path, uppercase manifest hash, non-object manifest input, malformed evidence type, 10 audit-log tamper variants (missing fields, duplicate ids, broken link, non-object event, non-list root, wrong genesis, invalid enums, invalid stored hash format, recomputed-hash mismatch), plus original 3 regression tests (`test_rea_gate_blocks_without_valid_signature`, RBAC matrix, receipt schema) — historical **55 total, 0 skipped** (**CLAIMED**); current measured **88 passed** (**PASS**).

---

## 5. Full-suite results

Historical `aa064b4` claim: `python -m pytest -p no:cacheprovider -q` → **453 passed, 2 skipped, 1 warning** (58.12s) — **CLAIMED / NOT VERIFIED** for current HEAD.

Current working tree (measured, see §0A): `python -m pytest -p no:cacheprovider --override-ini addopts="--strict-markers" -q` → **486 passed, 2 skipped, 1 warning** — **PASS**.

Skips (pre-existing, unchanged from baseline, platform-related):
- `tests/test_docker_tools.py:411` — symlinks unavailable on this filesystem
- `tests/test_tools.py:53` — symlinks unavailable on this filesystem

No failures. Warning count unchanged from baseline behavior (pytest config-level, pre-existing).

---

## 6. Static and security checks

| Check | Command | Historical `aa064b4` claim | Current working tree (§0A) |
|---|---|---|---|
| Ruff lint | `python -m ruff check --no-cache src tests` | All checks passed — **CLAIMED** | **All checks passed! — PASS** |
| Ruff format | `python -m ruff format --check --no-cache src tests` | 66 files — **CLAIMED** | **72 files already formatted — PASS** |
| Mypy | `python -m mypy --cache-dir=/tmp/mypy src` | 38 source files — **CLAIMED** | **Success: no issues found in 43 source files — PASS** |
| Semgrep | `semgrep --config semgrep.yml --error --metrics=off --disable-version-check --include "*.py" src tests scripts demo` | 5 rules / 70 files / 0 findings — **CLAIMED** | **BLOCKED** — installed, exited 1 before scanning (`ImportError: _ExtendedAttributes`; re-run: Application Control `WinError 4551`) |
| Gitleaks | `.tools/gitleaks.exe/gitleaks.exe` v8.30.1 (`gitleaks git --no-banner --verbose`) | green — **CLAIMED** | **VERIFIED (2026-11-20)** — 78 commits scanned, no leaks found, exit 0 (§0B) |

Notes below describe the historical `aa064b4` environment and are retained only as context.

Notes:
- `make` is unavailable on Windows; underlying commands from `Makefile`/`.github/workflows/ci.yml` were run directly (equivalent invocation; documented substitution).
- `semgrep.exe`/`pysemgrep.exe` blocked by Windows Application Control (exit 2); `python -m semgrep` deprecated (exit 2). Ran via repo-ignored `.security-venv-win/` venv using the in-process `semgrep.console_scripts.pysemgrep` entrypoint — same rules, same file set, result matches CI's documented 0-finding expectation.
- Env note: a `security-requirements.lock` install briefly drifted pins (jsonschema/pydantic/starlette); re-pinned to 4.26.0/2.10.6/0.41.3 matching `requirements.lock` before running checks.

---

## 7. Schema compatibility

Ad-hoc read-only validation (`jsonschema.Draft202012Validator`):

| Artifact | Schema | Result |
|---|---|---|
| `authorization.json` | `docs/schemas/authorization.schema.json` | VALID |
| `license-check.json` | `docs/schemas/license-check.schema.json` | VALID |
| `rea-input-manifest.json` | `docs/schemas/rea-input-manifest.schema.json` | VALID |

Runtime-generated receipts and audit logs are validated against `execution-receipt.schema.json` and `authorization-log.schema.json` inside the test suite (existing schema tests + new append tests — all passing).

Runtime-vs-schema notes:
- Runtime audit-log verification is **stricter** than schema (schema still permits `event_sha256: null`; runtime requires strict lowercase 64-hex) — runtime is the fail-closed enforcement layer.
- **Schema files WERE modified** in `main...dcc0509` (`authorization-log.schema.json`, `authorization-log.template.json`): version enum 1.0.0/1.1.0, lowercase-hex patterns, new required fields `sequence`/`idempotency_key`/`operation_id`, plus a compatibility description. The earlier "schema files were not modified (frozen boundary)" statement is **FALSE / SUPERSEDED**.
- v1.0.0 vs v1.1.0: `verify_event_chain(..., schema_version=...)` verifies v1.0.0 records using legacy required keys; appending requires 1.1.0 and explicitly rejects other versions — no silent version contradiction. §13.15 is updated accordingly.
- Gate canonical expiry location matches the schema's nested `authorization.expires_at_utc` definition.

---

## 8. Shipped artifact compatibility (R1)

Shipped `authorization.json` contains:
- `authorization.expires_at_utc` (nested, schema-canonical) — **now enforced** as the expiry source of truth (T-R1-D).
- `cryptographic_proof.signature` (hex) + `signed_payload_sha256` + `verification_method: "local-ed25519-key"` — structurally **not** the gate's expected top-level `signature.signature_base64` (base64 Ed25519 over canonical JSON of all other fields).
- No `*.pem`/`*.pub` public key exists in the repository; no in-repo code references `cryptographic_proof` (grep: 0 hits).

Consequence (historical, as originally shipped — superseded by §0B): the unsigned artifact **could not** pass gate R1 signature verification — the gate denied (fail-closed), which was the correct behavior for an unverifiable signature. T-R1-D records this limitation; no signature was fabricated at that time. Under authorized R1 Option B (§0B) the in-repo artifact was replaced with the verified signed artifact.

Candidate correction — **EXECUTED under authorized R1 Option B (2026-11-20; §0B):** the gate-compatible top-level `signature` block (Ed25519 over canonical JSON of all other fields, base64) and trusted public key were supplied by the out-of-repo signed artifact and `trusted-keys.json`. The authorization schema permits this optional block (reconciliation below); the current in-repo artifact digest is `0E6E6B02…`.

**Contract reconciliation (current tree; re-audited read-only):**
- `docs/schemas/authorization.schema.json` now defines an optional top-level `signature` object (`:177-200`) with required non-empty `key_id` and base64 `signature_base64` (optional `algorithm: Ed25519`), while retaining root `additionalProperties: false` (`:444`) and all existing required fields/enums. `signature` is not in the root `required` list (`:261-269`), so the shipped unsigned artifact still validates. This change is uncommitted but the expanded scope was formally ratified on 2026-11-20 (§0B).
- `scripts/validate_r1_r3.py:13-16` performs JSON Schema validation only; it does not cryptographically verify the gate signature, but the updated schema now accepts a top-level `signature` block (verified in-memory: shipped and synthetic signed artifacts both VALID).
- `scripts/sign_authorization.py:44-68,108-113` is now gate-compatible: it computes canonical bytes over all top-level fields except `signature` with `sort_keys=True`, `separators=(",", ":")`, UTF-8 — byte-identical to `gate.py:183-184` — signs with Ed25519, writes base64 `signature_base64` plus `key_id`, requires `APPROVED` status (matching `gate.py:205-220`), and refuses to overwrite the shipped `authorization.json` (`:99-100`). No private key is embedded.
- The gate-compatible signed artifact and signing evidence were applied in-repo under authorized R1 Option B (§0B); the external approver binding was rebound to the exact signed digest.

---

## 9. Protected artifact

`reports/worker-smoke.json` SHA-256 re-verified after all changes:
`3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` — **UNCHANGED / OK**.

---

## 10. Known limitations (cannot be solved without external trusted identity/approval authority)

1. **Approver identity is caller-asserted; registry binding mitigates but does not authenticate.** `approver_id` remains a plain parameter, but it must match an entry in the external trusted-approver registry (status ACTIVE, role HUMAN_APPROVER, `allowed_actions`, validity window). The production helper `require_stage05b_execution` additionally requires registry `authorization_id`/`artifact_sha256` bindings. The gate does not cryptographically bind the R1 signer to that human identity; authentication remains an external authority. Self-certification and same-actor checks are enforced for EXECUTOR, AGENT, and OPERATOR.
2. **Containment is not race-free.** A swap of a path between `_resolve_contained_file` resolution and the subsequent read is not detected (documented in code). Full TOCTOU elimination requires OS-level primitives (e.g., `O_NOFOLLOW`/handle-based opens) not available portably here.
3. **Symlink test on Windows:** `symlink()` requires `SeCreateSymbolicLinkPrivilege` (WinError 1314 unavailable here); the test falls back to `_winapi.CreateJunction` (verified working; `resolve()` follows reparse points, same escape semantics). True-symlink creation will run on Linux CI. Test skips only if both mechanisms fail (did not skip locally).
4. **Audit log is logically append-only, not whole-file byte-level append-only.** Writes re-serialize the full document via atomic replace; prior event objects and verified hashes are preserved unchanged. `T-LOG-B` now verifies raw bytes of each prior event object across append (in addition to parsed objects and chain integrity). Whole-file byte immutability would require an external write-once store.
5. **Shipped R1 signature block is now verifiable (R1 Option B, §0B)** — the gate-compatible signed artifact, external trusted key (`ASTRA_REA_TRUSTED_KEYS_PATH` registry), and approver binding were provisioned; verification requires the external trusted-key registry, not a standalone in-repo key. The legacy unverifiable state is historical.
6. **Independent second-party human review remains PENDING** — the Step 3A/4 read-only audit is not a human certification (Section 9 below remains an implementer self-review).
7. **No CI evidence for the uncommitted tree** — committed `dcc0509` runs `44630356731` (push) / `44630364224` (pull_request) both completed successfully (**VERIFIED** via read-only `gh run list`); historical runs `44603216332` / `44603313408` correspond to `aa064b4` and are **CLAIMED / SUPERSEDED**. No CI run covers the uncommitted remediation; nothing was pushed by this work.

---

## 11. Residual risks

| Risk | Status |
|---|---|
| Unauthenticated `approver_id` spoofing by a compromised local process | Accepted, documented (§10.1); requires external identity authority |
| TOCTOU path swap | Accepted, documented (§10.2); low practical exposure in offline CLI context |
| Gate denial of unsigned artifact | Historical fail-closed behavior; resolved by authorized R1 Option B (§0B) |
| Schema permits looser values than runtime enforces | Accepted; runtime stricter; schema permits optional top-level `signature` (uncommitted; scope ratified 2026-11-20, §0B) |
| Pre-existing platform skips (2) | Unchanged from baseline; not related to hardening |

---

## 12. Commit / CI status

| Item | Status |
|---|---|
| Branch / verified HEAD | `fix/stage05b-security-hardening` @ `dcc0509efb8bbc98d0bb8c844f3e756098293847` — **PASS** |
| Working tree at report time | Not clean: **16 modified tracked files + 1 untracked file** `src/astra_coder/rea/enforcement.py` (uncommitted remediation, including `authorization.json` and `rea-input-manifest.json` after R1/R3) — **DISCLOSURE**, no commit/push performed |
| Historical code commit | `aa064b4` — historical only, **CLAIMED / SUPERSEDED** by HEAD `dcc0509` |
| PR | **#18 OPEN** — https://github.com/lakshmanghosh1900-prog/Astra-Hybrid-Code/pull/18 (base `main`) — untouched |
| CI push run (committed HEAD) | `44630356731` — success (headSha `dcc0509`) — **VERIFIED via `gh run list`**, committed HEAD only |
| CI pull_request run (committed HEAD) | `44630364224` — success (headSha `dcc0509`) — **VERIFIED via `gh run list`**, committed HEAD only |
| Historical CI runs | `44603216332` (push) / `44603313408` (pull_request) — success (headSha `aa064b4`) — **CLAIMED / SUPERSEDED** |
| CI for uncommitted tree | **NOT VERIFIED** — no CI run covers the 16-modified + 1-untracked working tree; gitleaks re-executed locally and **VERIFIED** (78 commits, no leaks; §0B) |
| PR #11 (`feat/05b-rea`) | OPEN (untouched) |
| PR #17 (`docs/stage05b-closure-report`) | OPEN (untouched) |
| Human approval for merge/certification | **PENDING** |
| Independent security review | **PENDING** — Step 3A/4 read-only audit is not a human second-party certification |
| Stage 06 / Worker / REA execution | **NONE performed** |
| Signing human artifacts | **APPLIED (R1 Option B, §0B)** — `authorization.json` = `0E6E6B02…` signed artifact; external approver `artifact_sha256` rebound |
| Destructive git operations | **NONE** |

---

## 13. Section 9 security regression self-review (implementer, not independent)

| # | Question | Verdict | Evidence |
|---|---|---|---|
| 1 | Can missing/malformed expiry pass R1? | **NO** | T-R1-A, T-R1-B; `_resolve_expiry` returns error → `r1_ok=False` (gate.py) |
| 2 | Can expired authorization pass R1? | **NO** | T-R1-C; `expired = now > expiry` forces deny |
| 3 | Can shipped nested expiry be ignored? | **NO** | T-R1-D; canonical = nested only; root never authoritative |
| 4 | Can invalid signature pass? | **NO** | `_verify_r1_signature` all paths deny; T-R1 tests assert no signature-failure compensation; existing `test_rea_gate_blocks_without_valid_signature` |
| 5 | Can `../` escape pass? | **NO** | T-R3-A; `is_relative_to(root)` after resolve |
| 6 | Can absolute external path pass? | **NO** | T-R3-B |
| 7 | Can symlink escape pass? | **PROVEN (junction)** / true symlink pending CI | T-R3-C passed via junction; WinError 1314 documented; Linux CI will exercise true symlink |
| 8 | Can malformed SHA-256 pass? | **NO** | `_strict_sha256` fullmatch; uppercase + garbage tests deny |
| 9 | Can append proceed after tampered history? | **NO** | T-LOG-A (file bytes unchanged) + 10 tamper variants |
| 10 | Can `verified: true` be written without verification? | **NO** | Set only after `verify_event_chain(candidate)`; T-LOG-B asserts |
| 11 | Can EXECUTOR self-certify via gate? | **NO** | T-RBAC-B; rbac.py new rule + gate propagation |
| 12 | Can AGENT approve without human approver? | **NO** | T-RBAC-A, T-RBAC-B; same-actor + missing-approver rules |
| 13 | Can malformed JSON bypass checks? | **NO** | `_load_json_object` category denies; malformed-input tests |
| 14 | Do all failure paths deny? | **YES** | `allowed = all(checks) and len(reasons)==0`; every negative test asserts `allowed is False` + blocking reason |
| 15 | Are historical audit records readable? | **PARTIAL — SUPERSEDED** | v1.0.0 records are verifiable via `verify_event_chain(..., schema_version="1.0.0")` using legacy required keys, but are **not appendable** (explicit rejection). The earlier "old records verify under new checker" claim is **NOT VERIFIED**; no historical log files exist in-repo to test against. |
| 16 | Schema vs runtime consistent? | **YES (with documented strictness)** | §7: schema files **were** modified (version enum, lowercase hex, new required fields); runtime is version-aware and stricter where the schema is permissive; append rejects non-1.1.0 explicitly |
| 17 | New code introduces no regression? | **PASS (measured)** | Current full suite **486 passed, 2 skipped, 1 warning** vs historical claim 453; targeted REA **88 passed**; original 3 REA tests still present and passing |

---

## 14. Certification inputs (for Section 12 decision)

All PROVEN labels in this table are implementer self-review labels inherited from historical `aa064b4` runs and are **CLAIMED / NOT VERIFIED** for current HEAD unless explicitly marked "measured" or "§0A". Only §0A reports execution in the current working tree.

| Acceptance checkbox | Status |
|---|---|
| R1 expiry fail-closed | PROVEN (T-R1-A/B/C/E/F) |
| Shipped nested expiry handled | PROVEN (T-R1-D) |
| Signature robust fail-closed | PROVEN (code + tests) |
| R3 traversal blocked | PROVEN (T-R3-A) |
| Absolute external blocked | PROVEN (T-R3-B) |
| Symlink escape blocked / documented | PROVEN via junction locally; true symlink documented pending CI (§8/§10.3 — platform limitation explicitly documented, per checkbox allowance) |
| SHA-256 strict | PROVEN (uppercase/garbage tests) |
| Audit chain verified before append | PROVEN (code + T-LOG-A) |
| Tampered history rejected | PROVEN (T-LOG-A + 10 variants) |
| Append-only claims accurate | PROVEN (logical append-only; `T-LOG-B` now also asserts raw-byte preservation of each prior event object) |
| Integrity metadata truthful | PROVEN (code + T-LOG-B, measured) |
| Gate-level RBAC gap closed | PROVEN (T-RBAC-B) |
| Same-actor enforced | PROVEN (T-RBAC-A) |
| Malformed inputs fail closed | PROVEN (malformed suite) |
| All 15 adversarial tests pass, 0 skipped | PROVEN (measured: 88 passed targeted, §0A; historical 55 CLAIMED) |
| Existing regression tests pass | PROVEN (original 3 preserved + passing, measured) |
| Full suite passes except justified skips | PROVEN (measured: 486 passed, 2 pre-existing platform skips, 1 warning, §0A) |
| Ruff passes | PROVEN (measured, §0A) |
| Mypy passes | PROVEN (measured, §0A) |
| Semgrep passes | **CLAIMED** (historical `aa064b4` only) / **BLOCKED** for current tree (startup `ImportError: _ExtendedAttributes`; re-run: Application Control `WinError 4551`) |
| Gitleaks passes | **VERIFIED (2026-11-20)** — 78 commits scanned, no leaks found, exit 0 (§0B) |
| Schema compatibility verified | **PASS (in-memory)** — schema permits optional top-level `signature`; sign script canonical bytes match `gate.py` (§8). Scope ratification and signing evidence **RATIFIED / APPLIED (§0B)** |
| Protected SHA unchanged | PROVEN (§9) |
| Independent security review completed | **PENDING** — Step 3A/4 read-only audit is not a human second-party certification |
| CI evidence available | **VERIFIED** for committed `dcc0509` (`44630356731` push, `44630364224` pull_request, both success) / **NOT VERIFIED** for the uncommitted working tree |
| No unauthorized Stage 06/Worker/REA execution | PROVEN (none occurred) |
| Human approval for final merge/certification | **PENDING** (not yet given) |

**Result (superseded):** the historical "24 of 26 PROVEN" tally is **CLAIMED / SUPERSEDED** by §0A/§0B. Status remains **HOLD — NOT CERTIFIABLE / NOT READY**: independent second-party review and final explicit human approval are outstanding, and no CI run covers the uncommitted remediation (committed `dcc0509` CI runs succeeded but do not verify the working tree).

**Next action:** obtain an independent second-party security review of PR #18 (including the uncommitted remediation), then the human operator makes the merge/certification decision (PR #11 and #17 remain open and are not part of this merge).
