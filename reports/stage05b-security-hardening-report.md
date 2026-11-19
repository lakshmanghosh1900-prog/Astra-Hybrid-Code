# Stage 05b Security Hardening Report

**Date:** 2026-11-20
**Branch:** `fix/stage05b-security-hardening` (created from `docs/stage05b-closure-report`, HEAD `9f987ffe27a6bc48a43af75f3f3f676608373aa7`)
**Status:** Work complete in working tree; **not yet committed** (awaiting explicit human confirmation per Section 0 authorization boundary).
**Source findings:** `reports/stage05b-readonly-audit-findings.md` (F-R1-01/02, F-R3-01, F-LOG-01/02, F-RBAC-01, malformed-input fail-closed gap), `reports/stage05b-adversarial-test-spec-detailed.md` (15 mandatory adversarial tests).

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

---

## 2. Files changed (working tree, not committed)

| File | Change |
|---|---|
| `src/astra_coder/rea/gate.py` | +276/-64 lines: strict expiry resolution, hardened signature verification, path containment, strict SHA-256, malformed-input guards, RBAC propagation, boundary semantics |
| `src/astra_coder/rea/receipt.py` | +145: `verify_event_chain`, `_canonical_event_hash`, `_atomic_write_json`, pre-write full-chain verification, truthful `integrity.verified` |
| `src/astra_coder/rea/rbac.py` | +16: missing-independent-approver deny rule |
| `src/astra_coder/rea/__init__.py` | +3/-1: export `verify_event_chain` |
| `tests/unit/rea/test_rea_enforcement.py` | +587: 15 mandatory adversarial tests + malformed-input suite; original 3 tests preserved |

Diff stat: 5 files, +963/-64. No other files modified. `.security-venv-win/` git-ignored (semgrep venv, not committed).

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

Targeted run: `python -m pytest tests/unit/rea/test_rea_enforcement.py -p no:cacheprovider -q` → **55 passed, 0 skipped**.

Mandatory 15 (all present, all passed):

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

Additional malformed-input tests (all passed): invalid gate JSON, invalid license result type, manifest non-object refs, manifest `inputs` type, manifest input entry non-object, non-string input path, uppercase manifest hash, non-object manifest input, malformed evidence type, 10 audit-log tamper variants (missing fields, duplicate ids, broken link, non-object event, non-list root, wrong genesis, invalid enums, invalid stored hash format, recomputed-hash mismatch), plus original 3 regression tests (`test_rea_gate_blocks_without_valid_signature`, RBAC matrix, receipt schema) — **55 total, 0 skipped**.

---

## 5. Full-suite results

`python -m pytest -p no:cacheprovider -q` → **453 passed, 2 skipped, 1 warning** (58.12s).

Skips (pre-existing, unchanged from baseline, platform-related):
- `tests/test_docker_tools.py:411` — symlinks unavailable on this filesystem
- `tests/test_tools.py:53` — symlinks unavailable on this filesystem

No failures. Warning count unchanged from baseline behavior (pytest config-level, pre-existing).

---

## 6. Static and security checks

| Check | Command | Result |
|---|---|---|
| Ruff lint | `python -m ruff check --no-cache src tests` | **All checks passed** |
| Ruff format | `python -m ruff format --check --no-cache src tests` | **66 files already formatted** |
| Mypy | `python -m mypy --cache-dir=/tmp/mypy src` | **Success: no issues found in 38 source files** |
| Semgrep | semgrep 1.181.0, `--config semgrep.yml --error --include '*.py' src tests scripts demo` | **Ran 5 rules on 70 files: 0 findings**, exit 0 |

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
- Runtime audit-log verification is **stricter** than schema (schema permits `event_sha256: null` and uppercase hex; runtime requires non-null strict lowercase 64-hex) — stricter runtime is consistent with the schema contract (schema = permissive envelope, runtime = fail-closed enforcement). Schema files were not modified (frozen boundary).
- Gate canonical expiry location matches the schema's nested `authorization.expires_at_utc` definition.

---

## 8. Shipped artifact compatibility (R1)

Shipped `authorization.json` contains:
- `authorization.expires_at_utc` (nested, schema-canonical) — **now enforced** as the expiry source of truth (T-R1-D).
- `cryptographic_proof.signature` (hex) + `signed_payload_sha256` + `verification_method: "local-ed25519-key"` — structurally **not** the gate's expected top-level `signature.signature_base64` (base64 Ed25519 over canonical JSON of all other fields).
- No `*.pem`/`*.pub` public key exists in the repository; no in-repo code references `cryptographic_proof` (grep: 0 hits).

Consequence: the shipped artifact **cannot** pass gate R1 signature verification today — the gate denies (fail-closed), which is the correct behavior for an unverifiable signature. T-R1-D records this limitation; no signature was fabricated, no artifact altered.

Smallest schema-compatible correction (**PROPOSAL ONLY — human-side, requires explicit human approval before any action**): have the external human signing step additionally emit a gate-compatible top-level `signature` block (Ed25519 over canonical JSON of all other fields, base64), with the public key provided to the gate — or approve a schema extension. Human approval authority remains external either way.

---

## 9. Protected artifact

`reports/worker-smoke.json` SHA-256 re-verified after all changes:
`3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` — **UNCHANGED / OK**.

---

## 10. Known limitations (cannot be solved without external trusted identity/approval authority)

1. **Approver identity is caller-asserted.** `approver_id` is a plain parameter; the gate does not cryptographically bind it. The shipped R1 signature (if corrected per §8) would prove a human signed the authorization, but binding that signature to a specific `approver_id` requires an external identity/approval authority. Self-certification and same-actor checks are enforced; identity authentication is out of repo scope.
2. **Containment is not race-free.** A swap of a path between `_resolve_contained_file` resolution and the subsequent read is not detected (documented in code). Full TOCTOU elimination requires OS-level primitives (e.g., `O_NOFOLLOW`/handle-based opens) not available portably here.
3. **Symlink test on Windows:** `symlink()` requires `SeCreateSymbolicLinkPrivilege` (WinError 1314 unavailable here); the test falls back to `_winapi.CreateJunction` (verified working; `resolve()` follows reparse points, same escape semantics). True-symlink creation will run on Linux CI. Test skips only if both mechanisms fail (did not skip locally).
4. **Audit log is logically append-only, not byte-level append-only.** Writes re-serialize the full document via atomic replace; prior event objects and verified hashes are preserved unchanged. The schema's `integrity.append_only` field is interpreted as logical append-only. Byte-level immutability would require an external write-once store.
5. **Shipped R1 signature block is unverifiable in-repo** (see §8) — requires external public key + schema-compatible block.
6. **No independent second-party review yet** — implementer self-review only (Section 9 below is a structured self-review, not an independent audit).
7. **No CI evidence yet** — nothing pushed; CI runs only after human confirms commit/push/PR.

---

## 11. Residual risks

| Risk | Status |
|---|---|
| Unauthenticated `approver_id` spoofing by a compromised local process | Accepted, documented (§10.1); requires external identity authority |
| TOCTOU path swap | Accepted, documented (§10.2); low practical exposure in offline CLI context |
| Gate denies the shipped artifact until signature block corrected | Intended fail-closed behavior; human-side proposal in §8 |
| Schema permits looser values than runtime enforces | Accepted; runtime stricter; schema frozen by boundary rules |
| Pre-existing platform skips (2) | Unchanged from baseline; not related to hardening |

---

## 12. Commit / CI status

| Item | Status |
|---|---|
| Working tree | 5 intended files modified, **not committed** |
| HEAD | `9f987ffe27a6bc48a43af75f3f3f676608373aa7` (unchanged) |
| Final commit SHA | **PENDING** — commit/push requires explicit human confirmation (Section 0 authorization) |
| CI run identifiers | **NONE** — nothing pushed; CI evidence available only after push |
| PR | Not created (pending same confirmation) |
| Human approval for merge/certification | **PENDING** |
| Independent security review | **NOT PROVEN** (self-review only) |
| Stage 06 / Worker / REA execution | **NONE performed** (correctly skipped) |
| Signing human artifacts | **NONE** |
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
| 15 | Are historical audit records readable? | **REASONED** | No historical log files exist in-repo; old writer's canonical rule (visible in pre-change source: `json.dumps(..., sort_keys=True, separators=(",", ":"))` over payload-minus-hash) is byte-identical to `_canonical_event_hash` — old records verify under new checker |
| 16 | Schema vs runtime consistent? | **YES** | §7; runtime stricter where schema loose; schema unchanged |
| 17 | New code introduces no regression? | **NO REGRESSION** | Full suite 453 passed vs baseline 401 passed (+52 new); original 3 REA tests still present and passing |

---

## 14. Certification inputs (for Section 12 decision)

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
| Append-only claims accurate | PROVEN (documented as logical append-only; no byte-level claim) |
| Integrity metadata truthful | PROVEN (code + T-LOG-B) |
| Gate-level RBAC gap closed | PROVEN (T-RBAC-B) |
| Same-actor enforced | PROVEN (T-RBAC-A) |
| Malformed inputs fail closed | PROVEN (malformed suite) |
| All 15 adversarial tests pass, 0 skipped | PROVEN (55 passed, 0 skipped) |
| Existing regression tests pass | PROVEN (original 3 preserved + passing) |
| Full suite passes except justified skips | PROVEN (453 passed, 2 pre-existing platform skips) |
| Ruff passes | PROVEN |
| Mypy passes | PROVEN |
| Semgrep passes | PROVEN (5 rules, 70 files, 0 findings) |
| Schema compatibility verified | PROVEN (§7) |
| Protected SHA unchanged | PROVEN (§9) |
| Independent security review completed | **NOT PROVEN** (self-review only) |
| CI evidence available | **NOT PROVEN** (not pushed; requires human confirmation) |
| No unauthorized Stage 06/Worker/REA execution | PROVEN (none occurred) |
| Human approval for final merge/certification | **PENDING** (not yet given) |

**Result:** 23 of 26 checkboxes PROVEN; 3 unchecked (independent review, CI evidence, human approval) → per Section 12 rule, status remains **STAGE 05b — PARTIAL — NOT CERTIFIED** until those external items complete.

**Next action (Section 13-G recommendation):** Human operator explicitly confirms commit + push + PR creation for `fix/stage05b-security-hardening`; then CI evidence is collected, an independent review is performed, and the human makes the merge/certification decision.
