# Stage 07 Phase 2 implementation and independent review package

## A. Identity

Repository: C:/Users/User/Desktop/ASTRA CODER.
Branch: feat/stage07-phase2-enterprise-hybrid-wiring.
Baseline and unchanged HEAD: 39a9a732ecc87244496c023e4be17074018303a3.
Phase 1 merge PR #30 verified. No push or merge performed.
No follow-up commit while the directory-wide security gate remains HOLD.

## B. Changes

- src/astra_coder/config.py: environment-loaded planner/Codex/Claude models and
  compatible Claude endpoint/key; configured secrets included in redaction.
- src/astra_coder/hybrid_routing.py: one registry per role, existing BudgetRunner,
  ModelGateway, NetworkAuthorizer, policy and usage ledger integration. Server-error
  retries only; circuit isolation and HTTP timeouts bounded by remaining budget.
- src/astra_coder/hybrid_approval.py: signed approval envelope and human-ratified
  external approval_signing_key_ids mapping, existing REA trust checks, locked
  external single-use authorization/nonce journal. No real keys provisioned.
- src/astra_coder/hybrid_enterprise.py: governed entry point, existing REA executor,
  lifecycle events, Docker-only verification, rollback on post-apply failure.
- src/astra_coder/hybrid_skill.py: flushed same-directory atomic replacement.
- tests/unit/test_stage07_enterprise.py: 32 permanent Phase 2 tests.
- docs/schemas/stage07-approval-envelope.schema.json and
  docs/schemas/stage07-execution-report.schema.json: generated contract schemas.
- docs/design/stage07-hybrid-rea-skill.md: Phase 2 architecture, configuration,
  approved-diff workflow, registry/store boundaries, limits and review status.
- reports/stage07-phase2-review.md: this review package.

## C. Provider and gateway evidence

Existing HTTP transport is invoked through BudgetRunner and ModelGateway, never a
raw HTTP bypass. HTTPS compatible endpoint/model/key must be explicitly configured
for each role. No cross-role fallback. Claude native Messages is not implemented;
an explicitly configured compatible endpoint is required. Model identities and
live providers were not externally verified or called. Tests use MockTransport.
Missing network/remote approval, credentials/config, exhausted token budget or
kill switch deny before network. Only server errors retry (at most 3 attempts);
401/403/429 do not retry. Circuit and expired deadline tests pass. Successful
usage is recorded by the existing ledger. Configured secrets are redacted.

## D. Approval and REA evidence

Option A is implemented alongside unchanged REA trust. Ed25519 envelope signature,
explicit single-human key ownership, active key and approver, expiry, plan/patch
digests, target path and no self-approval are checked. Missing/ambiguous mapping
denies. External authorization ID and nonce journal prevents re-consumption.
The journal must be human/host-provisioned and protected from rollback; no model
or production code provisions human keys or approvals. Signed test keys stay in
memory; external pytest temporary directories contain fixture public registries.

End-to-end test uses real signed R1/R2/R3, real EXECUTOR RBAC, trusted approver,
scope binding, atomic patch application and hash-chained lifecycle receipts.
Only HTTP/container transports are stubbed, not REA enforcement or signature
verification. Docker transport test asserts network disabled/read-only boundary,
dispatches a typed tool request and returns a test verification result.
This is not a live Docker or live provider test.

Approval includes an exact diff digest. A novel diff requires separate proposal
and independent review before execution; runner regeneration must match exactly.
No model response can issue approval. Crash recovery and host-level durable store
protection remain explicit host responsibilities, not an invented guarantee.

## E. Lifecycle and sandbox evidence

Events: STAGE_05B_GATE_EVALUATED, STAGE07_PATCH_INTENT, STAGE07_PATCH_APPLIED,
STAGE07_VERIFICATION_RESULT, then STAGE07_EXECUTION_COMPLETED or
STAGE07_EXECUTION_FAILED. Audit append failure denies; post-apply failure rolls
back target bytes and attempts failure audit. Persistent audit/rollback failure
raises for reconciliation; no success is returned. Power loss is not transactional
across journal/file/audit. Host uses one protected store/log pair per workspace.
Verification is RunCommandInput -> SandboxToolCall -> DockerSandbox; host shell
is never used. Missing sandbox reports SKIPPED_NO_SANDBOX and a failure event.

Docker was rechecked after the human's availability update: unavailable on PATH
and at C:/Program Files/Docker/Docker/resources/bin/docker.exe. No local image
verification or live container execution is claimed.

## F. Verification results

All Python commands use .venv/Scripts/python.exe -B -m from repository root.

| Command arguments | Result | Exit |
|---|---|---:|
| pytest -p no:cacheprovider -q -o addopts=--strict-markers tests/unit/test_stage07_hybrid.py | 70 passed | 0 |
| pytest -p no:cacheprovider -q -o addopts=--strict-markers tests/unit/test_stage07_enterprise.py | 32 passed | 0 |
| pytest -p no:cacheprovider -q -o addopts=--strict-markers tests/unit/rea/test_rea_enforcement.py | 88 passed | 0 |
| pytest -p no:cacheprovider -q -o addopts=--strict-markers tests/unit | 194 passed | 0 |
| ruff check --no-cache src tests | All checks passed | 0 |
| ruff format --check --no-cache src tests | 79 files formatted | 0 |
| mypy --cache-dir=C:/Users/User/AppData/Local/Temp/opencode/astra-mypy-cache src | 48 source files; no issues | 0 |
| Draft202012Validator.check_schema for docs/schemas/*.json | 9 schemas valid | 0 |

Schema/example contract consistency is also covered by permanent Phase 2 tests.
Tests cover provider selection/failure, denied budget/network, circuit/deadline,
redaction/usage, signed approval failures, replay, sandbox argv rejection,
no-sandbox status, real REA workflow and post-write audit-failure rollback.

## G. Security and protected integrity

Scanner: .tools/gitleaks.exe/gitleaks.exe. Used redaction and JSON stdout captured
in memory; temporary snapshots stored outside repository. No values printed.

| Scan | Findings | Exit |
|---|---:|---:|
| Git history | 0 | 0 |
| Phase 2 deliverables snapshot | 0 | 0 |
| Current tracked-file snapshot | 2 historical-report false positives | 1 |
| Whole working directory | 28 | 1 |

Directory findings reconcile to existing 22 verified false positives plus six
generated Next.js preview-key detections. No new Stage 07 finding. Preserve
reports/security/stage07-phase1-security.md unchanged: SECURITY HOLD. No token
validation, rotation, deletion, suppression or external deployment inspection.
.env and .env.* are ignored; no credentials or external registries committed.
Image-layer scan unavailable; standalone-copy risk remains unresolved.

Protected hashes before/after match:

```text
reports/worker-smoke.json
3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8
authorization.json
0E6E6B0296D6120511BF89E3CC0B7261134969DF754471921E6B55FBD7F22EED
```

git diff --exit-code main -- src/astra_coder/rea and all four protected evidence
paths is empty. PR #11 remains OPEN; same head
2d48828ce5881c64121f5f50105c31f2b37267d7, main base and updatedAt
2026-11-18T13:38:33Z. AstraMindX not accessed. No dependency upgrades.

## H. Commit scope

Ten authorized Phase 2 files listed above, no generated artifacts, caches, keys,
registries or unrelated files. Required eventual commit message:
feat: stage07 phase2 - enterprise role routing, approval store, and governed hybrid runner
No commit/push/merge claimed while all-security-gates-pass condition remains unmet.

## I. Remaining limits and independent review

Independent second-party review PENDING; human sign-off PENDING. Live provider
test requires separate test-credential authorization. Compatible endpoints need
human configuration; actual GPT/Claude/Codex identities are not attested by labels.
No live Docker evidence is available. Host must protect registries/store/log,
serialize writers and reconcile crashes. No automated production deployment,
approval issuance, certification or security-HOLD clearance is claimed.

## J. Verdict

BLOCKED: directory-wide security gate is not clean (six generated preview-key
detections remain on the explicitly preserved SECURITY HOLD). Implementation and
unit/lint/type/schema gates pass; independent review package is prepared without
impersonating a reviewer. No completion commit made under the all-gates-pass rule.
