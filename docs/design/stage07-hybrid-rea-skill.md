# Stage 07 Phase 1: hybrid planning contract and bounded REA patch executor

**STAGE 07 PHASE 1 — PARTIAL IMPLEMENTATION / NOT CERTIFIED**

## Purpose and architecture reused
Phase 1 validates planner/coder data and applies bounded single-file text patches.
It reuses AstraAgent, require_stage05b_execution, the existing gate, RBAC, trust,
file locking and hash-chained audit writer. No alternate authorization authority.
REA internals and protected Stage 05b evidence remain unchanged.

## Planner and coder contracts; schema validation
GPT_BRAINING_PLANNER, CLAUDE_CODER and CODEX_CODER are data labels only.
Actual GPT/Claude/Codex routing is absent. Trusted callbacks accept text and return
strict Pydantic-validated data; unknown fields are rejected. They receive no shell
or file tool arguments, but trusted Python callbacks are not OS sandboxed.
Plans require risk checks, exact allowed files, exclusions and named steps. Patch
requests bind plan, step, diff and fail-closed skill. Draft202012Validator checks
both published schemas and examples in permanent tests. Schemas need no redesign.

## Approval and digest binding
plan_digest hashes UTF-8 compact sorted-key JSON of model_dump(), including defaults.
diff_sha256 hashes exact UTF-8 diff bytes, including line endings. Plan ID, step ID,
caller approved-plan digest and request digest must agree. A caller digest alone
is not authenticated approval.
execution_bundle_digest hashes compact sorted-key JSON containing skill, plan_id,
plan_sha256, step_id and diff_sha256. Its exact value must be top-level bundle_sha256
in signed R1. Existing enforcement checks its R3 and trusted-approver bindings.
Changing either plan or patch invalidates signed approval, even if caller digests
are replaced. The host provisions signed authorization and external registries;
there is no authenticated approval store. Existing signer-to-human limitations
remain; no certification is claimed.

## Allowed/excluded paths and containment
Allowed paths are exact files; exclusions cover subtrees case-insensitively.
Absolute paths, backslashes, colons, dot segments, trailing-dot/space aliases,
resolved symlink aliases, caches, protected evidence and REA internals are denied.
Headers must name the exact target. Hosts restrict repository and external audit
paths, protect against hostile filesystem writers and hard-link aliases, and
serialize other writers. This API is not an OS sandbox or global filesystem lock.

## R1/R2/R3 and RBAC identity
The default EXECUTOR role is policy-compatible with RUN_REA_EXECUTION and requires
independent trusted approval. Model data labels never become principals. Supplied
execution roles still pass central RBAC. Self-certification is passed through and
rejected. Existing signature/state/expiry, license, manifest input hashes, scope
binding and trusted-approver checks remain active. No central policy is changed.

## Audit lifecycle, replay and failure semantics
External audit log is mandatory. Existing enforcement appends a gate decision.
After gate success, signed bundle verification and parsing, STAGE07_PATCH_INTENT
is appended through the existing hash-chain writer before mutation, binding the
authorization ID, plan, step and diff. Its operation ID is consumed once; retries
require review even after write failure. A separate lock serializes wrapper calls
using the same log. The host must mandate one authoritative log: different logs
are not global replay protection.
Gate/intent append failure prevents mutation. Pre-gate validation raises without
receipts; post-gate validation has a gate event but no completion event. Intent is
not proof of completion. Completion/failure receipts and crash recovery remain
host responsibilities; no second audit authority is introduced. The final write
is not atomic with audit and I/O failure may partially write. Intent remains
consumed for human reconciliation. Target path and original bytes are rechecked.

## Parser supported and unsupported formats
Plain single-file unified headers, ordered non-overlapping and adjacent/multiple
hunks, optional count-one syntax, context and insert/delete/replace are supported.
Header framing accepts LF/CRLF; payload terminators are preserved and must match
source context. No implicit EOL conversion. Standard no-newline markers strip only
the preceding payload framing terminator. Both offsets, counts, context and final
newline placement are checked.
Binary, extended Git headers, rename, file creation/deletion (/dev/null), multi-file,
malformed/empty patches and unmarked unterminated bodies are rejected. Verification
commands remain data proposals; no arbitrary shell commands are executed.

## Permanent tests and exact commands
The Stage 07 test module separates mocked isolation tests from real enforcement.
Real tests reuse existing REA fixture builders, generate keys in memory, keep trust
registries/test artifacts outside the repository and never mock enforcement.
They assert every gate check, exact resulting bytes and valid audit chain.
Run from repository root, prefixing each command with .venv/Scripts/python.exe -B -m:

```text
pytest -p no:cacheprovider -q tests/unit/test_stage07_hybrid.py
pytest -p no:cacheprovider -q tests/unit/rea/test_rea_enforcement.py
pytest -p no:cacheprovider -q tests/unit
ruff check --no-cache src tests
ruff format --check --no-cache src tests
mypy --cache-dir=<external-temp-directory> src
```

## Trust boundaries, host responsibilities and limitations
Hosts authenticate independent human approval, provision signed bundles/registries,
choose workspace, executor identity and authoritative log, exclude hostile writers,
and reconcile consumed intents. Test keys demonstrate enforcement, not production
authority. Phase 1 has no provider identity verification or application entry point.

## Phase 1 exit criteria and review
Permanent parser, real/negative enforcement, schema, full unit, lint, type and
security results must be reported accurately. Generated preview-key deployment
uncertainty remains SECURITY HOLD until independently dispositioned. Second-party
review and subsequent human sign-off remain required; local tests are not approval.

## Phase 2 deferred scope
Real GPT/Claude/Codex transports/routing, ModelGateway/free-cascade network/budget/
deadline integration, authenticated approval store, full application entry point,
verification runner, production credentials and deployment are deferred. No claim
of live providers, certification, Stage 07 closure, push or merge authorization.
