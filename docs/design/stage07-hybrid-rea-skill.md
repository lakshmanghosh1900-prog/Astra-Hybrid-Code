# Stage 07 Phase 2: enterprise hybrid wiring

**STAGE 07 PHASE 2 â€” IMPLEMENTED / PENDING INDEPENDENT REVIEW (NOT CERTIFIED)**

Phase 2 extends the merged Phase 1 contract with real role-to-provider routing,
existing gateway/budget/network policy integration, external human-key approval
binding, a governed runner, lifecycle receipts, and Docker-only verification.
Phase 1 behavior remains the bounded patch authority.

## Provider routing and gateway boundary

`HybridProviderRouter` maps `GPT_BRAINING_PLANNER`, `CODEX_CODER`, and
`CLAUDE_CODER` to separately configured HTTPS OpenAI-compatible endpoints and
models. Missing model, endpoint, credential, paid-remote authorization, invalid
endpoint credentials, or cross-role output fails closed before network I/O.
There is no cross-role fallback. Model labels are checked as response metadata,
not trusted principals. Native Anthropic Messages transport is deferred until a
compatible provider is configured.

Every call uses the existing `ModelGateway` and `BudgetRunner`, including
`NetworkAuthorizer`, `PolicyEngine` remote approvals, worst-case token/cost
preflight, usage charging, wall-clock deadline, circuit breaker and bounded
server-error retry. Authentication, authorization, rate-limit and parse failures
are non-retryable. `SecretRedactor` covers configured values and provider audit
metadata. Provider credentials come only from environment-loaded Settings.

## Authenticated approval store

`ApprovalEnvelope` is signed by an Ed25519 key. The human-provisioned external
registry field `approval_signing_key_ids` maps `approver_id` to authorized key IDs;
missing, duplicate, or multi-owner mappings fail closed. Verification requires a
valid signature, active key and approver, expiry, authorization ID, exact plan and
patch digests, exact target path, executor separation, existing REA trust binding,
and an external single-use nonce journal. No string-ID equality infers ownership.
The journal is locked, fsynced and never stored in the repository.

## Governed runner and verification

`HybridEnterpriseRunner` coordinates planner output, human approval, coder output,
REA/RBAC execution, atomic replacement, and lifecycle events. Verification is
validated with `RunCommandInput` and sent only through `DockerSandbox`; the host
never runs a raw command. Without Docker, status is `SKIPPED_NO_SANDBOX`; it is
never reported as completed. Completion/failure receipts and rollback are emitted
through the existing hash-chain writer. Crash recovery and an authoritative
cross-process store remain host responsibilities.

**STAGE 07 PHASE 1 â€” PARTIAL IMPLEMENTATION / NOT CERTIFIED**

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

## Phase 2 configuration and operational limits

Use load_settings() with ASTRA_PLANNER_MODEL, ASTRA_CODEX_MODEL,
ASTRA_CLAUDE_MODEL, ASTRA_OPENAI_BASE_URL, ASTRA_OPENAI_API_KEY,
ASTRA_CLAUDE_BASE_URL, ASTRA_CLAUDE_API_KEY and ASTRA_ALLOW_PAID_REMOTE.
For T4, ASTRA_ALLOW_REMOTE_T4 and existing task-specific policy approvals are also
required. No endpoint/model/pricing is guessed. The host supplies conservative
positive per-token rates via HybridRoutingPolicy; native Anthropic Messages is
not implemented. Claude requires an approved compatible endpoint. No live model
or provider identity was verified in this task; real HTTP transports were tested
with httpx.MockTransport only. Provider metadata never confers RBAC permissions.
The router is per-task, single-writer; injected clients are trusted host objects.
HTTP timeouts recompute the remaining task budget on every retry. Late responses
are charged and then rejected. Existing accounting cannot establish billing for
failed server requests without usage reports; host billing reconciliation remains
required. No aggregate cost reservation across concurrent routers is claimed.

The human-provisioned approver record adds approval_signing_key_ids: a nonempty
unique list of key IDs that also exist in the unchanged trusted-key registry.
One key must have one human owner. Signature payload is sorted compact JSON of
ApprovalEnvelope.model_dump(mode='json') excluding signature_base64. Host must
protect registry and replay journal paths/permissions and prevent journal rollback.
The journal must be provisioned as [] externally; missing/corrupt journals deny.
The runner consumes authorization ID and nonce once; retries after mutation or
failure require human reconciliation, never automatic reauthorization.

Approval binds the exact diff digest. A new proposal must therefore be generated
and independently reviewed first; the runner accepts a pre-approved exact diff
and rejects a coder regeneration that differs. There is no automatic approval
callback and no model can approve its own output. The signed Stage 05b R1/R3 bundle
must be provisioned externally and match the approved plan/diff. Protected shipped
repository R1 is never rewritten; tests use isolated workspace copies only.

Verification argv is trusted host input validated by RunCommandInput and
SandboxToolCall, never taken as a shell string from provider text. The sandbox
mount is read-only, with network disabled; test/cache writes may need suitable
container configuration. Existing NoHostExecutor remains unchanged. Missing
sandbox yields SKIPPED_NO_SANDBOX and an execution-failed lifecycle event, not a
verified success. Live Docker execution could not be performed: Docker was absent
on PATH and at the standard Docker Desktop executable path in this session.

Atomic replacement preserves source mode and flushes bytes before os.replace.
The enterprise wrapper rolls back target bytes when post-apply audit or verification
fails and attempts a terminal failure receipt. Failed rollback or audit raises;
no success is returned. Power loss between journal, mutation and receipts is not a
cross-file transaction: durable consumed authorization plus intent requires manual
crash reconciliation. Same workspace must use one protected journal/log pair.
No protection against privileged host writers, registry rollback or hard-link
aliases is claimed. No second REA/RBAC authority or OS sandbox on host is introduced.

Run tests/unit/test_stage07_enterprise.py in addition to the Phase 1 commands.
JSON schemas cover approvals and reports. Independent second-party review and
human sign-off remain pending. The six preview keys remain SECURITY HOLD; no
push, merge, deployment or certification is authorized by this implementation.
