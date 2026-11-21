# Stage 07 Phase 2 remediation specification — PROPOSED

Status: DESIGN AND SPECIFICATION PROPOSAL ONLY — IMPLEMENTATION NOT AUTHORIZED — NOT CERTIFIED

Authority: Lakshman Ghosh, Human Sovereign Root. Date: 2026-11-21.
This file proposes requirements; MUST describes future acceptance conditions,
not permission to implement, execute, provision, migrate, commit or merge.

## 1. Scope, baseline and governance

Verified current main and HEAD: 93dcfa95429f84be15fcfb6b2a39302f981fbc73.
Unapproved Phase 2 commit: d74e2e640219351bdbbde5337c35a9d566a2bb5d on
feat/stage07-phase2-enterprise-hybrid-wiring, parent 39a9a732ecc87244496c023e4be17074018303a3.
It predates current main's Stage 05b reconciliation. It was read as Git objects,
not checked out, adopted or modified. It has been audited but is not approved;
the audit is not an exhaustive security verification. This proposal grants no
authority to merge that commit, restore its older evidence or repair its code.

Stage 05b remains NOT CERTIFIED. Stage 07 Phase 1 remains NOT CERTIFIED.
Phase 2 implementation remains NOT AUTHORIZED. Preserve the six Next.js findings:
GENERATED BUILD MATERIAL — DEPLOYMENT EXPOSURE UNRESOLVED — SECURITY HOLD.
No deployment-exposure conclusion, key rotation or suppression is proposed here.

The existing docs/design/stage07-phase2-approval-binding-PROPOSED.md remains
byte-for-byte unchanged. Its external human-to-key ownership proposal is a design
dependency, not an implemented identity guarantee. No matching-string inference.
Human-provisioned ASTRA_REA_APPROVER_REGISTRY_PATH and ASTRA_REA_TRUSTED_KEYS_PATH
remain authoritative; no production registry or human key is provisioned here.

### Observed boundaries and future responsibility allocation

| Module at d74e2e6 | Observation | Proposed responsibility, only after separate authorization |
|---|---|---|
| hybrid_enterprise.py, HybridEnterpriseRunner.run | Coder routing precedes store.consume; missing sandbox leaves an applied patch | Validate and reserve before provider; preflight sandbox; coordinate terminal state/rollback |
| hybrid_approval.py, verify_approval | External mapping/signature checks alongside REA trust | Strict canonical envelope, coherent registry snapshot, explicit binding verification |
| hybrid_approval.py:141–160, ApprovalStore.consume | Locked in-place JSON overwrite; no hash-chain/anchor | Durable reservation and transitions with complete chain and external anchor validation |
| hybrid_skill.py, execute_patch / atomic_replace | Existing REA gate and intent precede target replacement; sibling temp + fsync + replace | Preserve REA authority; expected-preimage checks and verified atomic apply/restore contract |
| Existing src/astra_coder/rea/ | Central R1/R2/R3, RBAC, trust and audit authority | Unchanged; no alternate gate or permissions |

This file changes no module, schema, test or report. Existing functionality,
unapproved implementation and proposed remediation are not interchangeable.

## 2. Defect 1: approval reservation before provider calls

### 2.1 Identity and exact authorization bindings

Define approval_id as a unique signed envelope identity; retain authorization_id
as the existing REA authorization identity. They MUST NOT be silently conflated.
For this single-use contract, authorization_id and nonce are also replay keys.
Define operation_id deterministically from a versioned signing domain,
repository/baseline scope, authorization_id, approval_id, plan ID/digest, step ID,
exact diff SHA-256 and exact target path. Bind the derived value to the signed
envelope or recompute and compare it under a ratified canonicalization contract.
Never use an unsigned random operation ID to bypass replay checks.

Before any LLM/coder routing or network call for the approved operation, ALL of
the following MUST succeed: strict envelope parsing with duplicate/unknown fields
rejected; Ed25519 signature; unambiguous human-owned active key; active trusted
approver/action and expiry; approver != authenticated executor; exact authorization,
bundle/plan/step/patch SHA-256 and target binding; and durable atomic RESERVED.
Verify actual proposed diff bytes where available, not only a claimed hash.
The existing signed R1/R3 bundle and REA trust are independently required.
No provider output, role label or caller digest can supply human authorization.

An exact plan/patch cannot be approved before it exists. Therefore the governed
execution entry point accepts already reviewed artifacts and their approval;
it MUST NOT bootstrap its own approval by calling plan() or generating a novel
patch first. Any separately authorized proposal-generation workflow requires its
own human-ratified network/budget scope and is outside this remediation. Coder
regeneration after reservation must match the preapproved bytes/digest or fail.
This resolves the dependency without weakening the pre-provider invariant.

### 2.2 State machine

```text
UNCONSUMED --verified + atomically persisted reservation--> RESERVED
UNCONSUMED --validation/policy denial, no provider----------> DENIED
RESERVED   --apply + sandbox verification + durable evidence--> CONSUMED_SUCCESS
RESERVED   --provider/gate/audit/verification/rollback failure--> CONSUMED_FAILED
```

DENIED is a terminal request decision, not a replacement for an existing state.
Do not append a DENIED record that resets a RESERVED/consumed identity. A fresh
operation after denial needs a new explicit authorization, never automatic retry.
ROLLED_BACK and CRITICAL_ROLLBACK_FAILED are event/outcome types recorded with
CONSUMED_FAILED, not extra reusable approval states. RESERVED remains unavailable
until terminal reconciliation; no time-based release or restart reset.

Any duplicate approval_id OR operation_id in RESERVED, CONSUMED_SUCCESS or
CONSUMED_FAILED MUST immediately raise ReplayError/PermissionError: zero provider
calls, zero new provider cost, zero target writes. Also reject reused authorization_id
or nonce under the single-use contract. Read-only signature verification itself
never reserves or consumes implicitly; the execution coordinator requires a
durable reservation receipt before it can invoke routing.

### 2.3 Process synchronization and call ordering

Use one authoritative store/anchor identity per repository scope, selected by the
trusted host, not arbitrary caller-controlled paths. Acquire an existing-style OS
exclusive file lock with bounded timeout across processes. While holding it:
verify full chain and external anchor, recheck authorization freshness/coherent
registry version, search all replay identities, append RESERVED, durably persist
journal and anchor, and return a reservation token bound to the resulting head.
Only then release the lock and permit a bounded provider call. Lock timeout,
missing files, I/O/anchor failure or changed bindings deny before network.
Do not hold only an in-process mutex or test a nonce before acquiring the lock.

The provider gateway MUST validate that the operation has a durable RESERVED
receipt; no alternate public runner/provider entry path may skip reservation.
Existing BudgetRunner/ModelGateway/NetworkAuthorizer budget, remote approval,
token and deadline checks remain additional mandatory gates, not replacements.
Revocation/expiry must be rechecked before mutation after a slow provider response.

Crash after reservation, including before any network call, preserves single-use
consumption. Crash after sending a request must never trigger automatic provider
retry on restart because external billing/outcome may be unknown. Human recovery
may close the state as CONSUMED_FAILED; any fresh attempt requires new authority.
Transient retry within one live reservation is permitted only under an explicitly
ratified retry/budget policy; duplicates never create a second retry budget.

## 3. Defect 2: tamper-evident journal and external anti-rollback anchor

### 3.1 Record format and hash domain

Each logical append adds an immutable record with required fields:

| Field | Required meaning |
|---|---|
| seq | Integer exactly previous seq + 1, starting at 1 |
| timestamp_utc | Canonical UTC; trusted-clock observation, not sole sequence authority |
| event_type | Versioned allowlisted reservation/terminal/rollback event |
| approval_id, operation_id | Exact scoped identities from verified approval |
| bundle_sha256 | Existing exact plan/step/diff bundle digest |
| state | RESERVED, CONSUMED_SUCCESS, CONSUMED_FAILED or DENIED, with legal predecessor |
| prev_entry_hash | 64 lowercase zero hex genesis sentinel for seq=1; otherwise preceding hash |
| entry_hash | SHA-256 over domain-separated canonical record excluding entry_hash and authenticator |

Include authorization_id, nonce, schema_version, repository_scope and previous/
resulting target hashes as signed/bound evidence fields where applicable. Reject
unknown versions, duplicate JSON names, nonfinite numbers, wrong types, gaps,
duplicate identities, illegal transitions, reorderings and chain mismatches.
No record contains credential values, provider prompts, private keys or signatures
from human envelopes unless separately justified; store envelope digest instead.

Choose exactly ONE versioned canonicalization: RFC 8785 JCS is proposed for journal
records. Recursively sorted JSON alone MUST NOT be labeled RFC 8785; numerical,
Unicode and escaping semantics differ. If a restricted sorted-JSON profile is
chosen instead, ratify its byte rules/test vectors and a distinct version/domain.
No verifier fallback between formats. Canonicalization is a ratification gate, not an implementation default: the selected profile MUST be named by an explicit canonicalization identifier and domain string in every journal record and verification vector. RFC 8785 JCS and any restricted sorted-JSON profile are not interchangeable; changing canonicalization requires a new journal version, new test vectors, and separate human authorization. No verifier may auto-detect, normalize, or fall back between canonicalizations, and malformed or alternate canonical bytes MUST be rejected before hashing. Example hash domain:
ASTRA_STAGE07_APPROVAL_JOURNAL_V1 + newline + canonical record bytes.

An optional detached/embedded HMAC or asymmetric signature authenticates the
domain, seq and entry_hash. If policy enables it, missing/invalid authentication
denies. Keys remain external; HMAC is a service-integrity mechanism, not evidence
of human approval. A hash chain alone detects internal edits only when compared
with a trusted anchor; it does not prevent an attacker recomputing the chain.

### 3.2 Atomic persistence (logical append, physical replacement)

Never seek/truncate an existing journal in place. Under the authoritative OS lock:

1. Validate journal, all chain entries, state transitions and protected anchor.
2. Build the old entries plus exactly one new entry; preserve earlier entry values.
3. Create a uniquely named sibling temporary file with restrictive permissions;
   reject symlink/reparse/alias substitutions and wrong ownership/volume scope.
4. Write complete updated bytes, flush(), os.fsync(), close, then os.replace()
   onto the journal. Fsync the parent directory where supported.
5. Atomically and durably advance the independent anchor to the same committed
   (latest_seq, latest_entry_hash), with expected-old-head compare-and-swap.
6. Reopen and validate both against each other before acknowledging reservation
   or success. No provider/target mutation until reservation acknowledgement.

On Windows or filesystems without directory fsync, document and test the actual
platform durability primitive and failure behavior. Do not equate atomic rename
with guaranteed power-loss durability. An unproven durable backend is a blocking
technical gate; no silent best-effort success. On Windows/NTFS, the implementation MUST document the exact primitive used for each durability step: file flush, os.fsync or its platform equivalent, temp-file creation, os.replace, and any directory-handle/fsync attempt. If a platform cannot fsync a directory, that limitation MUST be recorded as an explicit fail-closed condition or a separately ratified platform-specific durability primitive; it cannot be treated as best-effort success. A crash, permission denial, handle error, or unsupported primitive during any durability step blocks reservation acknowledgement and leaves the prior valid state or a blocked mismatch. No platform-specific fallback may silently weaken the canonical durability requirement.

### 3.3 Anchor trust and load rules

The external anchor file/log stores at least latest_seq and latest_entry_hash,
plus journal/scope identity, version and generation. Resolve it outside repo_root:
is_relative_to(repo_root) == False. The journal also remains external. Both paths
are fixed by trusted host configuration, not by an envelope, provider or mutable
repository file. Reject path aliases and inaccessible, malformed or mismatched scope.

External location alone does not supply anti-rollback. The anchor MUST be protected
by independent ACLs/service authority or an independently witnessed append-only
log/monotonic store; a principal capable of rolling back both files defeats a
plain two-file scheme. Document the adversary and refuse to claim protection
beyond that boundary. The runtime may advance the anchor under restricted
compare-and-swap authority but cannot initialize, rewind, replace or reset it. Threat-model boundary: if one principal, process, host administrator, container runtime, or compromised credential can modify both the journal and anchor paths, the two-file scheme provides tamper evidence only, not anti-rollback. Independent protection requires a separate service principal, ACL boundary, append-only/witnessed store, monotonic counter, or equivalent control that the runtime cannot bypass. The spec MUST name the assumed adversary and exact protection mechanism before implementation; otherwise the anchor claim is limited to tamper evidence and rollback resistance remains an explicit blocking risk.
Human provisioning creates genesis (seq=0, genesis hash) explicitly; missing
journal/anchor is never interpreted as an empty valid store. Genesis initialization is human-only and occurs before runtime use through a separately authorized provisioning process. Runtime code may advance a valid existing anchor under restricted compare-and-swap authority, but it MUST NOT create, initialize, rewind, replace, reset, repair, truncate, or re-anchor a missing, malformed, or mismatched journal or anchor. Missing, truncated, rolled-back, foreign-scope, lower-seq, same-seq/different-hash, journal-ahead, anchor-ahead, and authentication-mismatch states are terminal fail-closed denials requiring human reconciliation. No automatic repair, suffix discard, anchor advancement, or empty-store interpretation is permitted.

On every load verify the full chain and exact anchored head before use. Missing,
truncated, lower-seq or same-seq/different-hash journal raises TamperDetectedError.
A journal ahead of the anchor also denies: it may be a crash between writes or
tampering; do not automatically advance the anchor or discard the suffix.
Anchor ahead of journal, absent anchor, malformed/authentication failure and
foreign-journal substitution likewise deny immediately. No provider call, target
mutation, new nonce issuance or silent repair occurs on any mismatch.

There is no atomic transaction across two ordinary files. Crash between journal
replace and anchor update intentionally yields a blocked mismatch. Human recovery
must inspect old/new durable evidence through a separately authorized process,
never guess success. If a backend offers true atomic journal+anchor transactions,
ratify it separately. ROLLED_BACK and terminal events use the same durable protocol.

## 4. Defect 3: sandbox policy and verified rollback

### 4.1 Mode selection

Mode A defaults: require_sandbox=True and allow_unsandboxed_with_rollback=False.
Before reservation/provider/target mutation, verify the selected Docker sandbox,
approved image, typed verification request, isolation settings and availability.
Availability is more than finding a CLI executable: required daemon/image and
workspace boundary checks must pass without running the enterprise workflow.
If unavailable, return DENIED_NO_SANDBOX with zero target/filesystem mutation and
zero provider calls. This preflight denial writes no journal, lock/temp artifact
or receipt file; expose the reason through the returned decision. If existing
external telemetry is permitted to record denial, that is a separate explicitly
authorized non-target side effect, not a claim of literally zero filesystem writes.
Unknown/missing mode defaults to Mode A, never a permissive fallback. Telemetry is a diagnostic side channel, not execution authority: it MUST NOT create, modify, unlock, or imply permission for any target, journal, anchor, lock, temp, recovery, or audit artifact. Any telemetry or audit emission failure is fail-closed for the recording path but does not convert a denial into success or authorize mutation. If telemetry cannot be recorded, the denial result and reason remain authoritative; no retry, provider call, target mutation, or state transition occurs. Telemetry payloads MUST exclude secrets, envelope signatures, private keys, provider prompts, and target contents; only redacted identifiers, reason codes, and hashes may be emitted where separately authorized.

Mode B is exceptional: allow_unsandboxed_with_rollback=False by default. Only an
explicitly signed human policy binding the exact operation may enable it and
override require_sandbox. Contradictory/missing flags deny. It permits a provisional
bounded patch with mandatory rollback upon unavailable/failed/aborted verification;
it NEVER authorizes host shell execution or a successful unverified mutation.
If sandbox cannot be established post-apply, restore immediately and consume as
failure. No retained SKIPPED_NO_SANDBOX mutation is permitted in either mode. Mode B enablement MUST be a signed, expiring, operation-scoped break-glass authorization with explicit approver identity, issued/revoked state, and no self-approval. The effective policy is (require_sandbox=True, allow_unsandboxed_with_rollback=False) unless a valid signed override binds the exact authorization_id, operation_id, plan/diff/target, and repository scope. Contradictory flags, missing flags, expired/revoked override, scope mismatch, or unverifiable signature deny and default to Mode A or denial. Mode B still requires the same preimage capture, external recovery store, rollback hash verification, and terminal evidence; it cannot retain an unverified mutation. Recovery-store permissions, retention, cleanup, encryption, and hostile-writer/hard-link/symlink checks require a separately ratified policy before implementation.

No unsandboxed verification executor is introduced. Verification argv must pass
existing RunCommandInput/SandboxToolCall allowlists and execute only inside the
existing Docker boundary. Model-proposed shell strings are never executed on host.

### 4.2 Target transaction and evidence

After reservation and unchanged REA R1/R2/R3/RBAC checks, capture original_bytes,
original_sha256, resolved target identity and required permissions. Check against
signed preimage evidence where ratified; reject target changes before apply.
Keep recovery bytes in a host-protected external recovery store if crash rollback
is required; in-memory bytes alone cannot guarantee recovery after process death.
Retention/encryption/permissions and cleanup need separate authorized policy.

Append durable intent via existing REA audit authority before mutation. Apply
through sibling temp -> flush -> fsync -> replace -> directory fsync where
supported, preserving ratified file metadata. Record actual postimage hash,
then run sandboxed verification. Success requires valid verification plus durable
terminal audit and journal/anchor transition to CONSUMED_SUCCESS. Audit failure
at any post-apply point is failure, never completed.

On verification/sandbox failure, abort, expiry/revocation detected post-apply,
post-apply audit failure or an exception: atomically restore original_bytes using
the same durable replace protocol. Re-read target and require
post_rollback_sha256 == original_sha256; retain both hashes and operation ID.
Emit ROLLED_BACK in existing external hash-chained audit and approval journal,
with state CONSUMED_FAILED. Neither source bytes nor secrets belong in receipts.
Do not free the reservation after rollback. Same identity cannot run again.

Before restore, validate target containment and expected postimage/ownership.
If another writer changed the file, do not overwrite unrelated changes blindly;
halt with CRITICAL_ROLLBACK_FAILED and preserve evidence for human recovery.
Host must serialize the workspace across wrappers, not merely by a caller-selected
audit path. Atomic replacement does not solve hostile-writer races or hard links.

If restoration, hash verification or recording either rollback receipt fails,
emit CRITICAL_ROLLBACK_FAILED through surviving authorized channels, latch the
operation/workspace as blocked and halt fail-closed. Never claim both logs were
updated when one is unavailable. If all sinks fail, surface the critical exception
without secret payload, retain reservation/anchor evidence and require human
reconciliation. No further provider/execution retry and no success return.

## 5. Future verification matrix and acceptance criteria

The following is a test PLAN ONLY. No source/test/schema implementation or test
execution is authorized by this proposal. Use isolated test workspaces, ephemeral
test keys, externally provisioned test registries/journal/anchor and stubbed provider
transport unless a separate live-call approval exists. Verify exact bytes, chain,
state, provider-call count and incremental cost, not only exception type.

| ID | Required future test | Required result |
|---|---|---|
| G1 | Missing/unknown/ambiguous key ownership; inactive/revoked approver/key; wrong Ed25519 signature | DENIED, no provider/target write |
| G2 | Expired/future/naive time, clock uncertainty, self-approval | DENIED, zero calls/cost |
| G3 | Changed plan, step, patch bytes/digest, bundle, path, auth/repo/baseline/domain | DENIED, zero calls/cost |
| R1 | Valid signature and bindings, durable reservation | Provider observes RESERVED journal AND matching anchor before first call |
| R2 | Replay RESERVED, CONSUMED_SUCCESS, CONSUMED_FAILED by approval_id or operation_id | ReplayError, zero additional calls/cost/writes |
| R3 | Reuse authorization_id with different nonce, or nonce with different ID | Deny before provider |
| R4 | Two independent OS processes race for same operation | Exactly one durable reservation/allowed provider invocation; loser zero calls |
| R5 | Different caller log/store paths for same workspace | Reject nonauthoritative configuration; no replay bypass |
| R6 | Lock contention/timeout, reservation fsync/replace/anchor failure | No provider, no target mutation; state unavailable or blocked |
| J1 | Known canonical vectors, key ordering, Unicode/numbers, duplicate JSON members | One exact ratified hash format; malformed/alternate formats denied |
| J2 | Edit, delete, reorder, duplicate entry; seq gap; invalid transition; hash/authenticator mismatch | TamperDetectedError before provider |
| J3 | Truncate to valid prefix; replace with valid empty journal; old full snapshot | Anchor detects rollback; no auto-init/repair |
| J4 | Same seq with changed hash; foreign scope; missing/corrupt anchor/journal | Immediate denial |
| J5 | Journal ahead of anchor or anchor ahead of journal | Block for human reconciliation, no inferred success |
| J6 | Unauthorized rollback of both journal and anchor | Independent anchor protection detects/denies, or threat-model gate explicitly fails |
| C1 | Kill process before temp write, mid-write, after fsync, before/after replace and before/after anchor advance | Old valid state or blocked mismatch; never duplicate provider |
| C2 | Restart after RESERVED before/after request; unknown external provider result | No automatic retry; preserved consumption |
| S1 | Mode A no CLI/daemon/image or invalid isolation | DENIED_NO_SANDBOX; no file artifacts/target/provider mutation |
| S2 | Mode B absent/unsigned/tampered enablement, contradictory flags | Mode A or denial, never permissive fallback |
| S3 | Mode B signed enablement then no sandbox, verification failure or abort | Exact original bytes restored; verified hash; ROLLED_BACK in both logs; consumed failure |
| S4 | Audit/journal/anchor failure after apply, before final success | Rollback or critical blocked state; never success |
| S5 | Rollback replace/fsync failure, wrong hash, changed target or lost recovery bytes | CRITICAL_ROLLBACK_FAILED; no blind overwrite or retry |
| S6 | Shell escape, python -c, invalid executable/cwd, traversal/protected target | Denial through existing boundaries; no host command |
| E1 | Valid approval plus real test-key R1/R2/R3/RBAC and sandbox transport | Correct atomic postimage and matching terminal audit/journal/anchor |
| E2 | Missing signature/license/manifest/approver or unchanged core gate denies | No mutation; envelope cannot bypass REA |
| E3 | Crash after apply/verification but before terminal evidence | No claimed success; preserved consumption, external recovery and human reconciliation |
| E4 | Full unit/lint/type/schema/redacted scanner gates and protected hashes | Reproducible evidence; no secrets, no core/protected edits; existing SECURITY HOLD remains explicit |

Future acceptance requires all matrix cases, platform-specific durability and
multi-process tests, normative signature/hash vectors, complete failure-injection
evidence, protected SHA-256 checks, independent security review and explicit human
sign-off. Passing tests alone do not authorize implementation or certification.
Any unavailable anchor/host durability guarantee, unresolved rollback semantics or
preview-key exposure remains an explicit blocking risk, not a fabricated PASS.

## 6. Disposition and change control

This proposal is not a repair of d74e2e6, a Phase 2 approval, or a migration plan
execution. A future human decision must name implementation branch/baseline,
ratify canonicalization, anchor trust/durability, Mode B policy and crash recovery,
and define disposition of the unapproved commit. Preserve main's newer Stage 05b
evidence; do not treat a two-dot branch comparison as authority to restore old blobs.
No central REA/RBAC changes, real key provisioning, provider call, Docker workflow,
deployment, scanner suppression, commit, push or merge is authorized here.
