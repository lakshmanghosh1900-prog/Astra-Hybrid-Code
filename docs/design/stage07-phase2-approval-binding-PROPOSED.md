# Stage 07 Phase 2 external human approval binding — PROPOSED ONLY

Status: DESIGN AND SCHEMA PROPOSAL ONLY. IMPLEMENTATION NOT AUTHORIZED.
Authority: Human Sovereign Root. Governance freeze applies to all existing changes.
Date: 2026-11-21. No execution, migration, provisioning or cleanup is authorized here.

## Authorization boundary and evidence preservation

The Human Sovereign Root clarified that Option A ratified external human-to-key
binding as design/schema work only. Subsequent implementation and implementation
tests exceeded that boundary. Passing tests do not authorize those changes.
This document is the separately requested design-only deliverable. It does not
approve, adopt, fix, delete or revert the frozen implementation or its schemas.

Repository: C:/Users/User/Desktop/ASTRA CODER.
Branch: feat/stage07-phase2-enterprise-hybrid-wiring.
HEAD/baseline: 39a9a732ecc87244496c023e4be17074018303a3.
Index matches HEAD. No staged changes. Remote Phase 2 branch was not found in the
read-only origin query. No Phase 2 commit, push, merge or deployment was performed
by this agent. Test execution occurred earlier, using temporary fixtures and
stubbed HTTP/container transports; it was not production workflow execution.

## A. Existing verified functionality at the authorized baseline

Merged Phase 1 supplies strict planner/patch data contracts, canonical plan/diff
digests, bounded single-file parser and target checks, and calls to unchanged
REA R1/R2/R3, RBAC, trust and hash-chained audit authority. EXECUTOR requires
independent trusted approval. Phase 1 binds signed authorization and manifest
bundle digests to the plan/step/diff. That is distinct from proving which human
owns a signing key. Role labels do not establish model or human identity.

The existing trusted-key registry models key ID, public key, ACTIVE status and
validity windows. The approver registry models HUMAN_APPROVER identity, ACTIVE
status, permitted actions, authorization/artifact/bundle bindings and validity.
Neither existing typed record establishes key ownership by a human approver.
The accepted Stage 05b signer-to-human gap is not resolved by this proposal alone.
Core RBAC separates acting, approving and R1 signing principals; a proposed
approval-envelope key is not silently substituted for an R1 signing principal.

## B. Proposed design (not implementation authority)

### External registry ownership and provisioning

Human Sovereign Root alone provisions/ratifies ownership records in the externally
located files named by ASTRA_REA_APPROVER_REGISTRY_PATH and
ASTRA_REA_TRUSTED_KEYS_PATH. The agent, model, provider response and ordinary runner
cannot create keys, assert ownership, add approvers or rewrite these files.
Private keys never reside in the repository; key operations belong to a separately
authorized human signing process. Restrict registry ACLs and preserve provenance,
version and change approvals outside the repository.

Proposed approver extension: approval_signing_key_ids is a nonempty list of unique
existing key IDs. Each approval-signing key has exactly one human owner in the
registry snapshot. Missing lists, duplicate IDs/JSON member names, ambiguous owners,
unknown keys, malformed records and partial reads deny. Never infer ownership from
equal strings, model labels, a signature alone, or a human name in signed content.
The extension supplements existing REA trust and may not replace central policy.
Activation of the extension requires a separate implementation approval.

### Canonical signed ApprovalEnvelope

Propose an explicit, versioned signing domain, repository/branch/baseline scope,
authorization ID, approver ID, signing key ID, plan ID/digest, exact diff digest,
exact target paths, issue/expiry timestamps and single-use nonce. Optionally bind
expected target preimage digests through an approved schema revision; do not infer
that plan approval covers an arbitrary future patch or changed source state.

For this proposal, all payload values are strings or arrays of strings, no floats.
Reject duplicate JSON members and unknown fields before canonicalization. Restrict
identifiers to ASCII and forbid control characters. Propose UTF-8, no BOM,
recursively sorted object keys, compact separators, no insignificant whitespace,
no escaping of permitted ASCII except required JSON quoting. Include the domain
and schema version in the payload; exclude only signature_base64. The signer and
verifier must share normative test vectors before enabling execution. Do not accept
multiple canonicalization schemes or silently reserialize arbitrary Unicode.

Plan and diff digests identify exact bytes under the ratified Phase 1 plan
canonicalization and UTF-8 diff hashing rules. An approval whose plan/diff differs
is not repaired by recalculating the approval at runtime. The proposed signature
must cover every authorization-bearing field, including target paths and expiry.

### Ed25519 verification and existing authority

Proposed verification order: strict schema/canonical input -> fixed scope/domain ->
complete registry snapshot -> active approver and authorized action -> explicit
key ownership -> active Ed25519 key -> signature -> issue/expiry -> actor separation
and exact plan/patch/path matching -> replay reservation -> unchanged REA gate ->
existing audit intent -> bounded mutation. Any exception or missing evidence denies.
No self-asserted signature_verified flag is accepted.

Existing authorization ID, artifact hash and bundle bindings, R1 signature,
R2 license, R3 manifest hashes, RBAC, trusted-approver and audit checks remain
independently mandatory. A valid envelope does not bypass them. The implementation
must read coherent registry snapshots or deny/retry without mutation if they
change during evaluation; no lower-trust loader may override the core authority.

### Activation, revocation and expiration

Both approver and signing key must be active and within validity windows. Removing
ownership, disabling a key/approver or revoking an authorization must deny subsequent
attempts, including previously signed envelopes. Propose explicit authorization
revocation state with human-controlled provenance; its location and atomic update
protocol remain a human design decision, not an invented current capability.

Propose canonical UTC timestamps YYYY-MM-DDTHH:MM:SSZ, issued_at <= trusted current
time < expires_at, issued_at < expires_at, and expiry no later than the underlying
authorization. Clock uncertainty denies. Maximum lifetime and clock-skew policy
require explicit ratification; do not silently alter core REA time policy.

### Nonce, replay and crash behavior

Use a high-entropy signing-process nonce. Reserve authorization_id and nonce in a
single authoritative, external, access-controlled durable journal before mutation.
Reservation must be atomic across processes and must fail on unavailable/corrupt
state, duplicates, rollback detection or incomplete writes. A consumed ID is never
re-enabled by changing the nonce, log path, model or process. Multiple steps need
an explicit future authorization policy; default to one authorized mutation.

Propose states RESERVED, INTENT_RECORDED, APPLIED, VERIFIED, COMPLETED, FAILED and
RECONCILIATION_REQUIRED. No restart guesses whether a mutation occurred. A crash
between journal/file/audit transitions leaves consumption intact and requires
human reconciliation against target pre/postimage hashes and audit chain. This
proposal does not claim a cross-file transaction or implement recovery.

### Self-approval and exact target binding

Require independently authenticated executor and approver identities and deny
executor == approver. No model role string becomes either identity. Verify the
envelope's plan ID/digest, patch digest and paths against validated plan/patch
objects, signed R1/R3 bundle and current target preimage where ratified.

Paths are repository-relative exact file paths, normalized under one specified
policy before signing. Reject traversal, absolute/drive/UNC paths, alternate data
streams, case/Unicode/short-name aliases, symlink/junction/hard-link escapes,
protected artifacts and excluded subtrees. Lexical checks alone are insufficient;
implementation must prevent path races at the execution boundary. How to enforce
hard-link and privileged-writer assumptions on Windows needs independent review.

### Trust boundaries and fail-closed behavior

Trusted: human-provisioned registries, authenticated identity/session context,
protected nonce journal, trusted clock, unchanged REA authority and execution host.
Untrusted: model output, provider metadata, repository content, proposed diffs,
caller digests, unsigned approval strings and model-generated test claims.
The host is not an OS sandbox by virtue of this design. Verification remains
container-only; no raw host shell execution is authorized by an envelope.

Missing/ambiguous binding, invalid/expired signature, revoked/inactive principal,
self-approval, scope mismatch, replay, path escape or failed audit denies before
mutation. Audit failure after mutation requires failure status and reconciliation;
never claim rollback succeeded without checking resulting bytes. Secret values,
private keys, signatures and full registry content must not be echoed in errors.

### JSON Schema proposal (inline only; not an adopted runtime schema)

This schema describes a proposed envelope, not existing approved behavior. Hash,
identity, path containment, signature and replay semantics require independent
verification outside JSON Schema. Field/domain/time decisions need ratification.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PROPOSED Stage07ApprovalEnvelopeV1",
  "type": "object",
  "additionalProperties": false,
  "$defs": {
    "id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"},
    "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "time": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"}
  },
  "properties": {
    "domain": {"const": "ASTRA_STAGE07_HUMAN_EXECUTION_APPROVAL"},
    "schema_version": {"const": "1.0.0"},
    "repository": {"const": "lakshmanghosh1900-prog/Astra-Hybrid-Code"},
    "target_branch": {"type": "string", "minLength": 1, "maxLength": 256},
    "baseline_commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
    "authorization_id": {"$ref": "#/$defs/id"},
    "approver_id": {"$ref": "#/$defs/id"},
    "key_id": {"$ref": "#/$defs/id"},
    "plan_id": {"$ref": "#/$defs/id"},
    "plan_sha256": {"$ref": "#/$defs/digest"},
    "diff_sha256": {"$ref": "#/$defs/digest"},
    "target_paths": {"type": "array", "minItems": 1, "maxItems": 1, "uniqueItems": true,
      "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "issued_at": {"$ref": "#/$defs/time"},
    "expires_at": {"$ref": "#/$defs/time"},
    "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{32,128}$"},
    "signature_base64": {"type": "string", "minLength": 88, "maxLength": 88}
  },
  "required": ["domain", "schema_version", "repository", "target_branch",
    "baseline_commit", "authorization_id", "approver_id", "key_id", "plan_id",
    "plan_sha256", "diff_sha256", "target_paths", "issued_at", "expires_at",
    "nonce", "signature_base64"]
}
```

Strict Base64 decoding must yield an Ed25519 signature of exactly 64 bytes;
schema length alone is not sufficient. Timestamp pattern alone is not a valid
calendar or ordering check. No new standalone schema file is created by this task.

### Positive, negative and adversarial test plan — not executed under freeze

Positive: human-owned active test key; valid signature and canonical vector;
independent EXECUTOR/approver; matching R1/R2/R3, plan, exact patch and path;
fresh nonce; valid intent/completion chain; expected final bytes.

Negative: missing/duplicate/multi-owner mapping, unknown key/approver, wrong key
type, inactive/revoked/expired key or approver, invalid signature/Base64, unknown
fields, duplicate JSON members, noncanonical timestamps/Unicode, changed signed
field, wrong repository/branch/baseline, digest/path/preimage mismatch, missing
human authentication, self-approval, gate/RBAC/license/manifest denial and audit
failure. Every negative mutation attempt asserts unchanged protected/target bytes.

Adversarial: concurrent consumption; process restart; repeated authorization with
new nonce; journal rollback/truncation; substituted log/store; registry changes
between verification/use; clock rollback; symlink/junction/hard-link/short-name
and case collisions; partial writes; crash after each lifecycle transition;
denial during rollback; provider text attempting approval/command injection.
Transport stubs are labeled as such, not live-provider evidence. Real-key or live
provider tests require separate authorization. Independent reviewer must assess
threat coverage and host assumptions; builder test results are not approval.

### Migration and backward compatibility

Keep merged Phase 1 behavior and central REA registries unchanged until separate
authorization. Propose an explicit opt-in Phase 2 envelope version and registry
extension; missing extension denies Phase 2, never falls back to caller digest or
Phase 1 execution. Existing Phase 1 artifacts do not acquire new human identity
assurances retrospectively. Do not mutate Stage 05b evidence for migration.

Prepare human-reviewed external ownership records, canonical vectors, protected
journal provisioning, revocation/clock/crash procedures and independent review
before enabling the new path. Preserve old signed artifacts and define an explicit
version transition; do not reinterpret signatures under a new schema. No migration
or rollout occurs in this design-only task.

## C. Implemented but unauthorized changes — frozen evidence

At freeze entry: three tracked modifications (+130/-3) and seven untracked files
(1,157 lines). No additions/deletions are staged; no tracked files were deleted.
Counting untracked files as new content gives +1,287/-3 across ten files.
These counts exclude this newly authorized design-only document.

| Status | File | Diff or new lines | Classification / observed change |
|---|---|---:|---|
| M | docs/design/stage07-hybrid-rea-skill.md | +101/-2 | Design narrative mixed with unauthorized implementation assertions |
| M | src/astra_coder/config.py | +11/-0 | Unauthorized implementation: model/endpoint/key settings and redaction |
| M | src/astra_coder/hybrid_skill.py | +18/-1 | Unauthorized implementation: atomic replacement helper and writer change |
| ?? | docs/schemas/stage07-approval-envelope.schema.json | 78 | Generated schema candidate tied to unauthorized runtime model; not adopted |
| ?? | docs/schemas/stage07-execution-report.schema.json | 28 | Generated schema candidate tied to unauthorized runtime model; not adopted |
| ?? | reports/stage07-phase2-review.md | 154 | Evidence narrative with inaccurate authorization/completion framing |
| ?? | src/astra_coder/hybrid_approval.py | 160 | Unauthorized implementation: envelope verification and consumption journal |
| ?? | src/astra_coder/hybrid_enterprise.py | 172 | Unauthorized implementation: orchestration, receipts, verification, rollback |
| ?? | src/astra_coder/hybrid_routing.py | 199 | Unauthorized implementation: routing, budget/gateway adapter |
| ?? | tests/unit/test_stage07_enterprise.py | 366 | Unauthorized implementation tests; generated test keys/stub transports |

The review report's phrase "Ten authorized Phase 2 files" is inaccurate under the
human clarification. Its failure to identify unauthorized implementation is a
material governance omission. Existing design status "IMPLEMENTED / PENDING
INDEPENDENT REVIEW" is not authorization, acceptance, or certification. Those files
are preserved, not corrected or endorsed. Disposition is solely Human Sovereign Root's.

Frozen file SHA-256 manifest (current working-tree bytes, not test-time proof):

```text
a7635d2003a865a56ef576cd11afe3ffd382223b50ae3cfc1074407dd10f5a0e  docs/schemas/stage07-approval-envelope.schema.json
f8f6a254ff9a98e38086154e90b98ead0e4283080e7df127628870902c6c49cd  docs/schemas/stage07-execution-report.schema.json
23ce8ee9040b08658dfdec88616c2895b26bac84f62ae96fa8349b443b307b53  reports/stage07-phase2-review.md
50d995fe55fe25e6654bdfb2aba5b5faee26839a5cdc2bfe9f649e9b6c5ffe6a  src/astra_coder/hybrid_approval.py
40c376f0c335a2d4881875eb9c3c5095ee546c7a08391687b2336f72fd59b470  src/astra_coder/hybrid_enterprise.py
b5df42f459925ce69d6c3bcabcc2baa1e8fa84a542560b3653f331a46e9058ab  src/astra_coder/hybrid_routing.py
93ab92f6a5406bed9c5ba0f4e87d6f61db2ac525a2e991b4837b17e16d3cc5e7  tests/unit/test_stage07_enterprise.py
0312c240e699e40984daeb292c801d4889ce45314cd378715bb99f46aca070dc  docs/design/stage07-hybrid-rea-skill.md
d4766f3f3a5dab9d41007bd3d05e6e72b6439196a3c69f594abbc1ca29be2111  src/astra_coder/config.py
1860c663ec49f0f2c530ee47155431e1a515aca1bbe598f91fc78ceb49e98848  src/astra_coder/hybrid_skill.py
```

## D. Unverified assumptions, test provenance and security

Prior transcript records 194 full-unit tests passed, 70 Phase 1, 32 Phase 2 and
88 REA focused tests passed, plus lint/type/schema success. No test-time source
hash manifest or immutable revision captured uncommitted inputs. Source changes
were not made after that run in this session, but an exact cryptographic tie to
current bytes cannot be established retrospectively. Later documentation/report
edits also mean the complete current working tree is not identical to the tested
tree. These results cannot certify, authorize or approve the frozen changes.
No tests or workflow executions are rerun during this governance reconciliation.

Prior separate redacted scanner results, not rerun here:

| Scope | Findings | Exit | Meaning |
|---|---:|---:|---|
| Git history | 0 | 0 | Existing scanner configuration/suppressions unchanged |
| Ten Phase 2 deliverables snapshot | 0 | 0 | No detected secrets in that snapshot; not authorization |
| Tracked-file snapshot | 2 | 1 | Historical-report Docker-tag false positives |
| Whole working directory | 28 | 1 | 22 previously classified false positives; six generated preview-key detections |

Preserve exactly: GENERATED BUILD MATERIAL — DEPLOYMENT EXPOSURE UNRESOLVED — SECURITY HOLD.
No overall security PASS. No new suppression, credential rotation or deployment
exposure conclusion. Docker/live providers were not verified. The design document
itself has not been included in those earlier scans.

No real credentials/private keys or external registries were added to the ten
changed files by this agent. Source includes test-only credential placeholders
and in-memory ephemeral key generation, not provisioned human keys. The two JSON
schemas are generated tracked-candidate artifacts and the review report is evidence;
no new .next/cache/tool folders appear in the nonignored change inventory.
Earlier test execution created temporary fixture artifacts outside the repository;
ignored files are not exhaustively inventoried by git status, and no claim is made
that no temporary/cache artifact ever existed. No secret values are printed here.

Protected hashes reverified at freeze entry:

```text
reports/worker-smoke.json
3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8
authorization.json
0E6E6B0296D6120511BF89E3CC0B7261134969DF754471921E6B55FBD7F22EED
```

REA core, authorization.json, reports/worker-smoke.json, evidence-index.json,
rea-verification.json and the existing Phase 1 security report match the authorized
baseline. PR #11 remains OPEN with head 2d48828ce5881c64121f5f50105c31f2b37267d7,
base main and updatedAt 2026-11-18T13:38:33Z. No changes to main or PR #11.
AstraMindX was not accessed; that boundary is preserved without reading it to prove it.

## Required next human decision

Decide disposition of the preserved unauthorized implementation and tests; do not
automatically adopt, commit or revert them. Separately ratify the proposed schema,
canonicalization, ownership/revocation model, replay-store and crash policy before
any future implementation authorization. Review pending; no reviewer PASS asserted.

PHASE 2 GOVERNANCE FREEZE — IMPLEMENTATION UNAUTHORIZED — NO COMMIT — NO PUSH — NO MERGE
