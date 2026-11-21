# Stage 05b — Bounded REA Specification (R5)

- Artifact: R5 `spec.md`
- Stage: 05b
- Base: `main @ 088fd9e70500da9e4d49a01707f0de0d1dc6c958`
- Historical baseline referenced by evidence: `00807102f074db4f96a1fd01f4594dbe58e48b0d`
- Generated: 2026-11-21
- Status: Stage 05b **NOT CERTIFIED**. Stage 07 **NOT AUTHORIZED**.

## 1. Bounded REA analysis scope

REA analysis for Stage 05b is bounded to repository-local, read-only inspection of the Stage 05b
artifacts, REA adapter source, schemas, reports, and documented CI evidence. Analysis is limited to
what can be substantiated by tracked files and recorded commands. No runtime gate execution, no
live Worker/REA invocation, and no external trust-registry content inspection are in scope.

The scope is evidence-based: claims are recorded as `VERIFIED`, `PARTIAL`, `UNVERIFIED`, `MISSING`,
`NOT_PERFORMED`, or `NOT_VERIFIED` according to the evidence actually available.

## 2. Authorized target and repository

- Repository (local): `C:\Users\User\Desktop\ASTRA CODER`
- GitHub repository: `lakshmanghosh1900-prog/Astra-Hybrid-Code`
- Authorized base: `main @ 088fd9e70500da9e4d49a01707f0de0d1dc6c958`
- Explicitly out of scope: `C:\astramind-dev` (must not be touched).

## 3. Permitted inputs

- Tracked repository files at the pinned base: `authorization.json`, `license-check.json`,
  `rea-input-manifest.json`, `docs/schemas/*`, `docs/blueprint/*`, `reports/*`, `scripts/*`,
  `src/astra_coder/rea/*`, `src/astra_coder/cli.py`, `src/astra_coder/worker_main.py`.
- Recorded evidence from reports (commands, exit codes, CI run IDs, protected-hash expectations).
- Approved Section F structures for R4-R8 supplied by the principal for this task.
- Static inspection of source code and JSON/Markdown artifacts.

## 4. Prohibited actions

- No Stage 07 activation or orchestrator/proxy wiring.
- No Worker, REA, Docker, or live gate execution.
- No signing, private-key access, or registry file creation/editing.
- No deployment, release, tag, or certification claim.
- No modification of protected files: `reports/worker-smoke.json`, `authorization.json`,
  `license-check.json`, `rea-input-manifest.json`.
- No modification of `src/astra_coder/rea/`, `cli.py`, `worker_main.py`, or `tests/`.
- No opening of a PR and no merge into `main`.
- No invention of reviewer identity, review timestamps, CI run IDs, approval records, registry
  contents, or verification outcomes.

## 5. Expected outputs (R1-R8)

| Gate | Artifact | Current status |
| --- | --- | --- |
| R1 | `authorization.json` | Present; hash matches protected expectation; operational signature verification NOT RUN |
| R2 | `license-check.json` | Present; hash matches manifest reference; license gate NOT RUN |
| R3 | `rea-input-manifest.json` | Present; hash computed; R3 gate NOT RUN |
| R4 | `evidence-index.json` | Created in this task from substantiated evidence |
| R5 | `spec.md` | This document |
| R6 | `unknowns.json` | Created in this task with documented gaps |
| R7 | `rea-policy-review.json` | Created in this task from static policy review |
| R8 | `rea-verification.json` | Created in this task with targeted check results |

Presence of R1-R8 is an exit prerequisite, not proof of Stage 05b closure.

## 6. Evidence requirements and Section 4 checks

Section 4 of `docs/blueprint/FINAL-BLUEPRINT-AUTONOMOUS.md` requires pytest, Ruff, type-check,
security scan, PR CI success, clean/mergeable PR state, stage-only diff, and no false SUCCESS.
Historical Section 4 evidence is recorded in `reports/stage05b-section4-evidence.md` at baseline
`0080710`; it was not re-run in this task. Only the following targeted checks are authorized here:
`ruff check --no-cache scripts/validate_r1_r3.py`, JSON syntax validation of generated R4/R6/R7/R8,
`git diff --check`, and protected-hash verification. Full Section 4 PASS is **NOT CLAIMED**.

No authoritative repository schema exists for R4-R8. JSON syntax is validated; schema validation is
documented as unavailable rather than invented.

## 7. Unknown handling

Unresolved items are recorded in `unknowns.json` with stable IDs, evidence, impact, blocking status,
owner/decision, and resolution conditions. Explicit states (`PENDING`, `NOT_PERFORMED`,
`NOT_VERIFIED`, `PARTIAL`, `BLOCKED`) are used where evidence is unavailable. Unknowns are not
silently resolved by this specification.

## 8. Policy and approval boundaries

- Authorization authority: ASTRA Policy/Approval is final; REA is bounded evidence analysis only.
- Trusted-key and trusted-approver registries are external, file-based, operator-controlled, and
  referenced by environment variable names only. Their contents were NOT READ or verified here.
- Signer-to-human identity binding is documented as a gap with human risk acceptance in
  `reports/stage05b-signer-risk-acceptance.md`; no cryptographic fix is claimed.
- Independent security review and explicit human closure approval remain PENDING.
- Stage 05b remains **NOT CERTIFIED**; Stage 07 remains **NOT AUTHORIZED**.

## 9. Fail-closed hash, input, and registry handling

All hash, input, and registry handling is fail-closed. There is no silent fallback, no implicit
trust, and no best-effort substitution anywhere in R1-R8:

- **Missing** artifact, field, registry file, required environment reference, or approval record
  yields an explicit `MISSING`/`NOT_VERIFIED` status or denial. No default value, assumed identity,
  or skipped check may fill the gap.
- **Malformed** hash (anything other than strict lowercase 64-hex), malformed JSON, malformed
  signature or key material, or malformed registry content yields explicit denial. Input is never
  parsed leniently and an unparseable entry is never ignored.
- **Ambiguous** input — conflicting hash values, multiple path variants for one artifact, duplicate
  IDs, conflicting approval scopes, or root/nested field disagreement — yields explicit denial. No
  first-match or last-match selection is permitted.
- **Inconsistent** hashes: every recorded canonical Git blob LF SHA-256 must reproduce byte-for-byte
  from `git cat-file blob <commit>:<path>`. A mismatch marks the affected artifact `PARTIAL` or
  `BLOCKED`. No working-tree hash, CRLF variant, or legacy comparison value may be substituted for
  a canonical value.
- **Canonical basis** is Git blob LF SHA-256 only. Working-tree SHA-256 values, including CRLF and
  LF checkout variants, are recorded solely as legacy comparison metadata and never satisfy a
  canonical hash check.
- **Provenance isolation:** self hashes and provenance hashes live outside canonical artifact hash
  maps. `rea-verification.json` (R8) does not contain its own hash, and `evidence-index.json` (R4)
  does not contain the R8 hash.
- **External registries** are referenced by environment variable names only. Their contents are
  `NOT_VERIFIED` unless separately and explicitly verified; absence is denial, not trust.
- **Status floor:** Stage 05b remains `PARTIAL` / `NOT CERTIFIED` and Stage 07 remains
  `NOT AUTHORIZED` until independent review and explicit human closure approval are recorded.
