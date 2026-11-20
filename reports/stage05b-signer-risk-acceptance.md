# Stage 05b — Signer Risk Acceptance (Risk Acceptance Only)

Date: 2026-11-21
Base commit: 00807102f074db4f96a1fd01f4594dbe58e48b0d
Branch: docs/stage05b-signer-risk-acceptance
Scope: Documentation only. No code changes, no fixes, no deployment.

## Gap

`src/astra_coder/rea/rbac.py` lines 117-135 compare the signing key ID against the human approver ID using a
cross-namespace comparison. The two identifiers come from different namespaces (cryptographic key identity vs.
human identity) and the comparison does not fail closed on mismatch in a way that cryptographically binds the
signer to the human approver. As a result, the gate cannot prove that the person who signed the authorization
is the same person recorded as the approver in the trusted-approver registry.

## Why this is not fixed now

The repository does not contain an authenticated identity system. Introducing a partial binding (for example,
matching a username string to a key ID) would create the appearance of cryptographic assurance without
providing it. A half-fix would be worse than the documented gap because it would mask the absence of real
identity verification behind a passing check.

The denial path remains fail-closed: missing or malformed registry entries, inactive approvers, and missing
bindings all result in denial. Only the positive assertion "this key belongs to this human" is not proven.

## Risk

- Denial remains fail-closed for all missing/malformed/inactive cases.
- The signer-to-human binding is NOT proven. An attacker who controls a trusted key ID could not be
  distinguished from the legitimate approver by this gate alone.
- Mitigation: external trusted-key registry (`ASTRA_REA_TRUSTED_KEYS_PATH`) and trusted-approver registry
  (`ASTRA_REA_APPROVER_REGISTRY_PATH`) are file-based and operator-controlled. Physical/OS-level protection
  of those files is outside this repository's control.

## Acceptance

- Accepted by: Lakshman Ghosh (Human Sovereign Root)
- Date: 2026-11-21
- Condition: When an authenticated identity system is available in this repository, the signer-to-human
  binding MUST be implemented and verified with a dedicated test. Until then, this gap remains documented
  and accepted.
- This acceptance does NOT grant Stage 05b certification. Independent security review and explicit human
  closure approval remain PENDING.

## Related

- `src/astra_coder/rea/rbac.py:117-135` (signer/approver comparison)
- `reports/stage05b-security-hardening-report.md` (Section 9, limitation 1)
- `reports/stage05b-closure-report.md` (Section 12)
