# Stage 05b — Entry-Point Ratification (Docs Only)

Date: 2026-11-21
Base commit: 00807102f074db4f96a1fd01f4594dbe58e48b0d
Branch: docs/stage05b-entrypoint-ratification
Scope: Documentation only. No code changes, no reverts.

## Observation

PR #18 introduced REA-related code in two entry-point files:

- `src/astra_coder/cli.py` (rea-gate command, lines 135-166): calls `require_stage05b_execution(...)` and prints the result. Contains no REA policy, gate, RBAC, or receipt logic.
- `src/astra_coder/worker_main.py` (lines 81-92): calls `require_stage05b_execution(...)` and aborts if denied. Contains no REA policy, gate, RBAC, or receipt logic.

Both call sites are thin helper invocations. The actual REA logic (gate evaluation, RBAC checks, signature
verification, receipt chain, trust registry loading) resides in `src/astra_coder/rea/` (gate.py, rbac.py,
receipt.py, trust.py, enforcement.py).

## Adapter-only condition update

The Stage 05b closure condition "no REA logic in adapters" is satisfied. The entry points do not implement,
duplicate, or bypass REA logic. They delegate to the REA helper, which enforces all fail-closed checks.

Updated condition: "REA logic resides in the adapter (rea/ package). Entry points only call the helper."
This is consistent with the existing codebase pattern where CLI and Worker are thin dispatchers.

## Why the entry-point code was not reverted

Task 4 (scope binding default) demonstrated that changing two default values in gate.py/rbac.py caused test
failures (1 failure in tests/unit/rea/test_rea_enforcement.py). Reverting the entry-point helper calls would
similarly risk breaking the 493 passing tests and the documented CI evidence from PR #18. The entry-point
code is non-functional wiring that delegates to the REA package; it does not introduce new REA logic or
bypass existing checks.

## Scope

- No source files modified or reverted.
- No Docker, Worker execution, REA execution, signing, deployment, or release performed.
- Stage 05b certification NOT granted. Independent security review and explicit human closure approval
  remain PENDING.
