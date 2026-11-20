# Stage 05b Section 4 Independent Evidence

Date: 2026-11-21
Base commit: 00807102f074db4f96a1fd01f4594dbe58e48b0d
Branch: docs/stage05b-section4-evidence
Scope: Independent §4 evidence only. No code changes, no Docker, no Worker/REA, no signing, no deployment.

## Check results

| Check | Command | Exit code | Result |
|---|---|---|---|
| pytest | `python -B -m pytest -p no:cacheprovider --override-ini 'addopts=--strict-markers' -q` | 0 | 491 passed, 2 skipped, 1 warning (starlette DeprecationWarning), 24.19s |
| ruff check | `python -B -m ruff check --no-cache src tests` | 0 | All checks passed! |
| ruff format | `python -B -m ruff format --check --no-cache src tests` | 0 | 72 files already formatted |
| mypy | `python -B -m mypy --cache-dir=.../astra-mypy-cache src` | 0 | Success: no issues found in 43 source files |
| gitleaks | `.tools/gitleaks.exe/gitleaks.exe git --no-banner --verbose` | 0 | 90 commits scanned, no leaks found, 463ms |

## .gitleaksignore suppressions (pre-existing, 2 entries)

Both entries are finding-level suppressions for the D5.4 verification report (base commit 30be0c0), not active secrets:

- `30be0c025be7f786f5763cb2085f44cada38f812:reports/d54-dockerfile-verify-20261025.md:generic-api-key:38`
- `30be0c025be7f786f5763cb2085f44cada38f812:reports/d54-dockerfile-verify-20261025.md:generic-api-key:117`

## PR #18 CI evidence (historical, merged)

- State: MERGED (merged 2026-11-20T16:18:43Z)
- mergeable: UNKNOWN (post-merge)
- mergeStateStatus: UNKNOWN (post-merge)
- CI run 44767974342 (pull_request): quality — SUCCESS (completed 2026-11-20T15:55:29Z)
- CI run 44767963636 (push): quality — SUCCESS (completed 2026-11-20T15:55:27Z)

## Notes

- This evidence was gathered on a clean checkout of 0080710 (worktree at .git/stage05b-evidence-checkout).
- No source files, tests, schemas, or protected artifacts were modified.
- Protected hashes: worker-smoke.json = 3045C669..., authorization.json = 0E6E6B02... (unchanged).
- This evidence does NOT grant Stage 05b certification. Independent security review and explicit human closure approval remain PENDING.
