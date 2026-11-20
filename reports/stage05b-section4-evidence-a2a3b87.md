# Stage 05b Section 4 Fresh Evidence — a2a3b87

Date: 2026-11-21
Base commit: a2a3b875d62479f0909f9c74a82e265fdbba96a3
Branch: docs/stage05b-fresh-section4-a2a3b87
Scope: Independent §4 evidence only. No code changes, no Docker, no Worker/REA, no signing, no deployment.

## Check results

| Check | Command | Exit code | Result |
|---|---|---|---|
| pytest | `python -B -m pytest -p no:cacheprovider --override-ini 'addopts=--strict-markers' -q` | 0 | 491 passed, 2 skipped, 1 warning (starlette DeprecationWarning), 23.54s |
| ruff check | `python -B -m ruff check .` | 0 | All checks passed! |
| ruff format | `python -B -m ruff format --check src tests` | 0 | 72 files already formatted |
| mypy | `python -B -m mypy --cache-dir=.../astra-mypy-cache src` | 0 | Success: no issues found in 43 source files |
| gitleaks | `.tools/gitleaks.exe/gitleaks.exe git --no-banner --verbose` | 0 | 95 commits scanned, no leaks found, 430ms |

## Protected hashes

- reports/worker-smoke.json = 3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8
- authorization.json = 0E6E6B0296D6120511BF89E3CC0B7261134969DF754471921E6B55FBD7F22EED

## Notes

- This evidence was gathered on a clean checkout of a2a3b87.
- No source files, tests, schemas, or protected artifacts were modified.
- This evidence does NOT grant Stage 05b certification. Independent security review and explicit human closure approval remain PENDING.
- Baseline distinction: CURRENT_TREE_a2a3b87
