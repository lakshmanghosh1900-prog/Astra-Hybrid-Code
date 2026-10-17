# Engineering Decisions

## 2026-10-18 — Python 3.12 lock retained

The product contract remains Python 3.12, pinned by `.python-version`, the Docker image, and `pyproject.toml`. The current execution container exposes Python 3.11 only, so Python 3.12-specific installation and runtime checks are recorded as an environment gap rather than weakening the product requirement. Source code is kept compatible with 3.11 syntax where practical so offline static checks can still run in this workspace.

## 2026-10-18 — Dashboard is isolated

The dashboard is a client boundary, not a second orchestrator. The Python CLI/API remains the authoritative state and policy implementation. This keeps security behavior testable offline and avoids duplicated task state.
