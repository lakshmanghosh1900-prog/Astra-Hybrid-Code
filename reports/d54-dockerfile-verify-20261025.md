# D5.4 Bounded Verification — Dockerfile Patch + Health Gate

Run date: 2026-10-25 (host local, UTC+05:30). Scope strictly limited to the approved
D5.4 Dockerfile patch verification. Worker smoke, unrelated tests, Blocker 2, D6,
deployments and later stages were **not** run (hard stop respected).

## 1. Preflight (read-only, recorded before any action)

| Item | Value |
|---|---|
| Git HEAD | `4382b78e1e5202a646162af2298f35a83a30c176` (`main`, tracking `origin/main` [gone]) |
| Git status | 41 pre-existing modified tracked files (incl. `Dockerfile`, `.dockerignore`) + 23 untracked entries — all preserved untouched |
| Original image `astracoder-api:local` | `bcfd6605dd71` |
| `reports/worker-smoke.json` SHA-256 | `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` |
| Docker server | 29.8.2 |

## 2. Dockerfile patch-context confirmation (step 2)

The approved D5.4 lines are **already present** in the working-tree Dockerfile
(pre-existing modification; idempotent — zero lines required editing this run, so no
pre-existing edits were disturbed):

- `ASTRA_DATABASE_URL=sqlite:////data/astra.db` (Dockerfile:6)
- `RUN useradd --create-home --uid 10001 astra && mkdir -p /data && chown astra:astra /data` (Dockerfile:16-18)
- `USER astra` (Dockerfile:19)

No drift blocking the patch. Git diff of `Dockerfile` vs HEAD (multi-stage targets,
apt git/make, pip timeout/retries) is pre-existing work from before this run.

## 3. Candidate build (step 3) — three bounded attempts

| # | Mode | Result | Evidence |
|---|---|---|---|
| 1 | BuildKit default | **FAILED (exit 1, 5.9s)**: context sender `error from sender: open .security-venv\lib64: The file cannot be accessed by the system` — BuildKit walker opens a Directory+ReparsePoint entry despite `.dockerignore` exclusions | `d54-evidence/build-d54-verify-20261025-1.log` |
| 2 | `DOCKER_BUILDKIT=0` (configuration documented as verified on this host in `reports/8hour-submission-readiness.md:76`) | **FAILED (exit 2, 203.5s)**: transient PyPI index truncation during pip resolve (`json.decoder.JSONDecodeError: Unterminated string`) — network fault, not a patch fault | `d54-evidence/build-d54-kit0-20261025-1.log` |
| 3 | `DOCKER_BUILDKIT=0`, same tag command (repair of transient fault) | **PASSED (exit 0, 582.2s)** | `d54-evidence/build-d54-kit0-retry2.log` |

- Candidate tag: `astracoder-api:d54-verify-20261025-1` (unique; `astracoder-api:local` never overwritten or retagged).
- `.security-venv\lib64` was **not traversed** by the successful builds (legacy builder honored `.dockerignore`; `.security-venv/` excluded). Diagnosis of the attempt-1 failure used a single `Get-Item` stat of that one entry only (Directory, ReparsePoint, created 2026-10-18) — no directory listing/reading.

## 4. Candidate metadata (step 4, secrets not printed)

| Item | Value |
|---|---|
| Image ID | `sha256:a78f82aab4b7c198210ce4d55c8584b0a929a4cb88358415cd9de6f5e6f98ded` (`a78f82aab4b7`) |
| `Config.User` | `astra` (confirmed live: `id -un`=`astra`, `id -u`=`10001`) |
| `ASTRA_DATABASE_URL` | `sqlite:////data/astra.db` → `/data/astra.db` |
| Other env | names only (PATH, LANG, GPG_KEY, PYTHON_*, PYTHONDONTWRITEBYTECODE, PYTHONUNBUFFERED, PIP_NO_CACHE_DIR) — no secrets present |
| CMD | `uvicorn astra_coder.api:app --host 127.0.0.1 --port 8000`, WORKDIR `/app`, EXPOSE 8000 |

## 5. Test container (step 5)

| Item | Value |
|---|---|
| Name | `d54v-20261025-213631` (unique) |
| Container ID | `a3e95a08e05e268d6d17032cfa593e840f65b257b09fbeadd8ab17a7c53fc3a7` |
| Network | `none` |
| Port bindings | `{}` (none published) |
| Mounts | `[]` (none) |

## 6. Readiness + `GET /health` (step 6) — PASS

In-container probe: `GET http://127.0.0.1:8000/health` (real request, stdlib http.client).

| Item | Value |
|---|---|
| HTTP status | **200** |
| Body | `{"status":"ok","version":"0.1.0"}` — valid JSON, `status == "ok"` |
| Harness result | `OK=True`, attempt 1, harness elapsed **0.8 s** (≤30 s budget, 1 poll/s policy) |
| Container start → confirmed | 550.75 s (includes harness-defect repair windows below; container was continuously `running`, `RestartCount=0`, `FinishedAt` never set) |

Harness defect disclosure (not an app failure): the first two 30 s poll loops produced
only my own PowerShell→docker argument-quoting `SyntaxError`s (multiline arg passing,
then PS 5.1 stripping embedded double quotes from the probe). During those 60 s of
polling the container was observed `running` with no crash on every tick. Probe was
corrected; no false pass/fail of the application was recorded from those runs.

## 7. Failure classification (step 7)

Not triggered: no failure or timeout on the valid probe. Explicitly ruled out:

- **Confirmed SQLite permission exception:** NONE. `/data/astra.db` created, owned
  `astra:astra`, 77824 bytes; no traceback in logs.
- **Generic startup failure:** NONE. Logs: `Started server process [1]` → `Waiting for
  application startup.` → `Application startup complete.` → `Uvicorn running on
  http://127.0.0.1:8000`; `State.ExitCode=0`, `Restarting=false`.
- **Readiness timeout:** NONE (valid probe succeeded).
- No `/app/astra.db` fallback (`APP_DB_PRESENT=0`) → database URL honored.
- No credentials present in image env, container config, or logs.

Sanitized startup evidence is in `d54-evidence/container-logs.txt`.

## 8. Evidence saved before cleanup

This file plus `d54-evidence/*` were written **before** removing the container.

## 9–10. Cleanup and integrity recheck

### Cleanup result

| Step | Result |
|---|---|
| `docker stop a3e95a08e05e268d6d17032cfa593e840f65b257b09fbeadd8ab17a7c53fc3a7` | exit 0 |
| `docker rm` (exact CID from step 5, no name/image filters) | exit 0, container gone (`--filter id=` count = 0) |
| Pre-existing external container `luckys-pg` (`189d8ae4269d`) | untouched |
| Build intermediate `nostalgic_brown` (`cb601b80c0fa`, Exited(2)) | left in place — created by this run's failed attempt 2 (provenance: `build-d54-kit0-20261025-1.log`, "Step 7 … Running in cb601b80c0fa"); the plan authorized removal of only the test container. Optional cleanup: `docker rm cb601b80c0fa` |

### Integrity recheck (post-run vs preflight)

| Check | Preflight | Post-run | Verdict |
|---|---|---|---|
| Git HEAD | `4382b78e1e5202a646162af2298f35a83a30c176` | `4382b78e1e5202a646162af2298f35a83a30c176` | identical |
| `git status --short --branch` | 41 modified + 23 untracked entries (incl. ` M Dockerfile`) | byte-identical output | identical (this run added only files inside already-untracked `reports/`) |
| `reports/worker-smoke.json` SHA-256 | `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` | `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8` | identical — protected report unmodified |
| `astracoder-api:local` ID | `bcfd6605dd71` | `bcfd6605dd71` (Created 3 days ago) | identical — never overwritten/retagged |
| Dockerfile | ` M Dockerfile` (pre-existing edit) | SHA-256 `FB75820732748F90EAA2B0714C670928D4FE71330E660BB7541F6288AA2BD2FC`, diff vs HEAD = 19 insertions / 4 deletions | **no change by this run** (zero edits applied; the whole diff is the pre-existing working-tree state confirmed in step 2) |
| Candidate image | — | `astracoder-api:d54-verify-20261025-1` = `a78f82aab4b7` | created as required, unique tag |

### Concurrent external activity (not mine, untouched)

`astracoder-api:d5-4-20261025-r1` (`cf7a680cff08`) was **absent at preflight** and
appeared during this run's build window — evidence of a concurrent external build on
this host. It was created by neither of this run's `docker build` invocations (which
only tagged `d54-verify-20261025-1`) and was not modified, removed, or used.

### Verdict

All required D5.4 verification checks **PASSED**:

1. Preflight recorded; 2. Dockerfile patch context confirmed (idempotent, no edits);
3. Unique candidate built without touching `astracoder-api:local` and without
traversing `.security-venv\lib64`; 4. Metadata: `astra` (10001),
`sqlite:////data/astra.db`, no secrets printed; 5. Single uniquely-named
`--network none` container, no ports/mounts, ID-scoped cleanup; 6. `GET /health` =
HTTP 200 + valid JSON + `status == "ok"` within the 30 s budget; 7. Failure classes
ruled out (no SQLite permission exception, no startup failure, no readiness timeout);
8. Evidence saved before removal; 9. Integrity recheck all identical; 10. Reported.

Not run (hard stop): worker smoke, unrelated tests, Blocker 2, D6, deployments,
later stages. This file does not claim status for any stage beyond D5.4.

> Scope note: D54 is a D5.4-only record for the Dockerfile patch and health gate.
> Worker smoke is separate evidence and is not covered by this record.

