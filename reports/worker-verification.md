# Compose worker verification

## Verified scope

Real **structured JSON Plan** execution, not model-generated/natural-language
planning and not production security certification. The API authenticates and
queues; the separate worker claims; Git creates an isolated detached worktree;
all editing/tools and independent verification use hardened Docker containers;
task, request, result, and evidence hashes persist durably.

Latest detailed evidence: [worker-smoke.json](worker-smoke.json).

## Commands and actual outcomes

| Check | Actual result |
| --- | --- |
| `docker info --format '{{.OSType}}'` | `linux`, exit 0 |
| `docker compose --profile worker build api dashboard worker` | All three images built |
| `docker compose --profile worker build --quiet api worker` | Affected images rebuilt after final runtime changes |
| `python scripts/worker_smoke.py` | PASS, exit 0; actual project/task IDs recorded in JSON |
| Correct implementation | `succeeded`; 7 real contract tests, Ruff, Mypy passed |
| Incorrect implementation | `failed`; independent contract tests failed (not hidden or overridden) |
| Authorization / approval | Unauthenticated requests 401; developer approval/admin controls 403; execution before approval 403 |
| Isolation | Original clone unchanged; API has no Docker socket; task sandbox UID 10001, no socket, no root repository, read-only root, network disabled |
| Durability | Result/evidence hash unchanged after API process restart |
| Audit | Hash chain verified across API/worker events |
| Kill switch | Admin-only durable control; new work denied while enabled |
| Linux offline regression | 217 passed, 5 non-failing warnings, exit 0 |
| Ruff | Check passed; formatting passed for 46 files |
| Mypy | Passed, 24 source files |
| Whitespace | `git diff --check` passed before final report edit |
| Gitleaks source snapshot | No leaks found; ~474,796 bytes scanned; exit 0 |
| Semgrep | Unavailable; no pass claimed |

Offline regression command (Python 3.12.2 image, no network, no host source mount):

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --env ASTRA_DATABASE_URL=sqlite:////tmp/regression.db \
  astracoder-api:local make test
```

Gitleaks command inside the image:

```sh
.tools/gitleaks detect --no-git --source /app --no-banner --redact
```

This is a source-tree scan, not Git-history clearance. No scanner infrastructure
was installed. The arithmetic verification profile deliberately contains three
gates; it does not silently pretend the two security scanners passed. The worker's
default five-gate profile remains fail-closed when scanners are unavailable.

## Changes and limits

- Added opt-in Compose worker/seed services, prebuilt Docker CLI, Git/make image
  prerequisites, and task-scoped named-volume mounts.
- Added isolated trusted tool helper, Docker-only ToolMesh, deadline/step/approval/
  durable kill-switch checks, atomic queue claims/finalization and result endpoint.
- Added worker startup locking and fail-closed restart recovery. Startup clones
  committed HEAD only; source/dirty files are never rewritten and no commits occur.
- `scripts/worker_smoke.py` generates temporary server-only credentials and never
  embeds them in frontend bundles or this report. Its containers are stopped;
  all volumes/data remain retained. Failed setup attempts were also retained.
- Worker has privileged Docker-socket authority as a trusted control-plane process.
  No socket/credentials are passed to the API or task sandboxes. This is an opt-in
  controlled-machine demo, not multi-tenant production isolation.
- No model/provider calls occur. Token/cost consumption is zero; model-accounting
  integration is not claimed. Cancellation/kill switch are cooperative at boundaries;
  active calls are timeout-bounded rather than instantly interruptible.
- Dashboard static build/HTTP availability passed; no authenticated browser session
  or public deployment was claimed. Existing unchanged dashboard tests had 4 passes.
- Next.js 14.2.35 critical advisory remains unresolved; no verified compatible 14.x
  fix. Production login/token provisioning, Semgrep, full-history secret clearance,
  and competition registration/publication checks remain blockers.

No reset, cleanup of user data, commit, push, merge, publication, or release occurred.
