# Structured-plan worker demo

## Scope and trust boundary

This is real execution of an operator-supplied JSON `Plan`, not a simulated model
or a claim of natural-language autonomous coding. The API only enqueues work.
The worker creates a detached Git worktree from the approved revision; all reads,
patches, commands, and verification run in per-task Docker containers. They receive
only the task's named-volume subdirectory, no API credentials or Docker socket,
no network, a read-only root, UID 10001, dropped capabilities and resource limits.

The **trusted worker itself** needs the host Docker socket. That socket grants
host-level authority: use the opt-in profile only on your controlled demo machine,
not as an internet-facing multi-tenant security boundary. The API and dashboard
never receive it. All services bind to loopback.

## Build and verify locally

From the repository root with Python dependencies installed and Docker Linux running:

```sh
docker info --format '{{.OSType}}'
docker compose --profile worker build api dashboard worker
python scripts/worker_smoke.py
```

The smoke script uses a fresh Compose project/volumes, ports 18000 and 13000, and
random in-memory developer/reviewer/admin tokens sent only to the API server.
No token is embedded in the dashboard. It clones committed HEAD from this checkout
without changing any existing files or making commits; dirty work stays untouched.

It submits a T2 JSON plan, rejects premature execution/developer self-approval,
approves as a reviewer, queues, and waits for the worker's persisted result.
The positive plan writes `demo_math.py`. Immutable tests in the image (not the
editable worktree) verify its output plus UID, network, socket and filesystem
isolation; Ruff and Mypy independently check that file. An incorrect implementation
must fail. Admin kill-switch denial and result survival after API restart are
also checked. Success is computed from actual commands, never from a model message.

Output: `reports/worker-smoke.json`, containing real IDs, gate output and hashes.
The script stops its services when finished but retains every volume/container;
it does not delete/reset existing data. The dashboard HTTP smoke only verifies
static availability, not an authenticated browser workflow.

## Normal worker configuration

`docker compose --profile worker up` is opt-in. Supply server authentication
through environment variables; keep credentials out of source and public bundles.
`ASTRA_SOURCE_REPO` selects a local Git checkout (default this folder).
`ASTRA_WORKSPACE_VOLUME` names its workspace volume. On Linux set
`ASTRA_DOCKER_GID` to the Docker socket group if it is not 0. Existing cloned
repositories are preserved, not silently refreshed or reset.

Without `ASTRA_WORKER_GATES_JSON`, all five default gates are mandatory: tests,
lint, typecheck, Semgrep and Gitleaks. Missing scanners fail verification. The smoke
script explicitly configures a **demo-only** tests/lint/typecheck profile. This is
not scanner evidence and does not clear the critical Next.js audit finding.

`GET /tasks/{id}/result` returns the durable request and verification result and
requires bearer authentication. Admin-only `GET`/`POST /controls/kill-switch`
stores the switch durably. The worker rechecks it, approval validity, scope,
cancellation, step and time budgets at execution boundaries. An active command
is timeout-bounded; cancellation is cooperative between boundaries, not instant.
One worker process owns its stable ID; interrupted claimed work is failed closed
on worker restart, never replayed. No model calls occur, so token/cost use is zero.

## Still blocked for production

Missing verified security scans, multi-tenant Docker isolation, and model-backed
planning remain outside this demo's verified scope. The dashboard now uses a
server-side Next runtime with login/session/proxy routes, but that local flow is
not production identity provisioning. Do not publish/deploy it as a secure
autonomous production agent. Competition publication/submission remains a
separate human-authorized action.
