# Astra Coder Operations Runbook

For the opt-in structured-plan Compose worker and reproducible live smoke, use
[docs/worker-demo.md](docs/worker-demo.md). This does not require a frontend token
or change the blocked production security-release status.

## Local start

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
astra doctor
uvicorn astra_coder.api:app --host 127.0.0.1 --port 8000
```

The API defaults to loopback. Keep it behind an authenticated reverse proxy for team use. Set provider URLs and credentials through environment variables; never put them in `.env` committed to Git.

## Compose start

```bash
# Supply server-side dashboard values from a private shell/secret manager. Never
# put production credentials in a static bundle or commit these values.
export ASTRA_AUTH_MODE=tokens
export ASTRA_AUTH_TOKENS='{"<api-token>":{"actor_id":"local-developer","role":"developer"}}'
export ASTRA_DASHBOARD_ORIGIN='http://127.0.0.1:3000'
export ASTRA_DASHBOARD_API_TOKEN='<api-token>'
export ASTRA_DASHBOARD_LOGIN_TOKEN='<dashboard-login-token>'
export ASTRA_DASHBOARD_SESSION_SECRET='<at-least-32-character-secret>'
docker compose config
docker compose build api dashboard
docker compose up -d
curl http://127.0.0.1:8000/health
open http://127.0.0.1:3000
```

The Compose API and dashboard bind to loopback. The API data-init helper only
sets ownership on the existing named volume so the non-root API can use SQLite;
it does not delete or reset data. The dashboard is a static export served by a
non-root Nginx process on container port 8080. Review mounts, image digests,
and environment values before exposing them beyond one machine.

## Task flow

```bash
astra submit --repo /path/to/repo --task "describe the change" --risk T1
astra status TASK_ID
astra diff TASK_ID
astra approve TASK_ID
astra execute TASK_ID
astra deny TASK_ID --reason "not authorized"
astra cancel TASK_ID
```

T2+ work is approval-gated by default. `execute` only authorizes and durably queues
the task; the API process never runs agent commands. A dedicated worker claims the
queue, creates the task worktree, uses Docker-backed command and verification
adapters, and persists the terminal result. Approval does not make a task
successful; independent verification still must pass.

## Health and recovery

- `GET /health` checks API process availability only.
- Inspect task state and audit SSE events for policy, provider, sandbox, and verification evidence.
- On restart, incomplete tasks are failed closed by `StateStore.recover_after_restart`; re-run verification before any retry.
- Do not use `git reset --hard` or `git clean` in a user's repository. Roll back only task worktrees through `GitSafety`.
- If the kill switch is enabled, investigate the audit trail and clear it only through an admin policy action.

## Release gates

```bash
make test
make lint
make format
make typecheck
make security
cd dashboard && npm ci && npm test && npm run lint && npm run build && cd ..
PYTHONPATH=src python -m astra_coder.benchmark
docker compose config
```

A missing external scanner, Docker daemon, runtime, or provider is not a pass. Record it as unavailable and do not tag a release.
