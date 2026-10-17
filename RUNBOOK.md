# Astra Coder Operations Runbook

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
docker compose config
docker compose build
docker compose up -d
curl http://127.0.0.1:8000/health
open http://127.0.0.1:3000
```

The Compose API and dashboard bind to loopback. Review mounts, image digests, and environment values before exposing them beyond one machine.

## Task flow

```bash
astra submit --repo /path/to/repo --task "describe the change" --risk T1
astra status TASK_ID
astra diff TASK_ID
astra approve TASK_ID
astra deny TASK_ID --reason "not authorized"
astra cancel TASK_ID
```

T2+ work is approval-gated by default. Approval does not make a task successful; independent verification still must pass.

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
