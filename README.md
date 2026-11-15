# Astra Coder

Astra Coder is an evidence-first, local-first autonomous coding-agent control plane. It routes work through policy, typed tools, isolated execution, Git safety, and independent verification instead of trusting a model's success message.

> The repository is built in numbered stages. Optional integrations such as Ollama, Docker, Semgrep, gitleaks, and remote model providers fail closed when unavailable; offline tests use deterministic fakes.

## Competition demo scope

The local demo supports authenticated submission, reviewer approval, durable
queuing, and an opt-in **structured-plan worker** in Compose. It performs real
edits in task-scoped Docker containers and records independent verification and
durable results. An execute response still means **queued**, not successful.
This is not a verified natural-language/model-driven coding agent or a secure
public production service. The dashboard has a local server-side login/session
flow and same-origin API proxy, but no production identity-provider
provisioning. See [worker demo](docs/worker-demo.md) and the
actual [execution evidence](reports/worker-smoke.json).

See [competition submission notes and demo walkthrough](docs/competition-submission.md)
for current evidence, limitations, official rules, and outstanding submission checks.

## Requirements

- Python 3.12.2 (pinned in `.python-version`)
- Docker Engine/Desktop for sandbox integration tests
- Node.js 20.11.1 for the optional dashboard
- Git

## Setup

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
cp .env.example .env  # optional; never commit .env
```

## Run

```bash
astra doctor
astra --help
uvicorn astra_coder.api:app --host 127.0.0.1 --port 8000
```

The API is intentionally loopback-bound by default. Configure provider endpoints and credentials through environment variables only.

## Test and quality gates

```bash
make test
make lint
make typecheck
make security
```

`make test` is the canonical offline test command. `make security` requires Semgrep and gitleaks; if either is unavailable it fails closed. Release CI installs both tools.

## Dashboard

The Next.js dashboard is an optional client under `dashboard/`. It never owns orchestration state; it consumes the FastAPI API and SSE event stream.

```bash
cd dashboard
npm ci
npm run dev
```

## Architecture and security

Read [docs/BLUEPRINT.md](docs/BLUEPRINT.md), [docs/MARKET_ANALYSIS.md](docs/MARKET_ANALYSIS.md), and [SECURITY.md](SECURITY.md). Agent-generated commands are never executed on the host by the secure path. Work is isolated per task and success requires independent evidence.

The API authorizes and durably queues requests; the opt-in `worker` Compose
profile runs `astra_coder.worker_main`. Tasks in this mode contain JSON `Plan`
inputs, not free-text model prompts. Worker tools and verification run through
DockerSandbox; the API has no Docker socket. Default verification still requires
all five gates, including scanners. The scoped arithmetic demo uses explicit
image-side tests, lint, and types and is not a passing security-release gate.

## Development stages

Stage acceptance records live in `docs/stages/`. Each stage has a focused implementation, tests, evidence, and a Git commit. The benchmark and release report are generated under `docs/benchmarks/` and `FINAL_REPORT.md`.
