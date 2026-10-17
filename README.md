# Astra Coder

Astra Coder is an evidence-first, local-first autonomous coding-agent control plane. It routes work through policy, typed tools, isolated execution, Git safety, and independent verification instead of trusting a model's success message.

> The repository is built in numbered stages. Optional integrations such as Ollama, Docker, Semgrep, gitleaks, and remote model providers fail closed when unavailable; offline tests use deterministic fakes.

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

`make test` is the canonical offline test command. `make security` runs Semgrep and gitleaks when available and returns a clear unavailable status otherwise; release CI installs those tools and requires them.

## Dashboard

The Next.js dashboard is an optional client under `dashboard/`. It never owns orchestration state; it consumes the FastAPI API and SSE event stream.

```bash
cd dashboard
npm ci
npm run dev
```

## Architecture and security

Read [docs/BLUEPRINT.md](docs/BLUEPRINT.md), [docs/MARKET_ANALYSIS.md](docs/MARKET_ANALYSIS.md), and [SECURITY.md](SECURITY.md). Agent-generated commands are never executed on the host by the secure path. Work is isolated per task and success requires independent evidence.

## Development stages

Stage acceptance records live in `docs/stages/`. Each stage has a focused implementation, tests, evidence, and a Git commit. The benchmark and release report are generated under `docs/benchmarks/` and `FINAL_REPORT.md`.
