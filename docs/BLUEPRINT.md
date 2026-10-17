# Astra Coder v1.0 — Production Blueprint

**Status:** implementation contract  
**CLI:** `astra`  
**Primary users:** individual developers, platform teams, and enterprises that need autonomous software work without giving an unbounded model direct host access.

## 1. Product promise

Astra Coder is a model-agnostic, local-first coding agent. It accepts a natural-language engineering task, builds repository context, plans bounded work, edits only inside a task workspace, observes independent verification results, and returns an evidence-backed result. Every meaningful action is policy-checked and auditable. A model's claim that work is complete is never sufficient for success.

The differentiator is not simply “another chat-to-code UI.” Astra combines:

- local-first model selection with explicit cost and privacy policy;
- a single-writer, typed tool mesh;
- Docker-isolated execution with fail-closed security defaults;
- Git worktrees and rollback that preserve pre-existing user changes;
- independent verification with machine-readable evidence;
- durable state, append-only audit records, approval gates, and restart recovery;
- a CLI-first workflow that can be used headlessly, through FastAPI/SSE, or through a dashboard.

## 2. Locked technology contract

| Area | Required choice |
|---|---|
| Runtime | Python 3.12, pinned by `.python-version` |
| API | FastAPI, Pydantic v2 |
| CLI | Typer |
| Persistence | SQLAlchemy 2 + SQLite by default |
| Quality | pytest, ruff, mypy |
| Security tools | Semgrep and gitleaks when installed; unavailable tools fail closed in release gates |
| Repository intelligence | tree-sitter, ripgrep, deterministic fallback scanners |
| Isolation | Docker with explicit security flags |
| Models | Ollama/local first, OpenAI-compatible adapters, optional premium providers |
| Observability | structlog and OpenTelemetry-compatible events |
| Dashboard | Next.js 14 + Tailwind, isolated under `dashboard/` |

The dependency lockfile, Dockerfile, and `make test` are mandatory. External provider keys are environment-only. The code must work offline for tests using fakes and deterministic fixtures.

## 3. Deterministic architecture

Requests flow through these layers in order:

1. **Intake:** CLI, HTTP, or dashboard submits a typed task.
2. **Orchestrator and policy gate:** authenticate actor, classify risk, enforce budgets/kill switch, and require approval when policy says so.
3. **Repository intelligence:** discover files, symbols, dependencies, search matches, and a bounded context package.
4. **Agent loop:** Architect/Planner → Editor/Operator → Observe → Independent Reviewer → bounded Repair.
5. **Model gateway:** classify task, choose a local-first route, meter cost/tokens, retry only within a budget, and open a circuit on repeated provider failures.
6. **Tool mesh:** expose typed read/search/patch/shell/test/git tools; all paths and commands are validated before execution.
7. **Sandbox:** execute tests and commands in Docker using network isolation, read-only root, dropped capabilities, non-root user, resource limits, and a timeout.
8. **Evidence and recovery:** collect verification results, audit events, diffs, costs, logs, and state transitions; commit/checkpoint only through the Git safety layer.

No layer may bypass a preceding policy decision. The orchestrator is the only component allowed to advance task state. The editor is the only writer for a task workspace.

## 4. Agent loop and state machine

The canonical flow is:

```text
RECEIVED → POLICY_CHECKED → CONTEXT_BUILT → PLANNED → APPROVED?
  → EDITING → OBSERVING → VERIFYING → REVIEWING
  → REPAIRING (bounded) → SUCCEEDED | FAILED | CANCELLED | BLOCKED
```

Rules:

- Each transition is explicit, validated, timestamped, and persisted.
- The loop has hard maximum steps, wall-clock duration, repair attempts, output tokens, and estimated spend.
- Cancellation is cooperative first and forceful at sandbox timeout.
- A task cannot become `SUCCEEDED` without independent verification evidence and a clean policy decision.
- A failed, timed-out, denied, or unavailable verification gate cannot be converted to success by model text.
- Repair is reproduce-first: preserve the failing evidence, make one bounded change, rerun the same gate, and stop after the configured cap.

## 5. Risk, policy, and governance

Roles are `viewer`, `developer`, `reviewer`, `operator`, and `admin`. Permissions are evaluated at every sensitive action; role labels supplied by a model are ignored. Risk tiers:

- **T0:** read-only search, formatting, context preparation.
- **T1:** local edits and offline tests in a disposable worktree.
- **T2:** multi-file edits, dependency changes, or commands that consume significant resources.
- **T3:** networked/external side effects, secrets, deployment, destructive Git operations, or production-facing changes.
- **T4:** security-sensitive or irreversible operations; explicit human approval and independent review are mandatory.

Policy controls include per-task and daily token/spend budgets, step and time budgets, allowed path roots, command allow/deny rules, provider restrictions, approval requirements, kill switch, and audit retention. A kill switch stops new work and interrupts active work at the next safe boundary. Policy bypass attempts are audit events and fail closed.

## 6. Local-first model routing

The gateway has a provider registry and adapter interface. Provider names, base URLs, models, and prices are configuration data, never hard-coded secrets.

| Tier | Work | Default route | Fallback |
|---|---|---|---|
| T0 | Search, format, trivial transforms | deterministic tools/local embedding | none |
| T1 | Routine coding and boilerplate | Ollama local coder | cheap OpenAI-compatible provider |
| T2 | Multi-file work and debugging | stronger local model | DeepSeek/paid coding provider |
| T3 | Architecture and hard reasoning | configured premium provider | stop and request approval |
| T4 | Final review/security | independent configured reviewer | static scanners + fail-closed review |

Routing considers task risk, privacy policy, model capability, latency, cost, context length, and provider health. “Local-first” means the gateway tries an eligible local route before a remote route; it does not pretend a local model is installed. If no eligible provider is available, the task is `BLOCKED` with evidence.

## 7. Repository intelligence

The indexer builds a deterministic snapshot containing:

- ignored-file-aware tree;
- tree-sitter symbols and source ranges when a grammar is available;
- imports/dependencies and reverse references where detectable;
- ripgrep search results with bounded output;
- file hashes and incremental change detection;
- a context package scored for task relevance and capped by tokens/bytes.

Untrusted repository text is data, not instructions. `AGENTS.md`, `ASTRA.md`, and similar files are treated as policy input only after validation and are never allowed to change system safety rules.

## 8. Typed tool mesh

Every tool has a Pydantic input/output schema, a stable name, an audit event, and a policy requirement. Initial tools:

- `read_file`, `list_tree`, `search_text`;
- `write_patch` with an expected-base hash;
- `run_command` and `run_tests` routed through the sandbox;
- `git_diff`, `git_checkpoint`, and `git_rollback` through Git safety;
- `approve`, `deny`, and `cancel` control actions.

Security requirements: resolve paths under an approved root, reject traversal and symlink escapes, reject absolute paths outside the root, use argv arrays instead of shell interpolation, enforce command policy, cap output, redact secrets in logs, and serialize writes with a single-writer lock.

## 9. Sandbox contract

The default Docker invocation must include:

```text
--network=none
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges:true
--pids-limit=<bounded>
--memory=<bounded>
--cpus=<bounded>
--user=<non-root>
--mount=<task-worktree>:<workspace>:rw
--tmpfs=/tmp:rw,noexec,nosuid,size=<bounded>
```

Images are pinned by digest in release deployments. Secrets are not mounted into the sandbox by default. If Docker is unavailable, the secure execution path returns an explicit unavailable result; it never silently executes agent shell commands on the host. Tests may use a fake runner for offline behavior and separate integration tests when Docker is available.

## 10. Git safety

A task gets an isolated worktree created from a recorded base revision. Before any agent write, Astra records the user's pre-existing dirty state. Checkpoints are immutable metadata plus Git refs. Rollback acts only on the task worktree/ref and never calls `reset --hard`, `clean`, or deletion against the user's original worktree. If the base worktree is dirty, the task remains isolated and a merge/apply step requires explicit human review.

## 11. Verification and success rules

The verification engine runs configured commands independently of model output: tests, ruff, mypy, Semgrep, gitleaks, and project-specific checks. Each gate records command, environment class, exit code, duration, bounded stdout/stderr, parsed findings, and an evidence hash.

A task is successful only when:

1. required gates were actually run;
2. all required gates passed or an explicit, policy-approved waiver exists;
3. no security gate is unavailable or failed;
4. the final diff is inside the approved workspace and passes the expected-base check;
5. the reviewer accepted the evidence; and
6. the state transition is persisted atomically.

No output phrase, green-looking log line, or model self-review can satisfy these requirements.

## 12. Persistence, audit, and observability

SQLite stores tasks, transitions, approvals, provider calls, cost meters, verification runs, checkpoints, and recovery metadata. The audit log is append-only with sequence numbers, actor, action, target, policy decision, timestamp, request correlation ID, and hash chaining. Sensitive values are redacted before storage. Structured logs and OpenTelemetry spans use the same correlation ID but never include prompts, tokens, or secrets by default.

On restart, non-terminal tasks resume only from a durable safe boundary. In-flight sandbox processes are treated as interrupted and require re-verification. Replay reads the event chain without mutating the repository.

## 13. Interfaces

### CLI

```text
astra submit --repo PATH --task TEXT [--risk T1] [--json]
astra status TASK_ID [--follow]
astra diff TASK_ID
astra approve TASK_ID
astra deny TASK_ID --reason TEXT
astra cancel TASK_ID
astra doctor
```

### API

FastAPI exposes typed task submission, task status, diff, approval, cancellation, health, and SSE event endpoints. Authentication is a configurable boundary; local development defaults to loopback only. SSE events are replayable from a cursor and do not expose secrets.

### Dashboard

The Next.js client displays task list/status, live events, diff, approvals, evidence, and cost. It is a client of the API, not a second orchestrator. UI tests cover loading, empty, denied, failed, and successful evidence states.

## 14. Benchmark and release gates

The benchmark harness contains 70 deterministic tasks across small edits, bug fixes, multi-file work, verification repair, context stress, provider failure, policy bypass, path traversal, prompt injection, and rollback preservation. It reports success only from evidence records and records latency, cost, repairs, and failure class.

Release requires:

- clean Linux clone/build;
- pinned runtime and lockfile;
- `make test`, ruff, mypy, Semgrep, and gitleaks;
- sandbox integration checks when Docker is available;
- rollback preservation test;
- no secrets in the tree or history;
- no false-success test failures;
- completed `FINAL_REPORT.md` with known limitations.

## 15. Explicit non-goals for v1.0

- No claim that Docker is a perfect security boundary against a compromised host kernel.
- No automatic production deployment or secret access by default.
- No requirement that remote providers be available for offline tests.
- No claim of parity with proprietary model quality; Astra improves control, evidence, portability, and governance around available models.

## 16. Definition of done

Astra Coder v1.0 is done when a clean machine can install the pinned dependencies, run the offline test suite, start the CLI/API, submit a task against a fixture repository, observe a bounded plan/edit/verify flow, inspect evidence and diff, approve or reject policy-gated work, and recover safely after interruption. Documentation must make every unavailable optional integration explicit instead of masking it.
