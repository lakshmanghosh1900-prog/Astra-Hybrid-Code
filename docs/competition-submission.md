# ASTRA CODER — competition submission draft

> Historical eligibility review from before the Compose worker integration.
> Current execution scope and run instructions are in [worker-demo.md](worker-demo.md);
> current live evidence is in [worker-smoke.json](../reports/worker-smoke.json).
> The rules/registration/publication checks below remain unconfirmed. Historical
> statements about the missing worker or Docker prerequisites are superseded.

Prepared from the current workspace and prior verified checks. No publication,
deployment, or submission is authorized by this document.

## Accurate feature summary

ASTRA CODER is a local-first developer task-control prototype. Its verified scope
is authenticated task intake, reviewer approval, durable execution-request
queuing, cancellation, and replayable audit events. A dashboard displays task
state and approval controls. Worker, worktree, sandbox, and verification
components have offline tests, but a deployed autonomous execution flow is not
operational or verified. Queue acceptance is never execution success.

Recommended track: **Developer Tools & Open Source**. This is a recommendation,
not confirmation of the track selected in the participant's account.

## Official rules checked

Primary source: https://omnirush.ai/buildathon

- Submission: **20 October 2026, 11:59 PM IST** (18:29 UTC), by the server clock.
- Registration/joining: **19 October 2026, 11:59 PM IST**.
- Rules: "OmniRush is your only AI"; "Solo"; "Open source. A public GitHub repo."
- Evidence: "Submit the repo with a README and the OmniRush sessions you built it in."
- Judging: "It does what the README says" and "Small and polished beats big and broken."
- Rebuild: "Judges rebuild every project from scratch in Docker on a clean Linux
  machine and run its tests offline."
- FAQ 11: "Neither is required" for video and live link. A 2–3 minute video is
  recommended; a clear README and tests suffice for a CLI tool or library.
- FAQ 9: "Start fresh during the event." Code not from OmniRush sessions is
  flagged for review. Local Git timestamps are not proof of session provenance.
- Step 6: publish to the connected account's public GitHub repository, enter
  track/repository/sessions in the console, then paste its Submission ID into Unstop.

Submission console: https://omnirush.ai/console/buildathon

Linked event: https://unstop.com/p/omnirush-agentic-buildathon-2026-omnirush-1769914

The public console and Unstop fetches returned loading shells, so account-specific
registration, form fields, and any additional participant-only conditions remain
unverified. No published rule on the primary page requires autonomous execution
or expressly disqualifies a queue-only prototype. This is not an organizer ruling.

General terms: https://omnirush.ai/terms

Terms require age 18+, lawful use, and rights to shared content. They state a
7-day GitHub-account minimum, whereas the event page states 3 days. Confirm any
account-age issue in the console/with organizers rather than assuming an exemption.

## Evidence already obtained (not rerun for this document)

| Check | Latest evidence |
| --- | --- |
| Python suite | `python -m pytest`: 102 passed, 1 skipped, 3 warnings |
| Python lint / formatting | Ruff check passed; 37 files formatted |
| Python types | Mypy passed for 20 source files |
| Whitespace | `git diff --check` passed before this documentation edit |
| Dashboard tests | `npm test`: 4 passed |
| Dashboard lint / types | `npm run lint`, `npx tsc --noEmit`: passed |
| Dashboard build | `npm run build`: passed with Next 15.5.28 and server routes |
| Docker | Earlier images ran; latest Linux-engine check/build failed: engine pipe absent |
| Dependency audit | `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities after Next 15.5.28 |
| Security scanners | Semgrep/Gitleaks not runnable in the last Windows checks; no current scan pass |

Local checks used Python 3.12.10 and Node 24.18.0. Repository pins are Python
3.12.2 and Node 20.11.1. These results do not prove a clean pinned-Linux rebuild.

## Known limitations and actual submission blockers

- The linked public repository currently displays "This repository is empty":
  https://github.com/lakshmanghosh1900-prog/Astra-Hybrid-Code
  The current uncommitted/untracked local changes are not a published entry.
- Registration, connected GitHub ownership, selected sessions, exclusive OmniRush
  use, and age eligibility have not been confirmed. Local commits are dated
  17 October 2026, within the event, but this does not establish all eligibility.
- Docker unavailability is local infrastructure, not proof of broken code.
  Separately, the current root Dockerfile installs neither Git nor make, while
  tests/task intake need Git and the documented test command uses make.
  `.dockerignore` excludes `.git`; tests using `Path.cwd()` need self-contained
  Git fixtures. Compose also mounts no target Git repository. A new image build
  alone cannot establish that submission or offline tests work in that image.
- No worker service or model-to-plan process is wired into Compose. Do not launch
  a worker for this demo or claim a task reached success through sandbox execution.
  Approval binding, execution-time budgets, durable kill-switch propagation,
  queue concurrency, and independent verification are not production-proven.
- `GET /tasks/{id}/diff` returns Git status, not a reviewed patch. The dashboard's
  generic running category may include `context_built`; it is not worker evidence.
- The dashboard now uses a server-side Next runtime with login/session/logout and
  a same-origin API proxy. `ASTRA_DASHBOARD_API_TOKEN`,
  `ASTRA_DASHBOARD_LOGIN_TOKEN`, and `ASTRA_DASHBOARD_SESSION_SECRET` remain
  server-only; never place them in browser bundles or expose this local setup
  publicly. The browser workflow still needs a fresh authenticated rehearsal.
- The dashboard dependency was upgraded to supported Next 15.5.28 after checking
  the current advisory ranges. `npm audit --omit=dev --audit-level=high` now
  reports zero vulnerabilities. The server runtime still requires fresh
  authenticated rehearsal and controlled deployment; an audit pass is not a
  production security certification.
- A full `npm audit --audit-level=high` still reports development-tool findings
  in Vitest/Tailwind transitive dependencies. The available Vitest 5 fix needs
  Node 22.12+, beyond the pinned Node 20.11.1 runtime, and the Tailwind 4 fix is
  a major CSS/tooling migration. This remains a development-gate limitation,
  not a claim of zero total dependency findings.
- Linux-style scanner files exist locally, but no current successful Windows scan
  is established. Historical scan reports do not cover current changes.
- The event page does not list scanner passes or zero audit findings as standalone
  eligibility requirements. They remain security-release blockers, not automatically
  a published competition disqualification. Do not publicly deploy this build.

## Short non-executing demo walkthrough (record only after rehearsal)

Use a local checkout with Git and a valid HEAD. Use one continuously running API
process; do not switch to separate CLI service invocations during the walkthrough.

1. Follow root README setup. Supply `ASTRA_AUTH_MODE=tokens` and a server-side
   `ASTRA_AUTH_TOKENS` environment map with distinct developer and reviewer actors.
   Keep real values outside the repository, recording, and frontend bundle.
2. Set `ASTRA_DATABASE_URL=sqlite:///./competition-demo.db` to separate demo state
   from existing data, and `ASTRA_REPO_ROOT` to the checkout's actual root. Start:
   `uvicorn astra_coder.api:app --host 127.0.0.1 --port 8000`.
3. Show `GET /health` and an unauthenticated `GET /tasks` returning 401.
4. With the developer bearer token, `POST /tasks` using a harmless prompt,
   the actual Git checkout as `repo_path`, and `risk: "T2"`. Show `awaiting_approval`.
5. Show developer `POST /tasks/{id}/execute` being denied before approval.
6. Use the distinct reviewer token for `POST /tasks/{id}/approve`.
7. Use the developer token for `POST /tasks/{id}/execute`. Show HTTP 202 and
   `context_built`; explicitly say "accepted into the queue, NOT executed".
8. Show authenticated `GET /tasks/{id}/events`, then developer
   `POST /tasks/{id}/cancel` and the resulting `cancelled` state. No repository
   changes, model calls, worker launch, or successful execution are demonstrated.

The sequence has API regression coverage; a fresh live recording is still needed.
The dashboard is optional for this walkthrough, not a claim of a verified browser
session. Do not record tokens, prompts containing private data, or provider keys.

## Options and recommendation

| Option | Assessment | Effort / risk |
| --- | --- | --- |
| A: submit unchanged queue-only build | Queue-only is not prohibited, but current README/deployment/rebuild gaps and empty public repo remain | 30–60 min packaging alone; high judging/rebuild risk |
| B: finish autonomous worker | No published requirement makes this necessary; all live claims would need proof | Several hours to a day or more; high uncertainty; not the deadline recommendation |
| C: minimal safe queue-only candidate | Best match for "Small and polished beats big and broken"; no public deployment needed | Estimate 1–3 hours if Linux/Docker is available, plus human publication/registration checks |

Choose **C**: accurately scope the entry as developer task governance, fix only
clean-Linux Git/test prerequisites and misleading demo instructions/labels,
verify the queue-only flow, and record it. No promise of winning or final eligibility.

## Required artifacts and human checklist

- Confirm timely registration and connected GitHub account in the console.
- Confirm solo work, event-start provenance, and OmniRush-only generative AI use.
- Authorize publication separately, then publish the actual source/lockfiles,
  runtime pins, Dockerfile, tests, README, `.env.example`, and license to the
  connected account's public repository. Never publish databases, credentials,
  local logs, generated package metadata, or accidental backup files.
- Verify a fresh pinned Linux Docker build and offline test command; rehearse the
  exact API-only sequence once against an isolated demo database.
- In the console enter the track, repository, and actual matching session IDs.
  Save the Submission ID and paste it into the linked Unstop event before cutoff.
- Optional: add a genuine 2–3 minute unlisted video; no live URL or screenshots
  exist as verified artifacts of this review. A screenshot is suggested in the
  guide's README advice, not listed as a separate mandatory submission field.
- Re-read any additional authenticated-console/Unstop conditions. Organizer support:
  https://discord.gg/46jpGgeg2t

**Current decision: INSUFFICIENT EVIDENCE for final eligibility.** A queue-only
entry appears permissible under the published scope, but the public source,
registration/session checks, accurate demo, and clean rebuild remain outstanding.
