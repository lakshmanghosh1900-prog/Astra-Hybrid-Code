# Stage 04b — Free-Cascade Model Gateway: Architecture & Integration Contract

Status: **implemented + wired in working tree (Phase 1-3, 5, 6 complete), pending reviewed commit; NOT pushed; certification pending final governance — see docs/stages/04b.md**
Branch: `feat/v1.0.1-free-cascade`
Base: `main` @ `30be0c025be7f786f5763cb2085f44cada38f812`
Tag baseline: `v1.0.0` @ `30be0c025be7f786f5763cb2085f44cada38f812`
Stage HEAD at authoring: `43439cad69fd6af9b9fb2b68a97b48c8de9b7daf`

This document is the reviewable contract for the post-v1.0.0 free-tier cascade work. Stage 04b is
now implemented and wired in the working tree; implementation, config, tests, and evidence live in
the companion files listed in docs/stages/04b.md. Nothing is pushed. `main` and `v1.0.0` are
untouched.

Canonical source: Report B structure + 12 conflict rulings (Appendix A) + 4 locked operator
decisions (Section 10, D-1..D-4). Where Report A and Report B diverged, Appendix A is authoritative.
Rejected alternatives in Section 10.3 must not be reintroduced.

---

## 0.0 Stage 04b security hardening (post-review implementation notes)

The following controls are now implemented and enforced in code. The 12 conflict rulings in
Appendix A and the 4 locked operator decisions D-1..D-4 in Section 10 remain **locked and
unchanged**; nothing in this section alters them.

- **NETWORK evaluation point (Phase 1A).** `Action.NETWORK` is evaluated by `PolicyEngine.evaluate()`
  in `NetworkAuthorizer.authorize()` (`src/astra_coder/security.py`) at the worker boundary, invoked
  by `BudgetRunner.complete()` (`src/astra_coder/free_cascade.py`) **before** `ModelGateway.generate()`.
  A deny is fail-closed: no provider call, an audited `network_decision=deny` event, and no fallback.
  Production gateways are built with `require_network_authorization=True`, so `generate()` called
  without an `allowed_keys` decision raises `NetworkAuthorizationRequired`.
- **T4 recorded approval (Phase 1B).** `ASTRA_ALLOW_REMOTE_T4=true` is a flag, not an approval. Remote
  T4 also requires a `RemoteApproval` object carrying `approval_id`, `approver`, `task_id`,
  `provider`, `created_at`, `expires_at`, `paid`. Missing, expired, or task-mismatched approvals deny.
  Each decision (with approval id) is written to the audit sink.
- **Paid provider permission (Phase 1C).** `ASTRA_ALLOW_PAID_REMOTE=true` still requires the provider
  to be `paid_authorized`, an `Action.SECRETS` grant, and an explicit paid `RemoteApproval`. Default
  `false` stays fail-closed.
- **Secret redaction (Phase 1D).** `SecretRedactor` (denylist + regex + configured env values) is
  applied to the prompt and to repo/task context in `_render_prompt()` before any remote send. Secrets
  never reach the provider mock, the audit prompt field, logs, or errors.
- **Mandatory audit sink (Phase 1E / Gap C).** Every gateway decision emits provider, model,
  decision, reason, skip_reason, budget, tokens, approval id, actor, and task id. The production
  composition fails closed when the audit sink is absent (`NetworkAuthorizer` and `BudgetRunner`
  both reject a `None` sink).
- **Kill switch (Phase 1F).** `PolicyEngine` kill switch blocks `Action.NETWORK` at the authorizer,
  not only local actions.
- **TaskLimits preflight (Gap A).** `BudgetRunner.complete()` enforces `TaskLimits.max_tokens` and
  wall-clock budget before any provider call, raising `BudgetExceeded` with an audited deny.
- **Single classification (Gap B).** `eligible_specs()` and `generate()`/`candidate_plan()` share one
  tier/free/context/breaker classifier.
- **Cascade order validation (Gap F).** `ASTRA_FREE_CASCADE_ORDER` is validated at startup; empty,
  duplicate, or unknown providers raise `ValueError` fail-closed (no silent default).
- **OpenRouter global invariant (Gap G).** Registration and selection reject any non-`:free`
  OpenRouter model regardless of `free_tier`/`free_only`/`allow_paid_remote` flags unless an explicitly
  `paid_authorized` spec is combined with NETWORK + SECRETS + explicit paid approval. The free path
  enforces the `:free` suffix in `is_free_qualified()` and `skip_reason()`. The `ASTRA_OPENROUTER_FREE_ONLY`
  toggle was removed (see Section 10 env table).

---

## 0. Scope, invariants, and non-goals

### 0.1 Goal

Extend the existing Stage 04 gateway so that Astra Coder can plan with:

```
Ollama (local)
  -> NVIDIA NIM (free tier)
  -> OpenRouter (:free models only)
  -> Groq (free tier)
```

with deterministic ordering, explicit free-tier eligibility, hard budget enforcement, environment-only
credentials, and unchanged fail-closed orchestration semantics.

### 0.2 Contract invariants

1. **Capability floor is absolute.** A provider is never selected below the effective required
   `ModelTier`, even if it is local or free.
2. **Local-first is preserved.** `local=True` is a routing preference, not a capability waiver.
   Free-tier-first describes only the remote ordering. There is no global free-first mode.
3. **Free is explicit.** A model is free only when `ModelSpec.free_tier is True` AND its
   cost is `0.0` AND, for OpenRouter, its id ends with `:free`. Cost `0.0` alone is not proof.
4. **Keys are environment-only.** Missing keys disable providers; keys never enter logs, errors,
   audit metadata, prompts, or model responses.
5. **Budgets are ledgers, not hints.** A denied budget stops the call before network I/O; actual
   usage is still charged so the ledger cannot be understated.
6. **No model-controlled success.** The model still only produces a `Plan`; the existing editor,
   verifier, and independent reviewer decide success.
7. **All failure modes fail closed.** No empty plan, no fabricated evidence, no fallback to an
   unapproved provider, no silent tier downgrade.
8. **Determinism.** Ordering, retries, breaker behavior, and budget decisions are injectable and
   deterministic under test; no real network or credential is needed for acceptance tests.

### 0.3 Non-goals / must NOT be built

- No new HTTP transport framework, OpenAI SDK, LiteLLM, async gateway, streaming, or tool-calling
  protocol.
- No second classifier, second retry engine, or second circuit breaker.
- No second gateway class. Extend `ModelGateway` only.
- No second budget engine. `PolicyEngine` is the enforcement ledger.
- No secrets manager, keychain integration, or hot key reload in v1.0.1.
- No changes to `Plan` / `PlanAction` schema, `TaskState` machine, `TaskOrchestrator` control flow,
  `EditorAgent` tool allowlist, `IndependentReviewerAgent`, or `VerificationEngine`.
- No changes to approval semantics, `PolicyEngine.evaluate` RBAC, kill switch, Git safety, or
  sandboxing.
- No automatic paid fallback. Paid remote requires an explicit operator flag plus policy permission.
- No automatic capability downgrade to make a free provider fit.

---

## 1. Existing gateway reuse strategy

| Component | Decision | Contract detail |
|---|---|---|
| `ModelSpec` | **Extend** | Add `free_tier: bool = False`, `cascade_priority: int = 100`, and optional `api_key_env: str \| None = None`. Keep `provider`, `model`, `tier`, `local`, `context_tokens`, `input_cost_per_1k`, `output_cost_per_1k` unchanged. |
| `ModelRequest` | **Extend** | Add `allow_paid_remote: bool = True` so Stage 04 callers keep working; the free-cascade composition layer sets it to `False` by default. Keep `prompt`, `risk`, `required_tier`, `allow_remote`, `max_output_tokens`. |
| `ModelResponse` | **Extend (optional field)** | Add `usage_estimated: bool = False` for providers that omit usage. Existing fields `content`, `provider`, `model`, `input_tokens`, `output_tokens`, `cost` remain authoritative. |
| `ProviderKind` | **Extend** | Add `NVIDIA_NIM = "nvidia_nim"`, `OPENROUTER = "openrouter"`, `GROQ = "groq"`. Canonical provider id for NVIDIA is `nvidia_nim`, not `nim`. |
| `Provider` protocol | **Reuse unchanged** | One method: `complete(spec, request) -> ModelResponse`. |
| `OllamaProvider` | **Reuse unchanged** | Local HTTP adapter; no key; existing 30 s timeout. |
| `OpenAICompatibleProvider` | **Reuse + minimal extension** | One class serves NVIDIA NIM, OpenRouter, and Groq because all expose `/chat/completions`. Optional `default_headers: Mapping[str, str] \| None = None` (OpenRouter attribution) and `trust_env: bool = False` for remote adapters. No new provider classes. |
| `ProviderError` | **Extend** | Add `retryable: bool = True`; add `ProviderAuthError(ProviderError)` with `retryable = False`. Messages stay generic and never embed headers, keys, prompts, or response bodies. |
| `ModelRegistry` | **Reuse, tiny helper only** | Keep deterministic `register` / `specs`. Optional `get(provider, model)` lookup. Registry does not decide eligibility. |
| `TaskClassifier` | **Reuse unchanged** | Prompt-based minimum tier remains deterministic. It does not know about risk tiers, keys, or free tiers. |
| `CircuitBreaker` | **Reuse unchanged** | 3 failures / 30 s defaults, one breaker per `provider/model`, injectable clock. Per failed attempt counting. No per-exhausted-call change. |
| `CostMeter` | **Reuse unchanged** | Observability aggregate inside the gateway. It is not an enforcement ledger; `PolicyEngine` is. |
| `ModelGateway` | **Extend selection only** | New filters and ordering described in Sections 2 and 7. Existing public behavior remains when new fields are left at defaults and `allow_paid_remote=True`. No usage-sink hook in the gateway. |
| `PolicyEngine` | **Extend minimally (future stage)** | Add read-only affordability check, an always-recording charge method, and an injectable `today` callable. Existing `record_usage` semantics remain for current callers. |
| `Settings` / `load_settings` | **Extend (future stage)** | Add provider URL/key fields with `repr=False`; parse environment only. |
| `TaskOrchestrator` | **Reuse unchanged** | No new constructor parameters; the LLM-backed `PlanBuilder` is injected into `ArchitectAgent` at composition time. |
| `ArchitectAgent` | **Reuse unchanged** | Still applies `PromptInjectionGuard` before the builder and rejects empty plans. |
| `EditorAgent` | **Reuse unchanged** | Still dispatches only `read_file`, `write_patch`, `run_command`, `run_tests`, `search`; unknown tools fail. |
| `IndependentReviewerAgent` | **Reuse unchanged** | Still accepts only complete independent evidence. |
| `VerificationEngine` | **Reuse unchanged** | Still runs real gates and emits evidence hashes. |

**New module (future stage):** `src/astra_coder/free_cascade.py`

It is the only new module and contains:

- `risk_to_model_tier()` pure mapping;
- `FreeCascadePolicy` (eligibility, remote authorization, hop order);
- `BudgetRunner` (budgeted `ModelGateway` facade);
- `LLMPlanBuilder` (the `PlanBuilder` adapter);
- `build_free_cascade_gateway(settings)` and `build_plan_builder(...)` factories.

This module imports `gateway`, `policy`, `agents`, and `config`; none of those modules import it.
This preserves the dependency direction and avoids cycles. `agents.py` does not import `gateway.py`.

**No new third-party dependency.** `httpx`, `pydantic`, and the standard library are sufficient.

---

## 2. Free-tier eligibility and provider-selection rules

### 2.1 Hop order and canonical catalogue (Locked D-1)

| Hop | Provider id | Model id (default example, not a guarantee) | Tier floor | Local | Credential | Free-tier rule |
|---:|---|---|---|---|---|---|
| 0 | `ollama` | `qwen2.5-coder` (pin local size at implementation) | T1/T2, size-dependent | yes | none | Always free at the margin; counts tokens, cost `0.0`. |
| 1 | `nvidia_nim` | `qwen/qwen2.5-coder-32b-instruct` | T3 | no | `ASTRA_NVIDIA_API_KEY` | Eligible only when `free_tier=True` on the spec. |
| 2 | `openrouter` | `qwen/qwen3-coder:free` | T3 | no | `ASTRA_OPENROUTER_API_KEY` | Only model ids ending in `:free`. Enforced at registration and again at selection. |
| 3 | `groq` | `llama-3.3-70b-versatile` | T2 | no | `ASTRA_GROQ_API_KEY` | Eligible only when `free_tier=True` on the spec. |

Notes on D-1:

- Model ids are defaults, not guarantees. Providers rename or remove models. Implementation must
  re-verify free-tier status at implementation time.
- Groq being hop 3 does not mean it is tried for every tier. Groq is T2, so for a T3/T4 request
  it is skipped with `tier_too_low` and never tried. Ordering applies only among eligible candidates.
- Ollama tier must be pinned by local model size at implementation. Do not assume T2 for every install.
- Any additional generic `openai_compatible` provider configured through the existing
  `ASTRA_OPENAI_*` variables is **paid** unless explicitly tagged `free_tier=True`. It is outside the
  four-hop default cascade and is selected only when paid remote is explicitly allowed.

Default `cascade_priority`: Ollama `0`, NIM `10`, OpenRouter `20`, Groq `30`, generic paid `90`,
other/unclassified `100`. Operators may override order through `ASTRA_FREE_CASCADE_ORDER`, but the
capability floor is never overridden.

### 2.2 Eligibility predicate

A `ModelSpec` is eligible for a request only when **all** conditions hold:

1. **Registered:** `spec` is present in `ModelRegistry`.
2. **Configured:** `providers[spec.provider]` exists. For remote providers this means a non-blank
   environment key was present at gateway construction.
3. **Tier floor:** `spec.tier >= effective_required_tier`.
4. **Remote policy:** `spec.local` **or** (`request.allow_remote` **and** policy permits
   `Action.NETWORK` for the actor).
5. **Paid policy:** `spec.free_tier` **or** `request.allow_paid_remote` **and** policy explicitly
   permits paid spend.
6. **Free-only mode:** if `free_cascade_only` is on (default in v1.0.1), `spec.free_tier` must be
   true. Local Ollama is treated as free.
7. **Context fit:** `spec.context_tokens >= estimated_prompt_tokens + request.max_output_tokens`.
   Estimated prompt tokens use `ceil(len(prompt) / 4)` unless a better estimator is supplied.
   When the prompt estimate is unknown, the provider call remains the backstop and a context
   overflow is a provider error.
8. **Breaker state:** the per-`provider/model` breaker is closed.
9. **Provider-specific rule:** OpenRouter requires `spec.model.endswith(":free")`.
10. **Quota state:** the optional local free-quota window has not marked the provider exhausted. A
    provider `429` remains authoritative and overrides local state.

If any condition fails, the spec is skipped with a reason category. Skip reasons are collected for
the final error, but never include a key, prompt text, or full response body.

### 2.3 Ordering algorithm

Order all eligible candidates by the deterministic tuple:

```
(spec.cascade_priority,
 not spec.local,
 spec.tier,
 0 if spec.free_tier else 1,
 spec.provider,
 spec.model)
```

Consequences:

- Lower hop number wins.
- Ollama (`local=True`, priority 0) wins whenever it meets the tier floor and is healthy.
- Free remote beats paid remote at the same hop/capability.
- Ties are stable and reproducible by provider/model name.

No latency, random, or best-guess ordering is used in v1.0.1.

### 2.4 Local-first vs free-tier-first conflict resolution

The conflict is resolved in this fixed order:

1. **Capability floor:** filter first. Never compare a T1 local model against a T3 requirement.
2. **Local eligibility:** if an Ollama spec meets the floor, is registered, has an unopened breaker,
   has enough context, and is free-qualified, it is selected before any remote provider.
3. **Free remote cascade:** if local is absent, below the floor, context-insufficient, auth-disabled,
   rate-limited, or breaker-open, try free remotes in hop order: NIM -> OpenRouter `:free` -> Groq.
4. **Paid remote:** only if `allow_paid_remote=True`, policy allows paid spend, and the actor is
   permitted `Action.NETWORK`. Paid is last, never a silent fallback.
5. **Fail closed:** otherwise raise `GatewayUnavailable` with the ordered skip/failure summary.

A free provider is **not** preferred over a healthy local provider. A local provider is **not**
preferred over the capability floor. Free-tier-first describes the remote ordering; local-first
remains the first hop. There is no global free-first mode switch.

### 2.5 Skip and fallback matrix

| Situation | Same-provider retry? | Cascade to next eligible? | Breaker effect | Final outcome if nothing else |
|---|---|---|---|---|
| Provider not constructed / key missing | no | yes | none | `GatewayUnavailable` with "provider not configured" |
| Tier below floor | n/a | yes | none | `GatewayUnavailable` |
| Remote disallowed | n/a | local only | none | `GatewayUnavailable("no eligible model")` |
| Paid disallowed | n/a | free only | none | `GatewayUnavailable` |
| Context too small | no | yes | none | `GatewayUnavailable` |
| Breaker open | no | yes | skip until recovery window | `GatewayUnavailable("circuit open")` |
| Connection timeout / DNS / 5xx | yes, within `max_retries` | yes | failure each attempt | `GatewayUnavailable` |
| `401` / `403` auth failure | **no** | yes | failure recorded; provider skipped for the task | `GatewayUnavailable` |
| `429` rate limit | **no** for that provider this task | yes | failure recorded | `GatewayUnavailable` / quota reason |
| `400` / `422` invalid request | **no** | yes (likely caller bug) | failure recorded | `GatewayUnavailable` |
| Budget projection denied | n/a | **no** | none | `BudgetExceeded` before network |
| Parse failure of model output | n/a | **no additional model call** | none | plan fails closed |

---

## 3. RiskTier (T0–T4) -> ModelTier (T0–T4) mapping

`RiskTier` describes consequence/approval severity. `ModelTier` describes the minimum model
capability floor. They share labels but are separate types.

| RiskTier | Meaning | ModelTier floor | Default `allow_remote` (free cascade) | Paid remote default | Approval default | Notes |
|---|---|---|---|---:|---|---|
| `T0` | Docs, formatting, trivial read-only work | `T0` | `True` (free only) | no | no | Ollama-first; remote only if local absent/unhealthy. |
| `T1` | Routine implementation and small fixes | `T1` | `True` (free only) | no | no | Default task risk. |
| `T2` | Multi-file changes, debugging, refactors | `T2` | `True` (free only) | no | yes (`approval_min_risk=T2`) | Existing policy gate still applies. |
| `T3` | Architecture, migrations, trade-off analysis | `T3` | `True` (free only, if a T3 free spec exists) | no unless explicit | yes | If no eligible T3 free provider: fail closed; do not downgrade to T2. |
| `T4` | Security, threat model, vulnerability work | `T4` | `False` by default | no unless explicit + approval | yes + security review | Local-only unless `ASTRA_ALLOW_REMOTE_T4=true` and operator approval. |

Locked D-2: T3 free remote is allowed by default because a laptop rarely runs a T3 model.
T4 stays local-only by default.

### 3.1 `required_tier` semantics

- `request.required_tier` is a caller-supplied floor for a specific call.
- Effective floor: `effective_required = max(request.required_tier, risk_to_model_tier(request.risk))`.
- If `required_tier` is `None`, the floor is `max(classifier.classify(prompt),
  risk_to_model_tier(request.risk))`.
- An explicit `required_tier` may **raise** the floor; it may **never lower** the risk-derived floor.
- The classifier remains a prompt heuristic. It can raise the floor but cannot bypass risk policy.
- Mapping function: `required_tier = ModelTier[RiskTier(task.risk).value]` (ordinal equality).
  The mapping is total, injective, and order-preserving.

### 3.2 `allow_remote` semantics

- `allow_remote=False` removes every non-local spec before sorting, including free remotes.
- `allow_remote=True` is necessary but not sufficient: key presence, free/paid policy, tier,
  context, and breaker checks still apply.
- The free-cascade composition layer resolves the default from the RiskTier table above and passes
  the final boolean explicitly. Direct Stage 04 callers keep the existing default behavior.
- A remote denial is a routing decision, not an approval override. If policy requires approval, the
  task is already blocked upstream by `TaskService` / `PolicyEngine`.
- T4 remote requires both `ASTRA_ALLOW_REMOTE_T4=true` and a recorded approval. Otherwise the task
  fails closed at policy level. It never silently runs locally at a lower tier.

---

## 4. PlanBuilder injection contract

### 4.1 Current shape

`agents.py` already defines:

```
PlanBuilder = Callable[[Task, str], Plan]
ArchitectAgent(builder, guard).plan(task, repository_context) -> Plan
```

`TaskOrchestrator` calls `architect.plan(task, context)` and then follows the existing
Plan -> Edit -> Observe -> Verify -> Review -> terminal-state flow.

### 4.2 New adapter

`LLMPlanBuilder` (future, in `free_cascade.py`) implements the existing `PlanBuilder` callable:

1. **Input:** the `Task` and the already guard-checked repository context. The adapter must not
   bypass `ArchitectAgent`'s prompt-injection guard; the guard runs first because the builder is
   called from inside `ArchitectAgent.plan`.
2. **Prompt construction:** a deterministic renderer places system instructions, the task prompt,
   risk/tier requirements, the remaining token budget, and delimited untrusted context into a single
   bounded prompt. The prompt length is capped by the remaining budget. Repository content is
   explicitly labeled as untrusted data.
3. **Budgeted call:** `BudgetRunner.complete(ModelRequest)` is used, not the raw gateway. The request
   carries `risk`, resolved `required_tier`, resolved `allow_remote`, `allow_paid_remote`, and a
   `max_output_tokens` clamped to the remaining per-task/daily budget.
4. **Response parsing:** strict JSON only. The response must validate as `Plan` with
   `extra="forbid"`, `goal` length 1-4000, `steps` length 1-100, and rationale length <=2000.
   Fenced code blocks are not silently stripped; malformed output fails closed. No `eval`, no
   permissive JSON extraction.
5. **One parse attempt:** a malformed plan does not trigger a second model call. Provider-level
   retries already happened inside the gateway. This bounds planning cost.
6. **Tool safety:** `PlanAction.tool` values are passed to `EditorAgent` unchanged. Only the existing
   allowlist is dispatchable; the model cannot add tools, bypass `GitSafety`, or write outside the
   workspace.
7. **Approval evidence:** `Plan.requires_approval` is honored by `TaskOrchestrator` exactly as
   today. The adapter cannot mark its own plan approved.
8. **Accounting:** the adapter mirrors actual usage into the task ledger (Section 5). A budget error
   propagates; `TaskOrchestrator`'s existing fail-closed exception path records failure.

### 4.3 Composition root wiring

Injection happens where the worker/orchestrator is assembled, not inside `TaskOrchestrator`:

```
Settings
  -> FreeCascadePolicy + ModelRegistry + providers + ModelGateway
  -> BudgetRunner(gateway, policy, task, actor)
  -> LLMPlanBuilder(budget_runner, renderer, parser)
  -> ArchitectAgent(plan_builder)
  -> DockerOrchestratorFactory(architect, editor, reviewer, ...)
  -> TaskOrchestrator(...)
```

The wiring uses the existing `DockerOrchestratorFactory` seam. No new seam is introduced in the
orchestrator.

### 4.4 What does not change

| Component | Change |
|---|---|
| `ArchitectAgent` | None. Still guards context and rejects empty plans. |
| `EditorAgent` | None. Same tool allowlist and error path. |
| `IndependentReviewerAgent` | None. Same evidence requirements. |
| `VerificationEngine` | None. Same gates and evidence hashing. |
| `TaskOrchestrator` | None. Same transitions, approval checks, repair loop, fail-closed exception handling. |
| `TaskStateMachine` | None. |
| `runtime.Task` / `TaskLimits` | None. `tokens` is still the task-level counter. |
| `PolicyEngine.evaluate` | None for RBAC/approval/kill-switch behavior. Only additive budget helpers. |

The only behavioral change is that `ArchitectAgent` now receives an LLM-backed builder instead of a
deterministic placeholder. Success still requires independent verification and review.

### 4.5 Fail-closed semantics of the planner

| Failure | Result |
|---|---|
| `GatewayUnavailable` | Propagates, orchestrator catches, task `FAILED` with `orchestration failed closed: ...` |
| Invalid JSON / extra fields | `ValidationError`, task `FAILED` closed |
| Unknown tool in plan | `validate_tool_call` rejects, task `FAILED` closed |
| Budget exhausted | `BudgetExceeded`, task `FAILED` with the budget reason |
| Provider returns empty plan | Rejected by `ArchitectAgent` |

---

## 5. Token and cost budget enforcement

### 5.1 Ledger model

`PolicyEngine` is the enforcement ledger. `CostMeter` remains an observability aggregate.

Per call:

```
projected_tokens = ceil(len(prompt) / 4) + request.max_output_tokens
projected_cost   = worst-case eligible spec price applied to projected_tokens
```

The pre-flight check uses the **worst-case** eligible candidate so a later choice cannot overshoot
the budget. If the projection exceeds the per-task or daily limit, no provider is contacted.

After a response:

```
actual_tokens = response.input_tokens + response.output_tokens
policy.charge_usage(task_id, actual_tokens, response.cost)
task.tokens = max(task.tokens, policy.usage(task_id).tokens)
```

- Every successful provider response is charged exactly once.
- Failed calls with no response charge `0`.
- Retries that returned a response are charged for each response.
- `gateway.meter.record()` remains observational and may exceed a denied budget; it is never used
  for enforcement.
- `task.tokens` is a mirror of the policy ledger, not a second independent counter. Use `max()`,
  not `+=`, so a double settle cannot double-count.

Field mapping: `ModelResponse` exposes `input_tokens`, `output_tokens`, `cost`. There is no single
`tokens` field. The contract therefore always uses `tokens_used = input_tokens + output_tokens`.

### 5.2 API changes (future stage, additive)

- `PolicyEngine.can_afford(task_id, tokens, cost) -> str | None` — read-only; returns the first
  exceeded limit reason.
- `PolicyEngine.charge_usage(task_id, tokens, cost) -> Usage` — always records actual usage, then
  raises `PolicyDenied` if the recorded cumulative usage exceeds a limit. This preserves truthful
  accounting for provider overruns.
- Existing `record_usage` remains unchanged for current callers.
- `PolicyEngine(..., today: Callable[[], date] = date.today)` — injectable day source for
  deterministic daily-limit tests. Default behavior is unchanged.

### 5.3 `BudgetRunner` contract

`BudgetRunner` is per task and holds: gateway, policy, `task_id`, actor, task, optional audit sink,
and optional clock. It exposes only `complete(request) -> ModelResponse`.

Order of operations:

1. Resolve effective floor and remote/paid permissions.
2. Ask the gateway for the ordered eligible candidate estimate (read-only helper).
3. If no candidate: raise `GatewayUnavailable` without network I/O.
4. Compute worst-case projection; call `can_afford`.
5. If denied: emit `budget_denied` audit event; raise `BudgetExceeded` without network I/O.
6. Call `gateway.generate(request)`.
7. Charge actual usage with `charge_usage`.
8. Mirror `task.tokens`.
9. Emit `provider_call` audit metadata: provider, model, input/output tokens, cost, estimated flag.
   Never include prompt text or keys.
10. Return the `ModelResponse`.

### 5.4 Limit-exceeded behavior

| Condition | Behavior |
|---|---|
| Projected per-task tokens exceed `TaskLimits.max_tokens` | `BudgetExceeded`; no call; task fails closed with a budget reason. |
| Projected per-task tokens exceed `PolicyConfig.per_task_tokens` | `BudgetExceeded`; no call. |
| Projected daily tokens/cost exceed daily limits | `BudgetExceeded`; no call; the task fails closed; operator action is required. |
| Provider returns more tokens than requested | `charge_usage` records the truth and raises; the overrun is visible and not hidden. |
| Cost limit exceeded while tokens remain | `BudgetExceeded`; no cheaper-model downgrade. |
| Free provider (cost `0.0`) | Tokens still count against token limits; cost limits are unaffected. |
| Missing usage in response | Charge the pre-flight upper-bound estimate and set `usage_estimated=True`. |

`BudgetExceeded` is a distinct `RuntimeError` subclass. It must not be converted to
`GatewayUnavailable` or to success. Locked D-4: in v1.0.1 it is recorded by the current
orchestrator generic handler as `TaskState.FAILED` with `orchestration failed closed`. It is not
mapped to `BLOCKED`, to keep `orchestrator.py` unchanged.

**No spend may occur.** Every provider in the Stage 04b catalogue is free-tier
(`free_tier=True`, cost `0.0`). If a paid spec is ever registered, the cost branch of
`PolicyEngine` applies unchanged; the catalogue builder refuses to register any spec whose
cost is non-zero in Stage 04b free-only mode.

---

## 6. Remote-provider authentication and fallback restrictions

### 6.1 Environment contract

| Variable | Purpose | Default | Secret |
|---|---|---|---|
| `ASTRA_NVIDIA_API_KEY` | NVIDIA NIM bearer key | unset | yes (`repr=False`) |
| `ASTRA_NVIDIA_BASE_URL` | NIM base URL | `https://integrate.api.nvidia.com/v1` | no |
| `ASTRA_OPENROUTER_API_KEY` | OpenRouter bearer key | unset | yes (`repr=False`) |
| `ASTRA_OPENROUTER_BASE_URL` | OpenRouter base URL | `https://openrouter.ai/api/v1` | no |
| `ASTRA_GROQ_API_KEY` | Groq bearer key | unset | yes (`repr=False`) |
| `ASTRA_GROQ_BASE_URL` | Groq base URL | `https://api.groq.com/openai/v1` | no |
| `ASTRA_OLLAMA_BASE_URL` | Ollama base URL | `http://127.0.0.1:11434` | no |
| `ASTRA_FREE_CASCADE_ORDER` | Comma-separated hop override | `ollama,nvidia_nim,openrouter,groq` | no |
| `ASTRA_ALLOW_PAID_REMOTE` | Enable paid remote | `false` | no |
| `ASTRA_ALLOW_REMOTE_T4` | Allow remote for T4 | `false` | no |
| ASTRA_OPENROUTER_FREE_ONLY | Removed - OpenRouter always :free in Stage 04b, no toggle | n/a | no |
| `ASTRA_REMOTE_TIMEOUT_SECONDS` | Per-request remote timeout | `60` | no |
| `ASTRA_RETRY_BACKOFF_SECONDS` | Bounded retry backoff base | `0.5` (tests inject `0`) | no |

Existing `ASTRA_OPENAI_BASE_URL` / `ASTRA_OPENAI_API_KEY` remain for a generic paid
OpenAI-compatible provider. They are not part of the four-hop free cascade.

### 6.2 Key handling

- `Settings` stores keys in `field(default=None, repr=False)`. No dataclass `repr`, log line,
  `doctor` output, audit event, or error message may print a key.
- A key that is missing, empty, or whitespace-only means **provider not constructed**. The registry
  may still contain the model spec for diagnostics; the providers dictionary omits the provider, and
  selection reports "provider not configured" without a network call.
- Keys are read only at process/gateway construction. Rotation requires a restart in v1.0.1.
- `OpenAICompatibleProvider` sends `Authorization: Bearer <key>` only. Redirects are not followed,
  so a redirect cannot forward the header. Remote adapters use TLS verification and
  `trust_env=False` to avoid ambient proxy configuration capturing credentials; an explicit proxy
  must be configured by the operator if required.
- Error text is fixed and generic. Response bodies are not embedded in `ProviderError` because they
  can contain request identifiers or provider-side details.

### 6.3 Fallback restrictions

1. **Key missing:** skip, never attempt anonymous remote access.
2. **`allow_remote=False`:** filter out all remote specs before ordering; local-only. If no local
   candidate, `GatewayUnavailable("no eligible model")`.
3. **Free-only mode:** filter out `free_tier=False` specs, including a paid provider with a valid
   key. A valid key is not authorization to spend.
4. **Paid allowed:** requires both `allow_paid_remote=True` and policy permission for paid network
   use. Paid is attempted only after all free hops fail.
5. **T4:** remote is denied by default even when a paid key exists. Enabling
   `ASTRA_ALLOW_REMOTE_T4` is an explicit operator decision; approval and security review still
   apply.
6. **No cross-provider credential reuse.** A key is bound to its provider base URL only.
7. **No fallback to a provider not listed in the configured cascade.** Unknown providers in the
   registry are not sampled just in case.

### 6.4 Network failure semantics

| Failure | Classification | Retry same provider | Breaker | Cascade |
|---|---|---|---|---|
| Connect timeout / read timeout | transient | yes, up to `max_retries` | failure per attempt | yes |
| DNS / connection refused / TLS error | transient/config | yes, up to `max_retries` | failure per attempt | yes |
| HTTP `5xx` | transient | yes | failure per attempt | yes |
| HTTP `429` | quota/rate | no for this provider this task | failure recorded | yes |
| HTTP `401` / `403` | auth/config | no | failure recorded; provider disabled for task | yes |
| HTTP `400` / `422` | request/config | no | failure recorded | yes |
| Request timeout bounded by task wall clock | transient | within retry bound only | failure | yes |

Per-call timeouts are clamped to the remaining task wall-clock budget at the composition layer. No
retry may exceed the task's `max_seconds`.

**Egress restriction.** Remote calls carry the task prompt and repository context only.
The builder must not send secrets, `.env` contents, or git credentials. `PromptInjectionGuard`
already screens repository text for exfiltration instructions before the builder is called; the
builder must not bypass that guard.

---

## 7. Circuit breaker, retry, and failure semantics

### 7.1 Circuit breaker

- Reuse `CircuitBreaker(failure_threshold=3, recovery_seconds=30.0, clock=...)`.
- One breaker per `provider/model` key, exactly as today.
- A failed attempt increments the failure count. A success resets count and open state.
- At 3 consecutive failures the breaker opens for 30 s. While open, the model is skipped with
  "circuit open" and the gateway may cascade to another spec.
- After the recovery window the current implementation closes the breaker and resets the count; it
  is a close-then-retry behavior, not a true half-open probe. This is accepted for v1.0.1 and is
  documented rather than changed.
- Because every failed attempt counts, one `generate` call with `max_retries=2` can open a
  single-model breaker. This is intentional and bounded.
- Budget denials and plan-parse failures do not touch provider breakers.

### 7.2 Retry rules

- `max_retries` is per model/provider; total attempts per model = `max_retries + 1`. Default `2`.
- Retry only `ProviderError` with `retryable=True`.
- Non-retryable errors skip the remaining attempts for that model and cascade to the next eligible
  spec.
- Locked D-3: optional bounded backoff `min(ASTRA_RETRY_BACKOFF_SECONDS * 2**attempt, 2.0)` with
  no jitter. Production base `0.5`, tests inject `0`. No retry may exceed the task wall-clock limit.
- Gateway-level retry never re-parses a plan and never changes the model tier.

### 7.3 `GatewayUnavailable` conditions

`GatewayUnavailable` is raised exactly when no eligible provider returned a response:

1. No spec survives filtering (`no eligible model`).
2. Every candidate is missing/disabled (`provider not configured`).
3. Every candidate is breaker-open (`circuit open`).
4. Every attempt fails transiently or non-retryably.
5. Every candidate is skipped for context, quota, or policy reasons.

The error message is deterministic and contains provider/model plus reason category in attempt
order. It contains no key, prompt, full response body, or secret. `GatewayUnavailable` is not raised
for budget denial or invalid plan output; those use `BudgetExceeded` / parse errors.

### 7.4 Failure outcome

In `TaskOrchestrator`, any of these exceptions reaches the existing generic handler and produces
`TaskState.FAILED` with `orchestration failed closed: <reason>`. There is no transition to
`SUCCEEDED`, no empty plan, and no model-authored success claim. A budget or provider outage is
therefore visible as a failed task with evidence, not a silent pass.

---

## 8. Acceptance tests and quality gates

### 8.1 `tests/test_gateway.py` (extend; existing tests must keep passing)

1. Existing Stage 04 tests remain unchanged: deterministic classifier, local-before-remote,
   local-failure cascade, remote denial, retry/cost meter, circuit open.
2. Hop order: Ollama -> NIM -> OpenRouter -> Groq with fake providers.
3. `allow_remote=False` excludes free remotes and raises `GatewayUnavailable("no eligible model")`.
4. Free-only mode excludes paid specs even when a paid key/provider is present.
5. `allow_paid_remote=True` selects paid only after all free hops fail.
6. A paid key with `allow_paid_remote=False` causes zero paid HTTP calls.
7. Tier floor cannot be lowered by an explicit lower `required_tier`.
8. Missing provider instance is skipped with a deterministic "not configured" reason.
9. Context-insufficient spec is skipped.
10. `401` / `403` causes no same-provider retry and cascades to the next free provider.
11. `429` causes no same-provider retry and cascades.
12. Non-transient failure skips the model; transient failure retries within `max_retries`.
13. Breaker still opens at 3 failures / 30 s with an injected clock; recovery closes it.
14. Error messages and `repr` do not contain dummy API keys or prompt text.
15. Stable ordering for equal priority/tier/provider/model inputs.

### 8.2 `tests/test_free_cascade.py` (new)

1. Parametrized risk mapping: T0->T0, T1->T1, T2->T2, T3->T3, T4->T4, including `allow_remote`
   defaults and T4 remote denial.
2. `effective_required = max(required_tier, risk_floor)`; explicit lower tiers are rejected.
3. Eligibility matrix: configured/unconfigured, free/paid, local/remote, tier above/below, context
   fit/overflow, breaker closed/open.
4. OpenRouter `:free` invariant: non-`:free` model rejected at registration/selection.
5. Local-first vs free-tier-first: healthy local wins; unhealthy/below-floor local cascades to free.
6. `BudgetRunner` pre-flight: per-task and daily denials produce `BudgetExceeded` with zero
   provider calls.
7. Actual usage propagation: `policy.usage(task_id)` and `task.tokens` match
   `input_tokens + output_tokens`; cost accumulates once.
8. Free responses charge cost `0.0` but still consume token budget.
9. Provider overrun is recorded truthfully and then raises; no hidden spend.
10. Missing usage charges the upper-bound estimate and sets `usage_estimated=True`.
11. Daily rollover uses the injected `today` callable; no test depends on the real date.
12. `LLMPlanBuilder`: valid JSON -> `Plan`; invalid JSON -> fail closed; extra fields rejected;
    empty steps rejected; oversized goal/rationale rejected.
13. Prompt-injection context is rejected by `ArchitectAgent` before any provider call (assert zero
    provider calls).
14. Unknown tool names in a valid plan remain rejected by `EditorAgent`.
15. Missing key means provider absent; no HTTP request is made.
16. Remote denial, free-only mode, and paid opt-in paths.
17. Network failure cascades through NIM -> OpenRouter -> Groq and finally raises
    `GatewayUnavailable`.
18. Audit metadata contains provider/model/tokens/cost but no prompt or key.
19. Determinism: same inputs produce identical candidate order and error text.

### 8.3 Determinism rules

- No real network: use `FakeProvider` and/or `httpx.MockTransport`.
- No real sleeping: inject a no-op/synthetic sleeper; breaker clock is injected.
- No real date: inject `today`.
- Environment is set only via `monkeypatch`; tests clear all `ASTRA_*_API_KEY` variables first and
  use obvious dummy values such as `test-key`.
- No test requires Docker, Ollama, NIM, OpenRouter, Groq, or any credential.
- No test asserts on model quality or live provider output.

### 8.4 Gates

```
python -m pytest tests/test_gateway.py tests/test_free_cascade.py -q
make test
make lint
make format
make typecheck
make check
make security
```

Windows equivalent:

```
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src tests
.venv\Scripts\python.exe -m ruff format --check src tests
.venv\Scripts\python.exe -m mypy src
```

Additional expectations:

- `mypy --strict` passes for the new `free_cascade.py`; no untyped public functions, no new `Any`
  beyond the existing `PlanAction.payload` mapping.
- Ruff `S` rules pass; no realistic secrets in tests.
- Coverage remains at or above the configured 80% gate.
- CI runs the same gates on Python 3.12.
- Semgrep/gitleaks remain release gates; unavailability is reported as unavailable, not as a pass.
- No secret material in the repository, in test fixtures, in logs, or in exception messages.
- Protected files remain byte-identical to their pre-stage hashes (Section 11).
- Stage 16 is **not** marked passed by this stage.

---

## 9. Future file-level change plan (not performed in this stage)

| File | Future change |
|---|---|
| `src/astra_coder/gateway.py` | `ModelSpec` free/priority fields, `ModelRequest.allow_paid_remote`, `ModelResponse.usage_estimated`, retryable provider errors, selection filters/order, optional headers/`trust_env`, injectable sleeper. |
| `src/astra_coder/free_cascade.py` | New: risk mapping, eligibility policy, `BudgetRunner`, `LLMPlanBuilder`, factories. |
| `src/astra_coder/config.py` | New provider URL/key/order/paid/T4/backoff settings, all keys `repr=False`, environment-only parsing. |
| `src/astra_coder/policy.py` | Add `can_afford`, `charge_usage`, injectable `today`; leave `evaluate` and `record_usage` semantics intact. |
| `tests/test_gateway.py` | Add the new gateway tests while preserving Stage 04 coverage. |
| `tests/test_free_cascade.py` | New test module. |
| `.env.example` | Document new variables with dummy/empty values only (future stage). |
| `docs/stages/04b.md` | Evidence and acceptance record (future stage). |

Explicitly unchanged: `orchestrator.py`, `agents.py`, `verification.py`, `runtime.py`, `service.py`,
`worker.py`, `Dockerfile`, `.github/workflows/ci.yml`, dashboard files, reports, lockfiles.

---

## 10. Risks, explicit defaults, and locked operator decisions

| Risk | Mitigation / default |
|---|---|
| Free providers change/remove models | Model ids and order are environment-configurable; defaults are examples, not guarantees. |
| Free quotas are rate-limited | `429` is non-retrying for that provider; cascade to the next free hop; audit the reason. |
| Free tier is not truly free | `free_tier` is an explicit operator assertion; price `0.0` alone never qualifies. |
| Paid spend by accident | `allow_paid_remote=False` default in free-cascade composition; paid requires an explicit flag and policy permission. |
| T4 data leaves the host | T4 remote denied by default; enabling requires an explicit operator flag plus approval. |
| Key leakage in logs/errors | `repr=False`, generic errors, no prompt/body logging, no redirects, `trust_env=False` for remotes. |
| Budget under-counting | `charge_usage` records actual usage even on overrun; missing usage charges an upper bound. |
| Local model quality below risk floor | Floor is absolute; fail closed instead of silently downgrading. |
| Provider/model name drift | Registry is config-driven; diagnostics report the exact skipped key. |

### 10.1 Locked operator decisions D-1..D-4

**D-1 - Default free models and ModelTier assignments:** Ollama `qwen2.5-coder` T1/T2,
NVIDIA NIM `qwen/qwen2.5-coder-32b-instruct` T3, OpenRouter `qwen/qwen3-coder:free` T3,
Groq `llama-3.3-70b-versatile` T2. Defaults only, re-verify at implementation.

**D-2 - T3 vs T4 remote policy:** T3 free remote allowed by default (`allow_remote=True`),
because a laptop rarely runs a T3 model. T4 stays local-only by default (`allow_remote=False`).

**D-3 - Retry backoff:** Production `ASTRA_RETRY_BACKOFF_SECONDS=0.5`, cap `2.0`, no jitter.
Tests inject `0.0`.

**D-4 - BudgetExceeded mapping:** v1.0.1 keeps `orchestrator.py` unchanged. `BudgetExceeded`
is recorded as `TaskState.FAILED` with `orchestration failed closed`. Not mapped to `BLOCKED`.

### 10.2 Other locked defaults

- Cascade order: Ollama -> NIM -> OpenRouter `:free` -> Groq.
- Local-first is the invariant default. No free-first mode switch.
- Free-tier remote opt-in: free-only composition by default; paid requires explicit opt-in.
- Retry count: `max_retries=2` (3 attempts).
- Breaker accounting: per failed attempt.
- 401/403 treated as non-retryable.
- Free-tier models count against token budgets: yes.

### 10.3 Rejected alternatives - do not reintroduce

- `ASTRA_CASCADE_MODE=free_first` / any global free-first switch: rejected.
- `ASTRA_FREE_TIER_ENABLED` gate: rejected, replaced by free-only composition.
- `ASTRA_NIM_*` naming: rejected, canonical is `ASTRA_NVIDIA_*` and provider id `nvidia_nim`.
- `priority` field name: rejected, canonical is `cascade_priority`.
- `budget.py` + `llm_plan.py` split: rejected, canonical is single `free_cascade.py`.
- `usage_sink` hook in `ModelGateway`: rejected, `BudgetRunner` is the sole bridge.
- Per-exhausted-call breaker accounting: rejected, per-attempt counting is canonical.
- `permanent: bool` on `ProviderError`: rejected, canonical is `retryable: bool` + `ProviderAuthError`.
- Cost `0.0` alone as free proof: rejected, requires `free_tier=True` plus cost plus `:free` where applicable.

---

## 11. Definition of done for this stage

- This document exists at `docs/design/stage-04b-free-cascade-contract.md`.
- No `.py`, `.ts`, Dockerfile, `.env*`, config, test, report, or lockfile is modified.
- No commit except this design commit, no push, no force-push, no tag change.
- `feat/v1.0.1-free-cascade` is still the active branch at the authorized HEAD.
- `main` and `v1.0.0` are untouched.
- Protected files remain byte-identical to pre-stage hashes:
  `reports/worker-smoke.json` `3045C669207D0ADDCDF117EA37B6CBF82E595C67FA6AAAD018B3B6645326D5D8`,
  `dashboard/package-lock.json` `738F54E6736EE30DE28BD4583E5C583F38FB9983173FF85CB0A10132AE9A21B0`,
  `FINAL_REPORT.md` `97912AAB8C814C33B8ADF1A189C5A133237FEEB8E504C3885D8A1ACCBA14B8D3`.
- The design is reviewable and complete enough that Stage 04b implementation can proceed without
  renegotiating routing, budget, auth, or failure semantics.
- Stage 16 is not marked passed by this stage.
- Implementation is **not** authorized by this design commit alone.

---

## Appendix A - Locked 12 conflict rulings

1. Provider naming: `nvidia_nim` / `ASTRA_NVIDIA_*`.
2. Free proof: `free_tier=True` AND cost `0.0` AND OpenRouter `:free`.
3. Priority field: `cascade_priority`, default 100, hops 0/10/20/30.
4. Module layout: single `free_cascade.py`.
5. `ModelRequest`: add `allow_paid_remote=True`, free-cascade sets `False`.
6. Effective floor: `max(required, risk, classifier)`.
7. `allow_remote`: T0-T3 True free-only, T4 False by default, T4 remote needs flag plus approval.
8. Breaker: per failed attempt, `CircuitBreaker` unchanged.
9. Error flag: `retryable` plus `ProviderAuthError`.
10. Usage bridge: no `usage_sink`, `BudgetRunner` only, `task.tokens = max(...)`.
11. Free-first mode: rejected, local-first invariant.
12. Free gate: `ASTRA_FREE_TIER_ENABLED` rejected, free-only composition is canonical.
