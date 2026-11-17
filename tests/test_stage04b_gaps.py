"""Stage 04b gap coverage: free-cascade failure paths and policy guards."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from astra_coder.free_cascade import (
    BudgetExceeded,
    BudgetRunner,
    CascadePlanBuilder,
    FreeCascadePolicy,
    _render_prompt,
    is_free_qualified,
)
from astra_coder.gateway import (
    GatewayUnavailable,
    ModelGateway,
    ModelRegistry,
    ModelRequest,
    ModelResponse,
    ModelSpec,
    ModelTier,
    ProviderError,
)
from astra_coder.policy import (
    Action,
    Actor,
    PolicyConfig,
    PolicyDenied,
    PolicyEngine,
    RemoteApproval,
)
from astra_coder.redaction import SecretRedactor
from astra_coder.runtime import RiskTier, Task, TaskLimits
from astra_coder.security import NetworkAuthorizer, spec_key


@dataclass
class FakeProvider:
    responses: list[ModelResponse | Exception]
    calls: int = 0
    prompts: list[str] = field(default_factory=list)

    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        self.prompts.append(request.prompt)
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def spec(
    provider: str = "nvidia_nim",
    model: str = "coder",
    tier: ModelTier = ModelTier.T1,
    *,
    local: bool = False,
    free_tier: bool = True,
    paid_authorized: bool = False,
    priority: int = 10,
    context_tokens: int = 100_000,
    input_cost: float = 0.0,
    output_cost: float = 0.0,
) -> ModelSpec:
    return ModelSpec(
        provider=provider,
        model=model,
        tier=tier,
        local=local,
        free_tier=free_tier,
        paid_authorized=paid_authorized,
        cascade_priority=priority,
        context_tokens=context_tokens,
        input_cost_per_1k=input_cost,
        output_cost_per_1k=output_cost,
    )


def response(
    *,
    content: str = "ok",
    input_tokens: int = 1,
    output_tokens: int = 1,
) -> ModelResponse:
    return ModelResponse(
        content=content,
        provider="nvidia_nim",
        model="coder",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost=0.0,
    )


def task(
    *,
    prompt: str = "implement a function",
    risk: RiskTier = RiskTier.T1,
    max_tokens: int = 100_000,
    max_seconds: float = 900.0,
) -> Task:
    return Task(
        prompt=prompt,
        repo_path=".",
        risk=risk,
        limits=TaskLimits(max_tokens=max_tokens, max_seconds=max_seconds),
    )


def sink_events() -> tuple[list[tuple[str, str, str, str, dict[str, object]]], object]:
    events: list[tuple[str, str, str, str, dict[str, object]]] = []

    def sink(
        actor: str, action: str, target: str, decision: str, metadata: dict[str, object]
    ) -> object:
        events.append((actor, action, target, decision, metadata))
        return None

    return events, sink


def gateway_with(
    specs: list[ModelSpec],
    providers: dict[str, FakeProvider],
    cascade: FreeCascadePolicy | None = None,
) -> ModelGateway:
    return ModelGateway(
        ModelRegistry(specs),
        providers,
        cascade_policy=cascade or FreeCascadePolicy(),
        max_retries=0,
        retry_backoff_seconds=0.0,
        sleeper=lambda _seconds: None,
    )


_DEFAULT_REDACTOR = SecretRedactor()


def runner_for(
    gateway: ModelGateway,
    policy: PolicyEngine,
    current: Task,
    sink: object,
    *,
    authorizer: object | None = None,
    redactor: SecretRedactor | None = _DEFAULT_REDACTOR,
    task_id: str = "",
    started_at: float | None = None,
    clock: object | None = None,
) -> BudgetRunner:
    actor = Actor(actor_id="op", role="operator")
    resolved_authorizer = authorizer or NetworkAuthorizer(
        policy,
        actor,
        sink,
        allow_remote_t4=True,  # type: ignore[arg-type]
    )
    kwargs = {"task_id": task_id, "started_at": started_at}
    if clock is not None:
        kwargs["clock"] = clock  # type: ignore[assignment]
    return BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=current,
        actor=actor.actor_id,
        authorizer=resolved_authorizer,  # type: ignore[arg-type]
        redactor=redactor,  # type: ignore[arg-type]
        audit_sink=sink,  # type: ignore[arg-type]
        **kwargs,
    )


def plan_json(**overrides: object) -> str:
    data: dict[str, object] = {
        "goal": "do it",
        "steps": [{"tool": "read_file", "payload": {"path": "a.py"}, "rationale": "inspect"}],
        "requires_approval": False,
        "rationale": "top-level",
    }
    data.update(overrides)
    return json.dumps(data)


def test_free_qualified_rejects_nonzero_cost() -> None:
    assert not is_free_qualified(spec(free_tier=True, input_cost=0.01))
    assert not is_free_qualified(spec(free_tier=True, output_cost=0.01))


def test_openrouter_free_id_still_needs_paid_mode_even_if_paid_authorized() -> None:
    policy = FreeCascadePolicy(free_only=False, allow_paid_remote=True)
    openrouter = spec(
        "openrouter",
        "qwen/qwen3-coder",
        ModelTier.T1,
        free_tier=True,
        paid_authorized=True,
    )
    request = ModelRequest(prompt="implement", required_tier=ModelTier.T1, allow_paid_remote=True)
    assert (
        policy.skip_reason(
            openrouter,
            request,
            effective_tier=ModelTier.T1,
            provider_configured=True,
            breaker_open=False,
        )
        == "openrouter not paid authorized"
    )


def test_budget_runner_preserves_explicit_task_id_and_started_at() -> None:
    provider = FakeProvider([response()])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()
    current = task()
    runner = runner_for(
        gateway,
        PolicyEngine(),
        current,
        sink,
        task_id="explicit-task",
        started_at=0.0,
        clock=lambda: 1.0,
    )
    assert runner.task_id == "explicit-task"
    assert runner.started_at == 0.0
    runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert provider.calls == 1


def test_budget_runner_rejects_missing_redactor_and_authorizer() -> None:
    provider = FakeProvider([response()])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()
    policy = PolicyEngine()
    actor = Actor(actor_id="op", role="operator")
    authorizer = NetworkAuthorizer(policy, actor, sink, allow_remote_t4=True)
    with pytest.raises(ValueError, match="secret redactor"):
        runner_for(gateway, policy, task(), sink, authorizer=authorizer, redactor=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="network authorizer"):
        BudgetRunner(
            gateway=gateway,
            policy=policy,
            task=task(),
            actor="op",
            authorizer=None,  # type: ignore[arg-type]
            redactor=SecretRedactor(),
            audit_sink=sink,  # type: ignore[arg-type]
        )


def test_budget_runner_emits_skip_events_for_unconfigured_providers() -> None:
    provider = FakeProvider([response()])
    gateway = gateway_with(
        [
            spec("nvidia_nim", "coder", ModelTier.T1, priority=10),
            spec("groq", "llama", ModelTier.T1, priority=30),
        ],
        {"nvidia_nim": provider},
    )
    events, sink = sink_events()
    runner = runner_for(gateway, PolicyEngine(), task(), sink)
    runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert any(event[1] == "gateway_skip" for event in events)
    assert provider.calls == 1


def test_budget_runner_raises_when_no_candidate_is_eligible() -> None:
    gateway = gateway_with([spec("groq", "llama", ModelTier.T1, priority=30)], {})
    events, sink = sink_events()
    runner = runner_for(gateway, PolicyEngine(), task(), sink)
    with pytest.raises(GatewayUnavailable, match="no eligible model"):
        runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert any(event[1] == "gateway_unavailable" for event in events)


def test_budget_runner_denies_when_authorizer_allows_no_candidate() -> None:
    provider = FakeProvider([response()])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()

    class DenyAll:
        def authorize(self, *_args: object, **_kwargs: object) -> frozenset[str]:
            return frozenset()

    runner = runner_for(gateway, PolicyEngine(), task(), sink, authorizer=DenyAll())
    with pytest.raises(GatewayUnavailable, match="no network-authorized candidate"):
        runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert provider.calls == 0
    assert any(event[1] == "gateway_unavailable" for event in events)


def test_budget_runner_surfaces_provider_failure_as_gateway_unavailable() -> None:
    provider = FakeProvider([ProviderError("offline")])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()
    runner = runner_for(gateway, PolicyEngine(), task(), sink)
    with pytest.raises(GatewayUnavailable):
        runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert any(event[1] == "gateway_unavailable" for event in events)


def test_budget_runner_records_then_denies_actual_task_overrun() -> None:
    provider = FakeProvider([response(input_tokens=100, output_tokens=0)])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()
    current = task(max_tokens=20)
    runner = runner_for(gateway, PolicyEngine(), current, sink)
    with pytest.raises(BudgetExceeded, match="task token limit"):
        runner.complete(ModelRequest(prompt="x", required_tier=ModelTier.T1, max_output_tokens=5))
    assert provider.calls == 1
    assert current.tokens == 100
    assert any(event[1] == "budget_denied" for event in events)


def test_render_prompt_truncates_context_to_token_budget() -> None:
    current = task(max_tokens=10)
    rendered = _render_prompt(current, "y" * 500, 0, SecretRedactor())
    assert "[context truncated to token budget]" in rendered


def test_render_prompt_redacts_task_and_context() -> None:
    secret = "sk-" + "B" * 24
    current = task(prompt=f"deploy {secret}")
    rendered = _render_prompt(current, f"context {secret}", 1_000, SecretRedactor())
    assert secret not in rendered


@pytest.mark.parametrize(
    "content",
    [
        plan_json(requires_approval="yes"),
        plan_json(steps=[1]),
        plan_json(steps=[{"tool": 1}]),
        plan_json(steps=[{"tool": "read_file", "payload": 1}]),
        plan_json(steps=[{"tool": "read_file", "rationale": 1}]),
        "",
    ],
)
def test_plan_builder_rejects_malformed_provider_output(content: str) -> None:
    provider = FakeProvider([response(content=content)])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()
    builder = CascadePlanBuilder(
        gateway=gateway,
        policy=PolicyEngine(),
        actor=Actor(actor_id="op", role="operator"),
        audit_sink=sink,  # type: ignore[arg-type]
        redactor=SecretRedactor(),
        allow_remote_t4=True,
    )
    with pytest.raises(ValueError):
        builder(task(), "safe context")


def test_cascade_plan_builder_returns_parsed_plan() -> None:
    provider = FakeProvider([response(content=plan_json())])
    gateway = gateway_with([spec()], {"nvidia_nim": provider})
    events, sink = sink_events()
    builder = CascadePlanBuilder(
        gateway=gateway,
        policy=PolicyEngine(),
        actor=Actor(actor_id="op", role="operator"),
        audit_sink=sink,  # type: ignore[arg-type]
        redactor=SecretRedactor(),
        allow_remote_t4=True,
    )
    plan = builder(task(), "safe context")
    assert plan.goal == "do it"
    assert provider.calls == 1


def _approval(
    actor: Actor,
    *,
    approver: str | None = None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    paid: bool = False,
    spec_hash: str | None = None,
    scope_hash: str | None = None,
) -> RemoteApproval:
    now = datetime.now(UTC)
    return RemoteApproval(
        approval_id="a-1",
        approver=approver or actor.actor_id,
        task_id="task-1",
        provider="nvidia_nim",
        created_at=created_at or now,
        expires_at=expires_at or now + timedelta(minutes=10),
        paid=paid,
        spec_hash=spec_hash,
        scope_hash=scope_hash,
    )


def test_record_remote_approval_rejects_approver_mismatch() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    with pytest.raises(PolicyDenied, match="approver"):
        policy.record_remote_approval(operator, _approval(operator, approver="someone-else"))


def test_record_remote_approval_requires_timezone_aware_timestamps() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    naive = datetime(2026, 1, 1, 0, 0, 0)
    with pytest.raises(PolicyDenied, match="timezone-aware"):
        policy.record_remote_approval(
            operator, _approval(operator, created_at=naive, expires_at=naive + timedelta(hours=1))
        )


def test_record_remote_approval_requires_forward_expiry() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    now = datetime.now(UTC)
    with pytest.raises(PolicyDenied, match="expiry"):
        policy.record_remote_approval(operator, _approval(operator, created_at=now, expires_at=now))


def test_revoke_remote_approval_removes_record() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    policy.record_remote_approval(operator, _approval(operator))
    now = datetime.now(UTC)
    assert policy.remote_approval("task-1", "nvidia_nim", now=now, paid=False) is not None
    policy.revoke_remote_approval("task-1", "nvidia_nim", operator)
    assert policy.remote_approval("task-1", "nvidia_nim", now=now, paid=False) is None


def test_remote_approval_rejects_hash_mismatch() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    policy.record_remote_approval(
        operator, _approval(operator, spec_hash="spec-a", scope_hash="scope-a")
    )
    now = datetime.now(UTC)
    assert (
        policy.remote_approval("task-1", "nvidia_nim", now=now, paid=False, spec_hash="spec-b")
        is None
    )
    assert (
        policy.remote_approval("task-1", "nvidia_nim", now=now, paid=False, scope_hash="scope-b")
        is None
    )
    assert (
        policy.remote_approval(
            "task-1", "nvidia_nim", now=now, paid=False, spec_hash="spec-a", scope_hash="scope-a"
        )
        is not None
    )


def test_can_afford_and_charge_usage_reject_negative_values() -> None:
    policy = PolicyEngine()
    assert policy.can_afford("task", -1, 0.0) == "negative budget estimate"
    with pytest.raises(PolicyDenied, match="negative"):
        policy.charge_usage("task", -1, 0.0)


def test_budget_reason_categories_are_distinct() -> None:
    per_task_cost = PolicyEngine(PolicyConfig(per_task_cost=1.0, per_task_tokens=1_000))
    assert per_task_cost.can_afford("task", 0, 2.0) == "per-task cost budget exceeded"
    with pytest.raises(PolicyDenied, match="per-task cost"):
        per_task_cost.charge_usage("task", 0, 2.0)

    daily_tokens = PolicyEngine(PolicyConfig(daily_tokens=10))
    with pytest.raises(PolicyDenied, match="daily token"):
        daily_tokens.charge_usage("task", 11, 0.0)

    daily_cost = PolicyEngine(PolicyConfig(daily_cost=1.0))
    with pytest.raises(PolicyDenied, match="daily cost"):
        daily_cost.charge_usage("task", 0, 2.0)


def test_evaluate_rejects_negative_estimate_and_budget_overrun() -> None:
    policy = PolicyEngine(PolicyConfig(per_task_tokens=10))
    developer = Actor(actor_id="dev", role="developer")
    negative = policy.evaluate(developer, Action.READ, RiskTier.T0, "task", estimated_tokens=-1)
    assert not negative.allowed
    over = policy.evaluate(developer, Action.READ, RiskTier.T0, "task", estimated_tokens=50)
    assert not over.allowed
    assert "per-task token" in over.reason


def test_path_guard_rejects_missing_root_for_mutation(tmp_path: Path) -> None:
    policy = PolicyEngine(PolicyConfig(repo_root=tmp_path / "missing"))
    admin = Actor(actor_id="admin", role="admin")
    decision = policy.evaluate(admin, Action.EDIT, RiskTier.T0, "task", touched_paths=["a.py"])
    assert not decision.allowed
    assert "root is unavailable" in decision.reason


def test_path_guard_requires_scope_for_mutation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    policy = PolicyEngine(PolicyConfig(repo_root=root))
    admin = Actor(actor_id="admin", role="admin")
    decision = policy.evaluate(admin, Action.EDIT, RiskTier.T0, "task")
    assert not decision.allowed
    assert "scope is not specified" in decision.reason


def test_path_guard_resolves_relative_paths(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    policy = PolicyEngine(PolicyConfig(repo_root=root))
    developer = Actor(actor_id="dev", role="developer")
    decision = policy.evaluate(developer, Action.READ, RiskTier.T0, "task", touched_paths=["a.py"])
    assert decision.allowed


def test_daily_rollover_is_date_injected() -> None:
    today = [date(2026, 2, 1)]
    policy = PolicyEngine(PolicyConfig(daily_tokens=10), today=lambda: today[0])
    policy.charge_usage("task", 8, 0.0)
    assert policy.can_afford("other", 5, 0.0) == "daily token budget exceeded"
    today[0] = date(2026, 2, 2)
    assert policy.can_afford("other", 5, 0.0) is None


def test_network_authorizer_allows_operator_for_free_remote() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    events, sink = sink_events()
    authorizer = NetworkAuthorizer(policy, operator, sink, allow_remote_t4=False)
    allowed = authorizer.authorize(task(), [spec()], estimated_tokens=5, estimated_cost=0.0)
    assert spec_key(spec()) in allowed
    assert any(event[1] == "network_decision" and event[3] == "allow" for event in events)


def test_network_authorizer_requires_matching_t4_approval() -> None:
    policy = PolicyEngine()
    operator = Actor(actor_id="op", role="operator")
    events, sink = sink_events()
    t4_task = task(risk=RiskTier.T4)
    authorizer = NetworkAuthorizer(policy, operator, sink, allow_remote_t4=True)
    with pytest.raises(PolicyDenied, match="approval"):
        authorizer.authorize(t4_task, [spec()], estimated_tokens=5, estimated_cost=0.0)
