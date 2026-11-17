"""Stage 04b security boundary tests: network, approval, redaction, audit, budget."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from astra_coder.agents import ArchitectAgent
from astra_coder.config import Settings, load_settings
from astra_coder.free_cascade import (
    BudgetExceeded,
    BudgetRunner,
    FreeCascadePolicy,
    _render_prompt,
    build_free_cascade_gateway,
    validate_cascade_order,
)
from astra_coder.gateway import (
    GatewayUnavailable,
    ModelGateway,
    ModelRegistry,
    ModelRequest,
    ModelResponse,
    ModelSpec,
    ModelTier,
    NetworkAuthorizationRequired,
)
from astra_coder.policy import Actor, PolicyEngine, RemoteApproval
from astra_coder.redaction import REDACTED, SecretRedactor
from astra_coder.runtime import RiskTier, Task, TaskLimits
from astra_coder.security import NetworkAuthorizer, NetworkDenied, spec_key
from astra_coder.worker_main import build_architect


@dataclass
class CaptureProvider:
    responses: list[ModelResponse]
    calls: int = 0
    prompts: list[str] | None = None

    def __post_init__(self) -> None:
        self.prompts = []

    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        self.prompts.append(request.prompt)
        return self.responses.pop(0)


def free_spec(
    provider: str = "nvidia_nim",
    model: str = "coder",
    *,
    local: bool = False,
    paid: bool = False,
    paid_authorized: bool = False,
    tier: ModelTier = ModelTier.T1,
) -> ModelSpec:
    return ModelSpec(
        provider=provider,
        model=model,
        tier=tier,
        local=local,
        free_tier=not paid,
        paid_authorized=paid_authorized,
        cascade_priority=10,
        context_tokens=100_000,
    )


def make_task(risk: RiskTier = RiskTier.T1, *, max_tokens: int = 100_000) -> Task:
    return Task(
        prompt="implement a function",
        repo_path=".",
        risk=risk,
        limits=TaskLimits(max_tokens=max_tokens),
    )


def response(prompt: str = "ok") -> ModelResponse:
    return ModelResponse(
        content=prompt,
        provider="nvidia_nim",
        model="coder",
        input_tokens=1,
        output_tokens=1,
        cost=0.0,
    )


def sink_events() -> tuple[list[tuple[str, str, str, str, dict[str, object]]], object]:
    events: list[tuple[str, str, str, str, dict[str, object]]] = []

    def sink(
        actor: str, action: str, target: str, decision: str, metadata: dict[str, object]
    ) -> object:
        events.append((actor, action, target, decision, metadata))
        return None

    return events, sink


def remote_approval(
    actor: Actor,
    task: Task,
    provider: str,
    *,
    paid: bool,
    approval_id: str = "remote-1",
) -> RemoteApproval:
    now = datetime.now(UTC)
    return RemoteApproval(
        approval_id=approval_id,
        approver=actor.actor_id,
        task_id=str(task.id),
        provider=provider,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        paid=paid,
    )


def test_network_authorizer_denies_developer_remote_but_allows_local() -> None:
    policy = PolicyEngine()
    task = make_task()
    events, sink = sink_events()
    developer = Actor(actor_id="dev", role="developer")
    authorizer = NetworkAuthorizer(policy, developer, sink, allow_paid_remote=False)
    remote = free_spec()
    with pytest.raises(NetworkDenied):
        authorizer.authorize(task, [remote], estimated_tokens=10, estimated_cost=0.0)
    assert events[-1][1] == "network_decision"
    assert events[-1][3] == "deny"

    local = free_spec(provider="ollama", model="qwen", local=True)
    allowed = authorizer.authorize(task, [local], estimated_tokens=10, estimated_cost=0.0)
    assert allowed == frozenset({spec_key(local)})


def test_network_authorizer_requires_audit_sink() -> None:
    with pytest.raises(NetworkDenied, match="audit sink"):
        NetworkAuthorizer(
            PolicyEngine(),
            Actor(actor_id="op", role="operator"),
            None,
        )


def test_budget_runner_rejects_missing_security_collaborators() -> None:
    task = make_task()
    policy = PolicyEngine()
    events, sink = sink_events()
    authorizer = NetworkAuthorizer(
        policy, Actor(actor_id="op", role="operator"), sink, allow_remote_t4=True
    )
    gateway = ModelGateway(ModelRegistry([free_spec()]), {"nvidia_nim": CaptureProvider([])})
    with pytest.raises(ValueError, match="audit sink"):
        BudgetRunner(
            gateway=gateway,
            policy=policy,
            task=task,
            actor="op",
            authorizer=authorizer,
            redactor=SecretRedactor(),
            audit_sink=None,  # type: ignore[arg-type]
        )
    assert events == []


def test_budget_runner_redacts_prompt_before_provider_and_audit() -> None:
    secret = "sk-" + "A" * 24
    configured = "configured-secret-value"
    provider = CaptureProvider([response()])
    gateway = ModelGateway(
        ModelRegistry([free_spec()]),
        {"nvidia_nim": provider},
    )
    policy = PolicyEngine()
    task = make_task()
    events, sink = sink_events()
    actor = Actor(actor_id="op", role="operator")
    authorizer = NetworkAuthorizer(
        policy, actor, sink, allow_remote_t4=True, allow_paid_remote=False
    )
    runner = BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=task,
        actor=actor.actor_id,
        authorizer=authorizer,
        redactor=SecretRedactor([configured]),
        audit_sink=sink,
    )
    runner.complete(
        ModelRequest(
            prompt=f"use {secret} and {configured}",
            required_tier=ModelTier.T1,
            max_output_tokens=10,
        )
    )
    assert secret not in provider.prompts[0]
    assert configured not in provider.prompts[0]
    assert REDACTED in provider.prompts[0]
    assert secret not in str(events)
    assert configured not in str(events)
    assert provider.calls == 1


def test_t4_remote_requires_flag_and_matching_approval() -> None:
    policy = PolicyEngine()
    task = make_task(RiskTier.T4)
    actor = Actor(actor_id="op", role="operator")
    policy.approve(str(task.id), actor)
    events, sink = sink_events()
    spec = free_spec()

    denied = NetworkAuthorizer(policy, actor, sink, allow_remote_t4=False, allow_paid_remote=False)
    with pytest.raises(NetworkDenied):
        denied.authorize(task, [spec], estimated_tokens=10, estimated_cost=0.0)

    missing_approval = NetworkAuthorizer(
        policy, actor, sink, allow_remote_t4=True, allow_paid_remote=False
    )
    with pytest.raises(NetworkDenied):
        missing_approval.authorize(task, [spec], estimated_tokens=10, estimated_cost=0.0)

    policy.record_remote_approval(actor, remote_approval(actor, task, spec.provider, paid=False))
    approved = NetworkAuthorizer(policy, actor, sink, allow_remote_t4=True, allow_paid_remote=False)
    assert spec_key(spec) in approved.authorize(
        task, [spec], estimated_tokens=10, estimated_cost=0.0
    )


def test_paid_remote_requires_admin_secrets_and_paid_approval() -> None:
    policy = PolicyEngine()
    task = make_task()
    paid = free_spec(provider="paid", model="premium", paid=True, paid_authorized=True)
    events, sink = sink_events()

    operator = Actor(actor_id="op", role="operator")
    operator_authorizer = NetworkAuthorizer(
        policy, operator, sink, allow_remote_t4=True, allow_paid_remote=True
    )
    policy.record_remote_approval(
        operator, remote_approval(operator, task, paid.provider, paid=True)
    )
    with pytest.raises(NetworkDenied):
        operator_authorizer.authorize(task, [paid], estimated_tokens=10, estimated_cost=1.0)

    admin = Actor(actor_id="admin", role="admin")
    unauthorized = free_spec(provider="paid", model="premium", paid=True)
    with pytest.raises(NetworkDenied):
        NetworkAuthorizer(policy, admin, sink, allow_paid_remote=True).authorize(
            task, [unauthorized], estimated_tokens=10, estimated_cost=1.0
        )
    policy.record_remote_approval(
        admin, remote_approval(admin, task, paid.provider, paid=True, approval_id="paid-1")
    )
    assert spec_key(paid) in NetworkAuthorizer(
        policy, admin, sink, allow_paid_remote=True
    ).authorize(task, [paid], estimated_tokens=10, estimated_cost=1.0)


def test_task_token_limit_is_enforced_before_provider_call() -> None:
    provider = CaptureProvider([response()])
    gateway = ModelGateway(ModelRegistry([free_spec()]), {"nvidia_nim": provider})
    policy = PolicyEngine()
    task = make_task(max_tokens=10)
    events, sink = sink_events()
    actor = Actor(actor_id="op", role="operator")
    runner = BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=task,
        actor=actor.actor_id,
        authorizer=NetworkAuthorizer(policy, actor, sink, allow_remote_t4=True),
        redactor=SecretRedactor(),
        audit_sink=sink,
    )
    with pytest.raises(BudgetExceeded, match="task token limit"):
        runner.complete(
            ModelRequest(prompt="x" * 40, required_tier=ModelTier.T1, max_output_tokens=20)
        )
    assert provider.calls == 0
    assert events[0][1] == "budget_denied"


def test_paid_spec_without_authorization_is_skipped() -> None:
    provider = CaptureProvider([response()])
    gateway = ModelGateway(
        ModelRegistry([free_spec(provider="paid", model="premium", paid=True)]),
        {"paid": provider},
        cascade_policy=FreeCascadePolicy(free_only=False, allow_paid_remote=True),
    )
    with pytest.raises(GatewayUnavailable, match="paid provider not authorized"):
        gateway.generate(
            ModelRequest(
                prompt="implement",
                required_tier=ModelTier.T1,
                allow_remote=True,
                allow_paid_remote=True,
            )
        )
    assert provider.calls == 0


def test_openrouter_non_free_requires_explicit_paid_authorization() -> None:
    spec = free_spec(provider="openrouter", model="qwen/qwen3-coder", paid=True)
    with pytest.raises(ValueError, match=":free"):
        ModelRegistry([spec])
    authorized = spec.model_copy(update={"paid_authorized": True})
    registry = ModelRegistry([authorized])
    assert registry.specs() == (authorized,)


def test_worker_role_and_plan_mode_are_validated() -> None:
    settings = load_settings({})
    assert settings.worker_role == "developer"
    assert settings.worker_plan_mode == "llm"
    with pytest.raises(ValueError):
        load_settings({"ASTRA_WORKER_ROLE": "owner"})
    with pytest.raises(ValueError):
        load_settings({"ASTRA_WORKER_PLAN_MODE": "auto"})
    structured = load_settings({"ASTRA_WORKER_PLAN_MODE": "structured"})
    assert structured.worker_plan_mode == "structured"


def test_configured_secret_values_are_redacted() -> None:
    dummy = "test" + "-secret-value"
    settings = load_settings({"ASTRA_NVIDIA_API_KEY": dummy})
    assert dummy in settings.secret_values()
    redactor = SecretRedactor(settings.secret_values())
    assert redactor.redact(f"key={dummy}") == f"key={REDACTED}"


def test_network_deny_blocks_gateway_before_provider_call() -> None:
    provider = CaptureProvider([response()])
    gateway = ModelGateway(
        ModelRegistry([free_spec()]),
        {"nvidia_nim": provider},
        cascade_policy=FreeCascadePolicy(),
    )
    policy = PolicyEngine()
    events, sink = sink_events()
    developer = Actor(actor_id="dev", role="developer")
    runner = BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=make_task(),
        actor=developer.actor_id,
        authorizer=NetworkAuthorizer(policy, developer, sink),
        redactor=SecretRedactor(),
        audit_sink=sink,
    )
    with pytest.raises(NetworkDenied):
        runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert provider.calls == 0
    assert events[-1][1] == "network_decision"
    assert events[-1][3] == "deny"


def test_network_allow_emits_complete_audit_event() -> None:
    provider = CaptureProvider([response()])
    gateway = ModelGateway(
        ModelRegistry([free_spec()]),
        {"nvidia_nim": provider},
        cascade_policy=FreeCascadePolicy(),
    )
    policy = PolicyEngine()
    events, sink = sink_events()
    operator = Actor(actor_id="op", role="operator")
    current = make_task()
    runner = BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=current,
        actor=operator.actor_id,
        authorizer=NetworkAuthorizer(policy, operator, sink),
        redactor=SecretRedactor(),
        audit_sink=sink,
    )
    runner.complete(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    allow_events = [
        event for event in events if event[1] == "network_decision" and event[3] == "allow"
    ]
    assert allow_events
    metadata = allow_events[0][4]
    for key in ("provider", "model", "decision", "reason", "skip_reason", "budget", "tokens"):
        assert key in metadata
    assert metadata["actor"] == "op"
    assert metadata["task_id"] == str(current.id)
    assert provider.calls == 1


def test_t4_remote_denies_expired_approval() -> None:
    policy = PolicyEngine()
    current = make_task(RiskTier.T4)
    operator = Actor(actor_id="op", role="operator")
    policy.approve(str(current.id), operator)
    now = datetime.now(UTC)
    policy.record_remote_approval(
        operator,
        RemoteApproval(
            approval_id="expired-1",
            approver=operator.actor_id,
            task_id=str(current.id),
            provider="nvidia_nim",
            created_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            paid=False,
        ),
    )
    events, sink = sink_events()
    authorizer = NetworkAuthorizer(policy, operator, sink, allow_remote_t4=True)
    with pytest.raises(NetworkDenied):
        authorizer.authorize(current, [free_spec()], estimated_tokens=10, estimated_cost=0.0)
    assert events[-1][3] == "deny"
    assert "approval" in str(events[-1][4].get("reason"))


def test_t4_remote_denies_approval_for_another_task() -> None:
    policy = PolicyEngine()
    current = make_task(RiskTier.T4)
    other = make_task(RiskTier.T4)
    operator = Actor(actor_id="op", role="operator")
    policy.approve(str(current.id), operator)
    now = datetime.now(UTC)
    policy.record_remote_approval(
        operator,
        RemoteApproval(
            approval_id="wrong-task-1",
            approver=operator.actor_id,
            task_id=str(other.id),
            provider="nvidia_nim",
            created_at=now,
            expires_at=now + timedelta(minutes=10),
            paid=False,
        ),
    )
    events, sink = sink_events()
    authorizer = NetworkAuthorizer(policy, operator, sink, allow_remote_t4=True)
    with pytest.raises(NetworkDenied):
        authorizer.authorize(current, [free_spec()], estimated_tokens=10, estimated_cost=0.0)
    assert events[-1][3] == "deny"
    assert "approval" in str(events[-1][4].get("reason"))


def test_kill_switch_blocks_network_authorization() -> None:
    policy = PolicyEngine()
    policy.set_kill_switch(Actor(actor_id="admin", role="admin"), True)
    operator = Actor(actor_id="op", role="operator")
    events, sink = sink_events()
    authorizer = NetworkAuthorizer(policy, operator, sink, allow_remote_t4=True)
    with pytest.raises(NetworkDenied, match="kill switch"):
        authorizer.authorize(make_task(), [free_spec()], estimated_tokens=10, estimated_cost=0.0)
    assert events[-1][1] == "network_decision"
    assert events[-1][3] == "deny"


def test_secret_redaction_blocks_aws_github_and_private_key_everywhere() -> None:
    aws = "AKIAIOSFODNN7EXAMPLE"
    github = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    private_key = (
        "-----BEGIN RSA " + "PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKprivatekeymaterial\n"
        "-----END RSA " + "PRIVATE KEY-----"
    )
    redactor = SecretRedactor()
    current = Task(
        prompt=f"deploy with {aws} and {private_key}",
        repo_path=".",
        risk=RiskTier.T1,
        limits=TaskLimits(),
    )
    context = f"github token {github}\naws {aws}\n{private_key}"
    rendered = _render_prompt(current, context, 5_000, redactor)
    for secret in (aws, github, private_key):
        assert secret not in rendered
    assert REDACTED in rendered

    provider = CaptureProvider([response()])
    gateway = ModelGateway(
        ModelRegistry([free_spec()]),
        {"nvidia_nim": provider},
        cascade_policy=FreeCascadePolicy(),
    )
    policy = PolicyEngine()
    events, sink = sink_events()
    operator = Actor(actor_id="op", role="operator")
    runner = BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=make_task(),
        actor=operator.actor_id,
        authorizer=NetworkAuthorizer(policy, operator, sink),
        redactor=redactor,
        audit_sink=sink,
    )
    runner.complete(ModelRequest(prompt=rendered, required_tier=ModelTier.T1, max_output_tokens=16))
    sent = provider.prompts[0]
    for secret in (aws, github, private_key):
        assert secret not in sent
        assert secret not in str(events)


def test_production_gateway_requires_authorization_decision() -> None:
    settings = load_settings({"ASTRA_NVIDIA_API_KEY": "test" + "-key"})
    gateway = build_free_cascade_gateway(settings)
    with pytest.raises(NetworkAuthorizationRequired):
        gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))


def test_openrouter_non_free_is_rejected_in_free_mode() -> None:
    provider = CaptureProvider([response()])
    openrouter = free_spec(
        provider="openrouter",
        model="qwen/qwen3-coder",
        paid=True,
        paid_authorized=True,
    )
    gateway = ModelGateway(
        ModelRegistry([openrouter]),
        {"openrouter": provider},
        cascade_policy=FreeCascadePolicy(),
    )
    with pytest.raises(GatewayUnavailable, match="not free qualified"):
        gateway.generate(
            ModelRequest(
                prompt="implement",
                required_tier=ModelTier.T1,
                allow_paid_remote=True,
            )
        )
    assert provider.calls == 0


def test_openrouter_non_free_paid_mode_requires_secrets_and_approval() -> None:
    provider = CaptureProvider([response()])
    openrouter = free_spec(
        provider="openrouter",
        model="qwen/qwen3-coder",
        paid=True,
        paid_authorized=True,
    )
    gateway = ModelGateway(
        ModelRegistry([openrouter]),
        {"openrouter": provider},
        cascade_policy=FreeCascadePolicy(free_only=False, allow_paid_remote=True),
    )
    policy = PolicyEngine()
    events, sink = sink_events()
    operator = Actor(actor_id="op", role="operator")
    current = make_task()
    runner = BudgetRunner(
        gateway=gateway,
        policy=policy,
        task=current,
        actor=operator.actor_id,
        authorizer=NetworkAuthorizer(
            policy, operator, sink, allow_remote_t4=True, allow_paid_remote=True
        ),
        redactor=SecretRedactor(),
        audit_sink=sink,
    )
    with pytest.raises(NetworkDenied, match="no network-authorized candidate"):
        runner.complete(
            ModelRequest(
                prompt="implement",
                required_tier=ModelTier.T1,
                allow_paid_remote=True,
            )
        )
    assert provider.calls == 0
    assert any("secret access denied" in str(event[4].get("reason")) for event in events)

    admin = Actor(actor_id="admin", role="admin")
    policy.record_remote_approval(
        admin,
        remote_approval(admin, current, "openrouter", paid=True, approval_id="or-paid-1"),
    )
    allowed = NetworkAuthorizer(
        policy, admin, sink, allow_remote_t4=True, allow_paid_remote=True
    ).authorize(current, [openrouter], estimated_tokens=10, estimated_cost=1.0)
    assert spec_key(openrouter) in allowed


def test_eligible_specs_and_generate_share_one_classification() -> None:
    provider = CaptureProvider([])
    specs = [
        free_spec("ollama", "qwen", local=True, tier=ModelTier.T1),
        free_spec("nvidia_nim", "coder", tier=ModelTier.T3),
        free_spec("groq", "llama", tier=ModelTier.T2),
    ]
    gateway = ModelGateway(
        ModelRegistry(specs),
        {"ollama": provider, "nvidia_nim": provider, "groq": provider},
        cascade_policy=FreeCascadePolicy(),
    )
    request = ModelRequest(
        prompt="architecture migration trade-off",
        risk=RiskTier.T3,
        required_tier=None,
    )
    effective = gateway.effective_tier(request)
    assert gateway.eligible_specs(request) == gateway.candidate_plan(request)[0]
    assert (
        gateway.eligible_specs(request, effective) == gateway.candidate_plan(request, effective)[0]
    )
    assert [spec.provider for spec in gateway.eligible_specs(request)] == ["nvidia_nim"]


def test_cascade_order_validation_rejects_bad_values() -> None:
    for bad in ((), ("ollama", "ollama"), ("ollama", "bogus")):
        with pytest.raises(ValueError):
            validate_cascade_order(bad)
    with pytest.raises(ValueError, match="unknown"):
        build_free_cascade_gateway(Settings(free_cascade_order=("bogus",)))
    with pytest.raises(ValueError, match="duplicate"):
        load_settings({"ASTRA_FREE_CASCADE_ORDER": "ollama,ollama"})
    with pytest.raises(ValueError, match="empty"):
        load_settings({"ASTRA_FREE_CASCADE_ORDER": ""})


def test_worker_builds_free_cascade_architect_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = ModelGateway(ModelRegistry([free_spec()]), {"nvidia_nim": CaptureProvider([])})
    calls: list[Settings] = []

    def fake_gateway(settings: Settings) -> ModelGateway:
        calls.append(settings)
        return fake

    monkeypatch.setattr("astra_coder.worker_main.build_free_cascade_gateway", fake_gateway)
    settings = load_settings({"ASTRA_NVIDIA_API_KEY": "test" + "-key"})
    _events, sink = sink_events()
    architect = build_architect(
        settings, PolicyEngine(), Actor(actor_id="worker", role="developer"), sink
    )
    assert isinstance(architect, ArchitectAgent)
    assert calls == [settings]
    assert settings.worker_plan_mode == "llm"

    calls.clear()
    structured = build_architect(
        Settings(worker_plan_mode="structured"),
        PolicyEngine(),
        Actor(actor_id="worker", role="developer"),
        sink,
    )
    assert isinstance(structured, ArchitectAgent)
    assert calls == []
