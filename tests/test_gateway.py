from collections.abc import Callable
from dataclasses import dataclass

import httpx
import pytest

from astra_coder.config import load_settings
from astra_coder.free_cascade import FreeCascadePolicy
from astra_coder.gateway import (
    CircuitBreaker,
    GatewayUnavailable,
    ModelGateway,
    ModelRegistry,
    ModelRequest,
    ModelResponse,
    ModelSpec,
    ModelTier,
    OpenAICompatibleProvider,
    ProviderAuthError,
    ProviderError,
    TaskClassifier,
)
from astra_coder.runtime import RiskTier


@dataclass
class FakeProvider:
    responses: list[ModelResponse | Exception]
    calls: int = 0

    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def spec(
    provider: str,
    model: str,
    tier: ModelTier,
    local: bool,
    *,
    free_tier: bool = False,
    paid_authorized: bool = False,
    priority: int = 100,
    context_tokens: int = 32_000,
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


def response(provider: str, model: str, *, cost: float = 0.25) -> ModelResponse:
    return ModelResponse(
        content="ok", provider=provider, model=model, input_tokens=10, output_tokens=5, cost=cost
    )


def cascade_gateway(
    specs: list[ModelSpec],
    providers: dict[str, FakeProvider],
    *,
    policy: FreeCascadePolicy | None = None,
    max_retries: int = 0,
    breaker_factory: Callable[[], CircuitBreaker] | None = None,
) -> ModelGateway:
    return ModelGateway(
        ModelRegistry(specs),
        providers,
        cascade_policy=policy or FreeCascadePolicy(),
        max_retries=max_retries,
        breaker_factory=breaker_factory,
        retry_backoff_seconds=0.0,
        sleeper=lambda _seconds: None,
    )


def test_classifier_is_deterministic_and_risk_aware() -> None:
    classifier = TaskClassifier()
    assert classifier.classify("format this file") is ModelTier.T0
    assert classifier.classify("implement a parser") is ModelTier.T1
    assert classifier.classify("debug this multi-file bug") is ModelTier.T2
    assert classifier.classify("architecture migration trade-off") is ModelTier.T3
    assert classifier.classify("security vulnerability review") is ModelTier.T4


def test_local_provider_is_preferred_before_remote() -> None:
    local = FakeProvider([response("ollama", "local")])
    remote = FakeProvider([response("cloud", "remote")])
    registry = ModelRegistry(
        [
            spec("cloud", "remote", ModelTier.T1, False),
            spec("ollama", "local", ModelTier.T1, True),
        ]
    )
    gateway = ModelGateway(registry, {"ollama": local, "cloud": remote})
    result = gateway.generate(
        ModelRequest(prompt="implement a function", required_tier=ModelTier.T1)
    )
    assert result.provider == "ollama"
    assert remote.calls == 0


def test_failed_local_provider_cascades_to_remote() -> None:
    local = FakeProvider([ProviderError("offline")])
    remote = FakeProvider([response("cloud", "remote")])
    registry = ModelRegistry(
        [
            spec("ollama", "local", ModelTier.T1, True),
            spec("cloud", "remote", ModelTier.T1, False),
        ]
    )
    gateway = ModelGateway(registry, {"ollama": local, "cloud": remote}, max_retries=0)
    result = gateway.generate(
        ModelRequest(prompt="implement a function", required_tier=ModelTier.T1)
    )
    assert result.provider == "cloud"


def test_remote_is_not_used_when_disallowed() -> None:
    remote = FakeProvider([response("cloud", "remote")])
    gateway = ModelGateway(
        ModelRegistry([spec("cloud", "remote", ModelTier.T1, False)]), {"cloud": remote}
    )
    with pytest.raises(GatewayUnavailable, match="no eligible model"):
        gateway.generate(
            ModelRequest(prompt="implement", required_tier=ModelTier.T1, allow_remote=False)
        )


def test_retry_and_cost_meter() -> None:
    provider = FakeProvider([ProviderError("temporary"), response("ollama", "local")])
    gateway = ModelGateway(
        ModelRegistry([spec("ollama", "local", ModelTier.T1, True)]),
        {"ollama": provider},
        max_retries=1,
    )
    result = gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert result.content == "ok"
    assert provider.calls == 2
    assert gateway.meter.cost == 0.25


def test_circuit_breaker_stops_repeated_failures() -> None:
    provider = FakeProvider([ProviderError("one"), ProviderError("two"), ProviderError("three")])
    clock = [0.0]
    registry = ModelRegistry([spec("ollama", "local", ModelTier.T1, True)])
    gateway = ModelGateway(
        registry,
        {"ollama": provider},
        max_retries=0,
        breaker_factory=lambda: CircuitBreaker(
            failure_threshold=2, recovery_seconds=10, clock=lambda: clock[0]
        ),
    )
    with pytest.raises(GatewayUnavailable):
        gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    with pytest.raises(GatewayUnavailable):
        gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    with pytest.raises(GatewayUnavailable, match="circuit open"):
        gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert provider.calls == 2


def test_cascade_hop_order_is_ollama_nim_openrouter_groq() -> None:
    local = FakeProvider([ProviderError("offline")])
    nim = FakeProvider([ProviderError("offline")])
    openrouter = FakeProvider([ProviderError("offline")])
    groq = FakeProvider([response("groq", "llama")])
    registry = ModelRegistry(
        [
            spec("groq", "llama", ModelTier.T1, False, free_tier=True, priority=30),
            spec("openrouter", "coder:free", ModelTier.T1, False, free_tier=True, priority=20),
            spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10),
            spec("ollama", "local", ModelTier.T1, True, free_tier=True, priority=0),
        ]
    )
    gateway = ModelGateway(
        registry,
        {"ollama": local, "nvidia_nim": nim, "openrouter": openrouter, "groq": groq},
        cascade_policy=FreeCascadePolicy(),
        max_retries=0,
        sleeper=lambda _seconds: None,
    )
    result = gateway.generate(
        ModelRequest(prompt="implement a function", required_tier=ModelTier.T1)
    )
    assert result.provider == "groq"
    assert [local.calls, nim.calls, openrouter.calls, groq.calls] == [1, 1, 1, 1]


def test_cascade_allow_remote_false_excludes_free_remotes() -> None:
    remote = FakeProvider([response("nvidia_nim", "coder")])
    gateway = cascade_gateway(
        [spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10)],
        {"nvidia_nim": remote},
    )
    with pytest.raises(GatewayUnavailable, match="no eligible model"):
        gateway.generate(
            ModelRequest(prompt="implement", required_tier=ModelTier.T1, allow_remote=False)
        )
    assert remote.calls == 0


def test_cascade_free_only_excludes_paid_even_with_request_opt_in() -> None:
    paid = FakeProvider([response("paid", "model")])
    gateway = cascade_gateway(
        [spec("paid", "model", ModelTier.T1, False, free_tier=False, priority=90)],
        {"paid": paid},
    )
    with pytest.raises(GatewayUnavailable, match="not free qualified"):
        gateway.generate(
            ModelRequest(
                prompt="implement",
                required_tier=ModelTier.T1,
                allow_remote=True,
                allow_paid_remote=True,
            )
        )
    assert paid.calls == 0


def test_cascade_paid_is_selected_only_after_free_hops_fail() -> None:
    free = FakeProvider([ProviderError("offline")])
    paid = FakeProvider([response("paid", "model")])
    gateway = cascade_gateway(
        [
            spec("free", "model", ModelTier.T1, False, free_tier=True, priority=10),
            spec(
                "paid",
                "model",
                ModelTier.T1,
                False,
                free_tier=False,
                paid_authorized=True,
                priority=20,
            ),
        ],
        {"free": free, "paid": paid},
        policy=FreeCascadePolicy(free_only=False, allow_paid_remote=True),
    )
    result = gateway.generate(
        ModelRequest(
            prompt="implement",
            required_tier=ModelTier.T1,
            allow_remote=True,
            allow_paid_remote=True,
        )
    )
    assert result.provider == "paid"
    assert free.calls == 1
    assert paid.calls == 1


def test_cascade_paid_disallowed_makes_zero_paid_http_calls() -> None:
    paid = FakeProvider([response("paid", "model")])
    gateway = cascade_gateway(
        [spec("paid", "model", ModelTier.T1, False, free_tier=False, priority=90)],
        {"paid": paid},
        policy=FreeCascadePolicy(free_only=False),
    )
    with pytest.raises(GatewayUnavailable, match="paid disallowed"):
        gateway.generate(
            ModelRequest(
                prompt="implement",
                required_tier=ModelTier.T1,
                allow_remote=True,
                allow_paid_remote=False,
            )
        )
    assert paid.calls == 0


def test_cascade_explicit_tier_cannot_lower_risk_floor() -> None:
    local = FakeProvider([response("ollama", "local")])
    remote = FakeProvider([response("nvidia_nim", "coder")])
    gateway = cascade_gateway(
        [
            spec("ollama", "local", ModelTier.T1, True, free_tier=True, priority=0),
            spec("nvidia_nim", "coder", ModelTier.T3, False, free_tier=True, priority=10),
        ],
        {"ollama": local, "nvidia_nim": remote},
    )
    result = gateway.generate(
        ModelRequest(
            prompt="implement",
            risk=RiskTier.T3,
            required_tier=ModelTier.T1,
            allow_remote=True,
        )
    )
    assert result.provider == "nvidia_nim"
    assert local.calls == 0


def test_cascade_missing_provider_is_reported_without_network() -> None:
    gateway = cascade_gateway(
        [spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10)],
        {},
    )
    with pytest.raises(GatewayUnavailable, match="provider not configured"):
        gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))


def test_cascade_context_insufficient_is_skipped() -> None:
    provider = FakeProvider([response("nvidia_nim", "coder")])
    gateway = cascade_gateway(
        [
            spec(
                "nvidia_nim",
                "coder",
                ModelTier.T1,
                False,
                free_tier=True,
                priority=10,
                context_tokens=20,
            )
        ],
        {"nvidia_nim": provider},
    )
    with pytest.raises(GatewayUnavailable, match="context too small"):
        gateway.generate(
            ModelRequest(
                prompt="x" * 100,
                required_tier=ModelTier.T1,
                max_output_tokens=100,
            )
        )
    assert provider.calls == 0


def test_cascade_auth_failure_does_not_retry_same_provider() -> None:
    auth = FakeProvider([ProviderAuthError()])
    healthy = FakeProvider([response("groq", "llama")])
    gateway = cascade_gateway(
        [
            spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10),
            spec("groq", "llama", ModelTier.T1, False, free_tier=True, priority=30),
        ],
        {"nvidia_nim": auth, "groq": healthy},
        max_retries=2,
    )
    result = gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert result.provider == "groq"
    assert auth.calls == 1
    assert healthy.calls == 1


def test_cascade_rate_limit_does_not_retry_same_provider() -> None:
    limited = FakeProvider([ProviderError("provider rate limited", retryable=False)])
    healthy = FakeProvider([response("groq", "llama")])
    gateway = cascade_gateway(
        [
            spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10),
            spec("groq", "llama", ModelTier.T1, False, free_tier=True, priority=30),
        ],
        {"nvidia_nim": limited, "groq": healthy},
        max_retries=2,
    )
    result = gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert result.provider == "groq"
    assert limited.calls == 1


def test_non_transient_failure_skips_model_and_transient_retries() -> None:
    non_transient = FakeProvider([ProviderError("bad request", retryable=False)])
    transient = FakeProvider(
        [ProviderError("temporary"), ProviderError("temporary"), response("groq", "llama")]
    )
    gateway = cascade_gateway(
        [
            spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10),
            spec("groq", "llama", ModelTier.T1, False, free_tier=True, priority=30),
        ],
        {"nvidia_nim": non_transient, "groq": transient},
        max_retries=2,
    )
    result = gateway.generate(ModelRequest(prompt="implement", required_tier=ModelTier.T1))
    assert result.provider == "groq"
    assert non_transient.calls == 1
    assert transient.calls == 3


def test_breaker_opens_after_three_failures_and_recovers() -> None:
    clock = [0.0]
    provider = FakeProvider(
        [
            ProviderError("one"),
            ProviderError("two"),
            ProviderError("three"),
            response("nvidia_nim", "coder"),
        ]
    )
    gateway = cascade_gateway(
        [spec("nvidia_nim", "coder", ModelTier.T1, False, free_tier=True, priority=10)],
        {"nvidia_nim": provider},
        breaker_factory=lambda: CircuitBreaker(
            failure_threshold=3, recovery_seconds=30.0, clock=lambda: clock[0]
        ),
    )
    request = ModelRequest(prompt="implement", required_tier=ModelTier.T1)
    for _ in range(3):
        with pytest.raises(GatewayUnavailable):
            gateway.generate(request)
    with pytest.raises(GatewayUnavailable, match="circuit open"):
        gateway.generate(request)
    assert provider.calls == 3
    clock[0] = 31.0
    assert gateway.generate(request).provider == "nvidia_nim"
    assert provider.calls == 4


def test_provider_errors_and_repr_do_not_contain_secrets_or_prompts() -> None:
    secret = "dummy-" + "secret-value"
    settings = load_settings({"ASTRA_NVIDIA_API_KEY": secret})
    assert secret not in repr(settings)
    transport = httpx.MockTransport(lambda _request: httpx.Response(401))
    provider = OpenAICompatibleProvider(
        "https://example.invalid/v1",
        secret,
        client=httpx.Client(transport=transport),
    )
    with pytest.raises(ProviderAuthError) as excinfo:
        provider.complete(
            spec("nvidia_nim", "coder", ModelTier.T1, False),
            ModelRequest(prompt="PROMPT-" + "SECRET"),
        )
    assert secret not in str(excinfo.value)
    assert "PROMPT-" + "SECRET" not in str(excinfo.value)


def test_equal_priority_order_is_stable() -> None:
    specs = [
        spec("b", "m", ModelTier.T1, False, free_tier=True, priority=100),
        spec("a", "z", ModelTier.T1, False, free_tier=True, priority=100),
        spec("a", "m", ModelTier.T1, False, free_tier=True, priority=100),
    ]
    policy = FreeCascadePolicy()
    first = policy.order_candidates(specs)
    second = policy.order_candidates(list(reversed(specs)))
    assert first == second
    assert [(item.provider, item.model) for item in first] == [("a", "m"), ("a", "z"), ("b", "m")]


def test_openai_compatible_provider_accounts_usage_and_cost() -> None:
    key = "test" + "-key"
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers["Authorization"]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            },
        )

    provider = OpenAICompatibleProvider(
        "https://example.invalid/v1",
        key,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = provider.complete(
        spec(
            "nvidia_nim",
            "coder",
            ModelTier.T3,
            False,
            input_cost=1.0,
            output_cost=2.0,
        ),
        ModelRequest(prompt="implement"),
    )
    assert result.content == "ok"
    assert (result.input_tokens, result.output_tokens) == (100, 50)
    assert result.cost == pytest.approx(0.2)
    assert seen["authorization"] == f"Bearer {key}"


@pytest.mark.parametrize(
    ("status", "error_type", "retryable"),
    [
        (401, ProviderAuthError, False),
        (403, ProviderAuthError, False),
        (400, ProviderError, False),
        (422, ProviderError, False),
        (429, ProviderError, False),
        (500, ProviderError, True),
        (503, ProviderError, True),
    ],
)
def test_openai_compatible_http_error_classification(
    status: int, error_type: type[ProviderError], retryable: bool
) -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(status))
    provider = OpenAICompatibleProvider(
        "https://example.invalid/v1",
        "test" + "-key",
        client=httpx.Client(transport=transport),
    )
    with pytest.raises(error_type) as excinfo:
        provider.complete(
            spec("nvidia_nim", "coder", ModelTier.T3, False),
            ModelRequest(prompt="implement"),
        )
    assert excinfo.value.retryable is retryable
