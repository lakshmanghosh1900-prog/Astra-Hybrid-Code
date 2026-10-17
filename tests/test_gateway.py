from dataclasses import dataclass

import pytest

from astra_coder.gateway import (
    CircuitBreaker,
    GatewayUnavailable,
    ModelGateway,
    ModelRegistry,
    ModelRequest,
    ModelResponse,
    ModelSpec,
    ModelTier,
    ProviderError,
    TaskClassifier,
)


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


def spec(provider: str, model: str, tier: ModelTier, local: bool) -> ModelSpec:
    return ModelSpec(provider=provider, model=model, tier=tier, local=local)


def response(provider: str, model: str) -> ModelResponse:
    return ModelResponse(
        content="ok", provider=provider, model=model, input_tokens=10, output_tokens=5, cost=0.25
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
