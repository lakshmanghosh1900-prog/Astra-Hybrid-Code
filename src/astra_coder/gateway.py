"""Model-agnostic local-first gateway with bounded retries and circuit breakers."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .runtime import RiskTier


class ModelTier(IntEnum):
    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3
    T4 = 4


class ProviderKind(StrEnum):
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"


class ModelSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    tier: ModelTier
    local: bool
    context_tokens: int = Field(default=32_000, gt=0)
    input_cost_per_1k: float = Field(default=0.0, ge=0.0)
    output_cost_per_1k: float = Field(default=0.0, ge=0.0)


class ModelRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    prompt: str = Field(min_length=1, max_length=1_000_000)
    risk: RiskTier = RiskTier.T1
    required_tier: ModelTier | None = None
    allow_remote: bool = True
    max_output_tokens: int = Field(default=4_096, gt=0, le=1_000_000)


class ModelResponse(BaseModel):
    content: str
    provider: str
    model: str
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost: float = Field(default=0.0, ge=0.0)


class ProviderError(RuntimeError):
    """A provider failed; the gateway may try another eligible provider."""


class GatewayUnavailable(RuntimeError):
    """No eligible provider returned a response."""


class Provider(Protocol):
    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse: ...


class ModelRegistry:
    def __init__(self, specs: Iterable[ModelSpec] = ()) -> None:
        self._specs: dict[str, ModelSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ModelSpec) -> None:
        self._specs[f"{spec.provider}/{spec.model}"] = spec

    def specs(self) -> tuple[ModelSpec, ...]:
        return tuple(self._specs.values())


class TaskClassifier:
    """Deterministic classifier; a model is not needed to choose a model."""

    def classify(self, prompt: str) -> ModelTier:
        lowered = prompt.lower()
        if any(word in lowered for word in ("security", "threat model", "vulnerability")):
            return ModelTier.T4
        if any(word in lowered for word in ("architecture", "redesign", "migration", "trade-off")):
            return ModelTier.T3
        if any(word in lowered for word in ("debug", "bug", "multi-file", "refactor")):
            return ModelTier.T2
        if any(word in lowered for word in ("implement", "write", "add", "fix")):
            return ModelTier.T1
        return ModelTier.T0


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 3
    recovery_seconds: float = 30.0
    clock: Callable[[], float] = time.monotonic
    failures: int = 0
    opened_until: float | None = None

    @property
    def open(self) -> bool:
        if self.opened_until is None:
            return False
        if self.clock() >= self.opened_until:
            self.opened_until = None
            self.failures = 0
            return False
        return True

    def record_success(self) -> None:
        self.failures = 0
        self.opened_until = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_until = self.clock() + self.recovery_seconds


class CostMeter:
    def __init__(self) -> None:
        self.input_tokens = 0
        self.output_tokens = 0
        self.cost = 0.0

    def record(self, response: ModelResponse) -> None:
        self.input_tokens += response.input_tokens
        self.output_tokens += response.output_tokens
        self.cost += response.cost


class OllamaProvider:
    def __init__(self, base_url: str, client: httpx.Client | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=30.0)

    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        try:
            response = self._client.post(
                f"{self._base_url}/api/generate",
                json={"model": spec.model, "prompt": request.prompt, "stream": False},
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderError("Ollama request failed") from exc
        return ModelResponse(
            content=str(data.get("response", "")),
            provider=spec.provider,
            model=spec.model,
            input_tokens=int(data.get("prompt_eval_count", 0) or 0),
            output_tokens=int(data.get("eval_count", 0) or 0),
        )


class OpenAICompatibleProvider:
    def __init__(self, base_url: str, api_key: str, client: httpx.Client | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = client or httpx.Client(timeout=60.0)

    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        try:
            response = self._client.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": spec.model,
                    "messages": [{"role": "user", "content": request.prompt}],
                    "max_tokens": request.max_output_tokens,
                },
            )
            response.raise_for_status()
            data = response.json()
            choice = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderError("OpenAI-compatible request failed") from exc
        input_tokens = int(usage.get("prompt_tokens", 0) or 0)
        output_tokens = int(usage.get("completion_tokens", 0) or 0)
        cost = (input_tokens / 1_000 * spec.input_cost_per_1k) + (
            output_tokens / 1_000 * spec.output_cost_per_1k
        )
        return ModelResponse(
            content=str(choice),
            provider=spec.provider,
            model=spec.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
        )


class ModelGateway:
    def __init__(
        self,
        registry: ModelRegistry,
        providers: dict[str, Provider],
        *,
        classifier: TaskClassifier | None = None,
        max_retries: int = 2,
        breaker_factory: Callable[[], CircuitBreaker] | None = None,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        self.registry = registry
        self.providers = providers
        self.classifier = classifier or TaskClassifier()
        self.max_retries = max_retries
        self.meter = CostMeter()
        self._breakers: dict[str, CircuitBreaker] = {}
        self._breaker_factory = breaker_factory or CircuitBreaker

    def generate(self, request: ModelRequest) -> ModelResponse:
        required = request.required_tier or self.classifier.classify(request.prompt)
        candidates = [
            spec
            for spec in self.registry.specs()
            if spec.tier >= required and (request.allow_remote or spec.local)
        ]
        candidates.sort(key=lambda spec: (not spec.local, spec.tier, spec.provider, spec.model))
        failures: list[str] = []
        for spec in candidates:
            provider = self.providers.get(spec.provider)
            if provider is None:
                failures.append(f"{spec.provider}/{spec.model}: provider not configured")
                continue
            key = f"{spec.provider}/{spec.model}"
            breaker = self._breakers.setdefault(key, self._breaker_factory())
            if breaker.open:
                failures.append(f"{key}: circuit open")
                continue
            for attempt in range(self.max_retries + 1):
                try:
                    response = provider.complete(spec, request)
                    self.meter.record(response)
                    breaker.record_success()
                    return response
                except ProviderError as exc:
                    breaker.record_failure()
                    failures.append(f"{key} attempt {attempt + 1}: {exc}")
        detail = "; ".join(failures) or "no eligible model"
        raise GatewayUnavailable(detail)
