"""Model-agnostic local-first gateway with bounded retries and circuit breakers."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
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
    NVIDIA_NIM = "nvidia_nim"
    OPENROUTER = "openrouter"
    GROQ = "groq"


class ModelSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    tier: ModelTier
    local: bool
    context_tokens: int = Field(default=32_000, gt=0)
    input_cost_per_1k: float = Field(default=0.0, ge=0.0)
    output_cost_per_1k: float = Field(default=0.0, ge=0.0)
    free_tier: bool = False
    paid_authorized: bool = False
    cascade_priority: int = 100
    api_key_env: str | None = None


class ModelRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    prompt: str = Field(min_length=1, max_length=1_000_000)
    risk: RiskTier = RiskTier.T1
    required_tier: ModelTier | None = None
    allow_remote: bool = True
    allow_paid_remote: bool = True
    max_output_tokens: int = Field(default=4_096, gt=0, le=1_000_000)


class ModelResponse(BaseModel):
    content: str
    provider: str
    model: str
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost: float = Field(default=0.0, ge=0.0)
    usage_estimated: bool = False


class ProviderError(RuntimeError):
    """A provider failed; the gateway may try another eligible provider."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class ProviderAuthError(ProviderError):
    """Provider authentication failed; retrying cannot help."""

    def __init__(self, message: str = "provider authentication failed") -> None:
        super().__init__(message, retryable=False)


class GatewayUnavailable(RuntimeError):
    """No eligible provider returned a response."""


class NetworkAuthorizationRequired(GatewayUnavailable):
    """Raised when the production gateway is called without a network decision."""


class Provider(Protocol):
    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse: ...


class CascadePolicy(Protocol):
    """Structural contract implemented by ``free_cascade.FreeCascadePolicy``."""

    def effective_required_tier(
        self,
        risk: RiskTier,
        required_tier: ModelTier | None,
        classifier_tier: ModelTier | None = None,
    ) -> ModelTier: ...

    def order_candidates(self, specs: list[ModelSpec]) -> list[ModelSpec]: ...

    def skip_reason(
        self,
        spec: ModelSpec,
        request: ModelRequest,
        *,
        effective_tier: ModelTier,
        provider_configured: bool,
        breaker_open: bool,
    ) -> str | None: ...


class ModelRegistry:
    def __init__(self, specs: Iterable[ModelSpec] = ()) -> None:
        self._specs: dict[str, ModelSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ModelSpec) -> None:
        if spec.provider == ProviderKind.OPENROUTER and not spec.model.endswith(":free"):
            if not (spec.paid_authorized and not spec.free_tier):
                raise ValueError("OpenRouter non-:free models require explicit paid authorization")
        self._specs[f"{spec.provider}/{spec.model}"] = spec

    def specs(self) -> tuple[ModelSpec, ...]:
        return tuple(self._specs.values())

    def get(self, provider: str, model: str) -> ModelSpec | None:
        return self._specs.get(f"{provider}/{model}")


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
    def __init__(
        self,
        base_url: str,
        api_key: str,
        client: httpx.Client | None = None,
        *,
        default_headers: Mapping[str, str] | None = None,
        trust_env: bool = False,
        timeout: float = 60.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = client or httpx.Client(
            timeout=timeout,
            trust_env=trust_env,
            follow_redirects=False,
            headers=dict(default_headers or {}),
        )

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
        except httpx.HTTPError as exc:
            raise ProviderError("OpenAI-compatible request failed") from exc
        status = response.status_code
        if status in (401, 403):
            raise ProviderAuthError()
        if 300 <= status < 400:
            raise ProviderError("provider redirect refused", retryable=False)
        if status == 429:
            raise ProviderError("provider rate limited", retryable=False)
        if 500 <= status:
            raise ProviderError("provider server error", retryable=True)
        if 400 <= status < 500:
            raise ProviderError("provider rejected request", retryable=False)
        try:
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
        cascade_policy: CascadePolicy | None = None,
        retry_backoff_seconds: float = 0.0,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        require_network_authorization: bool = False,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds cannot be negative")
        self.registry = registry
        self.providers = providers
        self.classifier = classifier or TaskClassifier()
        self.max_retries = max_retries
        self.meter = CostMeter()
        self.cascade_policy = cascade_policy
        self.retry_backoff_seconds = retry_backoff_seconds
        self.require_network_authorization = require_network_authorization
        self._sleep = sleeper
        self._clock = clock
        self._breakers: dict[str, CircuitBreaker] = {}
        self._breaker_factory = breaker_factory or CircuitBreaker

    def candidate_plan(
        self, request: ModelRequest, effective_tier: ModelTier | None = None
    ) -> tuple[list[ModelSpec], list[str]]:
        """Return eligible specs and skip reasons from one classification pass."""
        return self._candidates(request, effective_tier)

    def eligible_specs(
        self, request: ModelRequest, effective_tier: ModelTier | None = None
    ) -> list[ModelSpec]:
        """Return eligible specs in deterministic winner-first order."""
        return self.candidate_plan(request, effective_tier)[0]

    def effective_tier(self, request: ModelRequest) -> ModelTier:
        """Public single-source tier calculation used by the budget bridge."""
        return self._effective_tier(request)

    def generate(
        self,
        request: ModelRequest,
        *,
        remaining_seconds: float | None = None,
        effective_tier: ModelTier | None = None,
        allowed_keys: frozenset[str] | None = None,
    ) -> ModelResponse:
        if allowed_keys is None and self.require_network_authorization:
            raise NetworkAuthorizationRequired(
                "network authorization is required before a provider call"
            )
        deadline = (
            None if remaining_seconds is None else self._clock() + max(0.0, remaining_seconds)
        )
        candidates, skips = self._candidates(request, effective_tier)
        if allowed_keys is not None:
            denied = [
                spec for spec in candidates if f"{spec.provider}/{spec.model}" not in allowed_keys
            ]
            skips.extend(f"{spec.provider}/{spec.model}: not network authorized" for spec in denied)
            candidates = [
                spec for spec in candidates if f"{spec.provider}/{spec.model}" in allowed_keys
            ]
        failures: list[str] = list(skips)
        if not candidates:
            detail = "no eligible model"
            if failures:
                detail = f"{detail}: {'; '.join(failures)}"
            raise GatewayUnavailable(detail)
        deadline_hit = False
        for spec in candidates:
            if self._deadline_passed(deadline):
                failures.append("task deadline exceeded")
                break
            key = f"{spec.provider}/{spec.model}"
            provider = self.providers.get(spec.provider)
            if provider is None:
                failures.append(f"{key}: provider not configured")
                continue
            breaker = self._breakers.setdefault(key, self._breaker_factory())
            if breaker.open:
                failures.append(f"{key}: circuit open")
                continue
            for attempt in range(self.max_retries + 1):
                if self._deadline_passed(deadline):
                    failures.append(f"{key}: task deadline exceeded")
                    deadline_hit = True
                    break
                try:
                    response = provider.complete(spec, request)
                    self.meter.record(response)
                    breaker.record_success()
                    return response
                except ProviderError as exc:
                    breaker.record_failure()
                    failures.append(f"{key} attempt {attempt + 1}: {exc}")
                    if not exc.retryable:
                        break
                    if attempt < self.max_retries:
                        delay = min(self.retry_backoff_seconds * (2**attempt), 2.0)
                        if deadline is not None:
                            remaining = deadline - self._clock()
                            if remaining <= 0 or delay >= remaining:
                                failures.append(f"{key}: task deadline exceeded")
                                deadline_hit = True
                                break
                            delay = min(delay, remaining)
                        if delay > 0:
                            self._sleep(delay)
            if deadline_hit:
                break
        detail = "; ".join(failures) or "no eligible model"
        raise GatewayUnavailable(detail)

    def _candidates(
        self, request: ModelRequest, effective_tier: ModelTier | None = None
    ) -> tuple[list[ModelSpec], list[str]]:
        required = self._effective_tier(request)
        if effective_tier is not None and effective_tier > required:
            required = effective_tier
        if self.cascade_policy is None:
            candidates = [
                spec
                for spec in self.registry.specs()
                if spec.tier >= required and (request.allow_remote or spec.local)
            ]
            candidates.sort(key=lambda spec: (not spec.local, spec.tier, spec.provider, spec.model))
            return candidates, []
        ordered = self.cascade_policy.order_candidates(list(self.registry.specs()))
        eligible: list[ModelSpec] = []
        skips: list[str] = []
        for spec in ordered:
            key = f"{spec.provider}/{spec.model}"
            breaker = self._breakers.get(key)
            reason = self.cascade_policy.skip_reason(
                spec,
                request,
                effective_tier=required,
                provider_configured=spec.provider in self.providers,
                breaker_open=breaker.open if breaker is not None else False,
            )
            if reason is None:
                eligible.append(spec)
            else:
                skips.append(f"{key}: {reason}")
        return eligible, skips

    def _effective_tier(self, request: ModelRequest) -> ModelTier:
        if self.cascade_policy is not None:
            return self.cascade_policy.effective_required_tier(
                request.risk,
                request.required_tier,
                self.classifier.classify(request.prompt),
            )
        return request.required_tier or self.classifier.classify(request.prompt)

    def _deadline_passed(self, deadline: float | None) -> bool:
        return deadline is not None and self._clock() >= deadline
