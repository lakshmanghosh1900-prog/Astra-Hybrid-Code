"""Role-isolated authenticated compatible endpoints behind existing budget gateway."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .config import Settings
from .free_cascade import BudgetRunner, FreeCascadePolicy
from .gateway import (
    ModelGateway,
    ModelRegistry,
    ModelRequest,
    ModelResponse,
    ModelSpec,
    ModelTier,
    OpenAICompatibleProvider,
    ProviderError,
)
from .hybrid_skill import ExecutionPlan, PatchRequest
from .policy import Actor, PolicyEngine
from .redaction import SecretRedactor
from .runtime import Task
from .security import AuditSink, NetworkAuthorizer


class HybridRoutingError(RuntimeError):
    """Role configuration, transport or contract denied (no provider payload echoed)."""


class StrictCompatibleProvider(OpenAICompatibleProvider):
    """Retry server errors only; never retry transport/parse errors."""

    remaining: Callable[[], float] | None = None
    call_timeout: float = 60.0

    def complete(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        if self.remaining is not None:
            # Recompute before every retry; HTTP cannot outlive remaining budget.
            self._client.timeout = httpx.Timeout(min(self.call_timeout, self.remaining()))
        try:
            return super().complete(spec, request)
        except ProviderError as error:
            raise ProviderError(
                "hybrid provider failed", retryable=(str(error) == "provider server error")
            ) from None


@dataclass(frozen=True)
class HybridRoutingPolicy:
    """Host-configured rates must be conservative; no implicit zero-cost defaults."""

    input_cost_per_1k: float
    output_cost_per_1k: float
    max_output_tokens: int = 4096

    def __post_init__(self) -> None:
        if (
            any(
                not math.isfinite(v) or v <= 0
                for v in (self.input_cost_per_1k, self.output_cost_per_1k)
            )
            or not 1 <= self.max_output_tokens <= 32768
        ):
            raise HybridRoutingError("invalid cost/token policy")


class HybridProviderRouter:
    """Each role owns a one-model registry: fallback cannot cross a role boundary.

    Claude requires an explicitly configured OpenAI-compatible Claude endpoint;
    native Anthropic Messages is not represented as a compatible endpoint.
    """

    def __init__(
        self,
        settings: Settings,
        routing: HybridRoutingPolicy,
        *,
        task: Task,
        policy: PolicyEngine,
        actor: Actor,
        audit_sink: AuditSink,
        clients: dict[str, httpx.Client] | None = None,
    ) -> None:
        self.settings, self.routing, self.task = settings, routing, task
        self.policy, self.actor = policy, actor
        self.redactor = SecretRedactor(settings.secret_values())
        self.audit_sink = audit_sink
        self.clients = clients or {}
        self.runners: dict[str, BudgetRunner] = {}

    def _runner(self, role: str) -> BudgetRunner:
        if role in self.runners:
            return self.runners[role]
        mappings = {
            "GPT_BRAINING_PLANNER": (
                self.settings.planner_model,
                self.settings.openai_base_url,
                self.settings.openai_api_key,
            ),
            "CODEX_CODER": (
                self.settings.codex_model,
                self.settings.openai_base_url,
                self.settings.openai_api_key,
            ),
            "CLAUDE_CODER": (
                self.settings.claude_model,
                self.settings.claude_base_url,
                self.settings.claude_api_key,
            ),
        }
        model, url, key = mappings.get(role, (None, None, None))
        if not model or not url or not key or not self.settings.allow_paid_remote:
            raise HybridRoutingError("role configuration or remote authorization missing")
        endpoint = urlsplit(url)
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username
            or endpoint.password
        ):
            raise HybridRoutingError("endpoint must be credential-free HTTPS")
        provider = role.lower()
        spec = ModelSpec(
            provider=provider,
            model=model,
            tier=ModelTier.T4,
            local=False,
            paid_authorized=True,
            input_cost_per_1k=self.routing.input_cost_per_1k,
            output_cost_per_1k=self.routing.output_cost_per_1k,
        )
        cascade = FreeCascadePolicy(
            free_only=False, allow_paid_remote=True, allow_remote_t4=self.settings.allow_remote_t4
        )
        transport = StrictCompatibleProvider(
            url, key, client=self.clients.get(role), timeout=self.settings.remote_timeout_seconds
        )
        gateway = ModelGateway(
            ModelRegistry([spec]),
            {provider: transport},
            cascade_policy=cascade,
            require_network_authorization=True,
            max_retries=2,
            retry_backoff_seconds=self.settings.retry_backoff_seconds,
        )

        def audit(
            a: str, action: str, target: str, decision: str, metadata: dict[str, object]
        ) -> object:
            import json

            safe = json.loads(self.redactor.redact(json.dumps(metadata)))
            return self.audit_sink(a, action, target, decision, safe)

        runner = BudgetRunner(
            gateway,
            self.policy,
            self.task,
            self.actor.actor_id,
            NetworkAuthorizer(
                self.policy,
                self.actor,
                audit,
                allow_paid_remote=True,
                allow_remote_t4=self.settings.allow_remote_t4,
            ),
            self.redactor,
            audit,
        )
        transport.remaining = runner._remaining_seconds
        transport.call_timeout = self.settings.remote_timeout_seconds
        self.runners[role] = runner
        return runner

    def generate(self, role: str, prompt: str) -> ExecutionPlan | PatchRequest:
        try:
            runner = self._runner(role)
            response = runner.complete(
                ModelRequest(
                    prompt=prompt,
                    risk=self.task.risk,
                    max_output_tokens=self.routing.max_output_tokens,
                )
            )
            runner._remaining_seconds()  # Late responses are charged, then denied.
            if role == "GPT_BRAINING_PLANNER":
                return ExecutionPlan.model_validate_json(response.content)
            patch = PatchRequest.model_validate_json(response.content)
            if patch.role != role:
                raise ValueError("role mismatch")
            return patch
        except Exception:
            raise HybridRoutingError("hybrid role call denied or invalid output") from None
