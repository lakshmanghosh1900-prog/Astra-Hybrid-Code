"""Remote network authorization, approval, and mandatory audit boundary."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from .gateway import ModelSpec
from .policy import Action, Actor, PolicyDenied, PolicyEngine
from .runtime import RiskTier, Task

AuditSink = Callable[[str, str, str, str, dict[str, object]], object]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class NetworkDenied(PolicyDenied):
    """A remote provider call was denied before any network I/O."""


def spec_key(spec: ModelSpec) -> str:
    return f"{spec.provider}/{spec.model}"


class NetworkAuthorizer:
    """Authorizes remote hops at the worker boundary, never inside the gateway."""

    def __init__(
        self,
        policy: PolicyEngine,
        actor: Actor,
        audit_sink: AuditSink | None,
        *,
        allow_remote_t4: bool = False,
        allow_paid_remote: bool = False,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if audit_sink is None:
            raise NetworkDenied("network authorization requires a process-backed audit sink")
        self.policy = policy
        self.actor = actor
        self.audit_sink = audit_sink
        self.allow_remote_t4 = allow_remote_t4
        self.allow_paid_remote = allow_paid_remote
        self.clock = clock

    def authorize(
        self,
        task: Task,
        specs: Iterable[ModelSpec],
        *,
        estimated_tokens: int,
        estimated_cost: float,
    ) -> frozenset[str]:
        """Return the provider/model keys that may be contacted for this task."""
        candidates = tuple(specs)
        local = {spec_key(spec) for spec in candidates if spec.local}
        remote = tuple(spec for spec in candidates if not spec.local)
        if not remote:
            return frozenset(local)

        decision = self.policy.evaluate(
            self.actor,
            Action.NETWORK,
            task.risk,
            str(task.id),
            estimated_tokens=estimated_tokens,
            estimated_cost=estimated_cost,
            touched_paths=[task.repo_path],
        )
        if not decision.allowed:
            self._emit(
                task,
                provider="*",
                model="*",
                decision="deny",
                reason=decision.reason,
                skip_reason=decision.reason,
                approval_id=None,
                estimated_tokens=estimated_tokens,
                estimated_cost=estimated_cost,
            )
            raise NetworkDenied(decision.reason)

        allowed = set(local)
        now = self.clock()
        for spec in remote:
            reason, approval_id = self._remote_denial(task, spec, now)
            self._emit(
                task,
                provider=spec.provider,
                model=spec.model,
                decision="deny" if reason else "allow",
                reason=reason or "allowed",
                skip_reason=reason,
                approval_id=approval_id,
                estimated_tokens=estimated_tokens,
                estimated_cost=estimated_cost,
            )
            if reason is None:
                allowed.add(spec_key(spec))
        if not allowed:
            raise NetworkDenied("no network-authorized candidate")
        return frozenset(allowed)

    def _remote_denial(
        self, task: Task, spec: ModelSpec, now: datetime
    ) -> tuple[str | None, str | None]:
        approval_id: str | None = None
        task_id = str(task.id)
        if task.risk is RiskTier.T4:
            if not self.allow_remote_t4:
                return "t4 remote denied", None
            approval = self.policy.remote_approval(
                task_id, spec.provider, now=now, paid=not spec.free_tier
            )
            if approval is None:
                return "t4 remote approval required", None
            approval_id = approval.approval_id

        if not spec.free_tier:
            if not self.allow_paid_remote:
                return "paid remote denied", approval_id
            if not spec.paid_authorized:
                return "paid provider not authorized", approval_id
            secret_decision = self.policy.evaluate(
                self.actor,
                Action.SECRETS,
                task.risk,
                task_id,
                touched_paths=[task.repo_path],
            )
            if not secret_decision.allowed:
                return f"secret access denied: {secret_decision.reason}", approval_id
            approval = self.policy.remote_approval(task_id, spec.provider, now=now, paid=True)
            if approval is None:
                return "paid approval required", approval_id
            approval_id = approval.approval_id
        return None, approval_id

    def _emit(
        self,
        task: Task,
        *,
        provider: str,
        model: str,
        decision: str,
        reason: str,
        skip_reason: str | None,
        approval_id: str | None,
        estimated_tokens: int,
        estimated_cost: float,
    ) -> None:
        self.audit_sink(
            self.actor.actor_id,
            "network_decision",
            str(task.id),
            decision,
            {
                "provider": provider,
                "model": model,
                "decision": decision,
                "reason": reason,
                "skip_reason": skip_reason,
                "budget": {"tokens": estimated_tokens, "cost": estimated_cost},
                "tokens": estimated_tokens,
                "cost": estimated_cost,
                "approval_id": approval_id,
                "actor": self.actor.actor_id,
                "task_id": str(task.id),
                "risk": task.risk.value,
            },
        )
