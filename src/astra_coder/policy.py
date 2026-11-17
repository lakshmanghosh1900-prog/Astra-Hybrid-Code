"""Fail-closed RBAC, risk, approval, kill-switch, and budget policy."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from threading import RLock

from pydantic import BaseModel, ConfigDict, Field

from .runtime import RiskTier


class Role(str):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    REVIEWER = "reviewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class Action(str):
    READ = "read"
    EDIT = "edit"
    EXECUTE = "execute"
    TEST = "test"
    GIT = "git"
    APPROVE = "approve"
    CANCEL = "cancel"
    NETWORK = "network"
    SECRETS = "secrets"
    DEPLOY = "deploy"


class Actor(BaseModel):
    model_config = ConfigDict(frozen=True)

    actor_id: str = Field(min_length=1, max_length=256)
    role: str = Field(min_length=1, max_length=32)


class Usage(BaseModel):
    tokens: int = Field(default=0, ge=0)
    cost: float = Field(default=0.0, ge=0.0)


class RemoteApproval(BaseModel):
    """Task-specific, expiring approval for one remote provider hop.

    This object authorizes a recorded human decision, not a role label supplied
    by a model. ``paid`` must match the provider's pricing mode and ``provider``
    must match the hop being called.
    """

    model_config = ConfigDict(frozen=True)

    approval_id: str = Field(min_length=1, max_length=128)
    approver: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    created_at: datetime
    expires_at: datetime
    paid: bool = False
    spec_hash: str | None = None
    scope_hash: str | None = None


class PolicyConfig(BaseModel):
    repo_root: Path | None = None
    per_task_tokens: int = Field(default=100_000, gt=0)
    daily_tokens: int = Field(default=1_000_000, gt=0)
    per_task_cost: float = Field(default=100.0, gt=0.0)
    daily_cost: float = Field(default=1_000.0, gt=0.0)
    approval_min_risk: RiskTier = RiskTier.T2


class PolicyDecision(BaseModel):
    allowed: bool
    approval_required: bool = False
    reason: str
    risk: RiskTier


class PolicyDenied(PermissionError):
    """Raised when policy refuses a mutation or usage reservation."""


_PERMISSIONS: dict[str, frozenset[str]] = {
    Role.VIEWER: frozenset({Action.READ}),
    Role.DEVELOPER: frozenset(
        {Action.READ, Action.EDIT, Action.EXECUTE, Action.TEST, Action.GIT, Action.CANCEL}
    ),
    Role.REVIEWER: frozenset({Action.READ, Action.APPROVE, Action.CANCEL}),
    Role.OPERATOR: frozenset(
        {
            Action.READ,
            Action.EDIT,
            Action.EXECUTE,
            Action.TEST,
            Action.GIT,
            Action.APPROVE,
            Action.CANCEL,
            Action.NETWORK,
            Action.DEPLOY,
        }
    ),
    Role.ADMIN: frozenset(
        Action.__dict__[name]
        for name in (
            "READ",
            "EDIT",
            "EXECUTE",
            "TEST",
            "GIT",
            "APPROVE",
            "CANCEL",
            "NETWORK",
            "SECRETS",
            "DEPLOY",
        )
    ),
}
_MUTATING: frozenset[str] = frozenset(
    {
        Action.EDIT,
        Action.EXECUTE,
        Action.TEST,
        Action.GIT,
        Action.NETWORK,
        Action.SECRETS,
        Action.DEPLOY,
    }
)
_RISK_ORDER: dict[RiskTier, int] = {
    tier: index
    for index, tier in enumerate((RiskTier.T0, RiskTier.T1, RiskTier.T2, RiskTier.T3, RiskTier.T4))
}


@dataclass(frozen=True, slots=True)
class _DayKey:
    day: date


def _remote_key(task_id: str, provider: str) -> str:
    return f"{task_id}/{provider}"


class PolicyEngine:
    """Central policy decision point; no caller may bypass `evaluate`."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        *,
        today: Callable[[], date] = date.today,
    ) -> None:
        self.config = config or PolicyConfig()
        self._lock = RLock()
        self._task_usage: defaultdict[str, Usage] = defaultdict(Usage)
        self._daily_usage: defaultdict[_DayKey, Usage] = defaultdict(Usage)
        self._approvals: dict[str, tuple[str, str | None, str | None]] = {}
        self._remote_approvals: dict[str, RemoteApproval] = {}
        self._kill_switch = False
        self._today = today

    @property
    def kill_switch_enabled(self) -> bool:
        with self._lock:
            return self._kill_switch

    def set_kill_switch(self, actor: Actor, enabled: bool) -> None:
        self._require(actor, Action.APPROVE if enabled else Action.APPROVE)
        if actor.role not in {Role.ADMIN}:
            raise PolicyDenied("only an admin can change the kill switch")
        with self._lock:
            self._kill_switch = enabled

    def approve(
        self,
        task_id: str,
        actor: Actor,
        spec_hash: str | None = None,
        scope_hash: str | None = None,
    ) -> None:
        self._require(actor, Action.APPROVE)
        with self._lock:
            self._approvals[task_id] = (actor.actor_id, spec_hash, scope_hash)

    def restore_approval(
        self, task_id: str, actor_id: str, spec_hash: str, scope_hash: str
    ) -> None:
        """Restore durable approval evidence after a process restart."""
        with self._lock:
            self._approvals[task_id] = (actor_id, spec_hash, scope_hash)

    def deny(self, task_id: str, actor: Actor) -> None:
        self._require(actor, Action.APPROVE)
        with self._lock:
            self._approvals.pop(task_id, None)

    def record_remote_approval(self, actor: Actor, approval: RemoteApproval) -> None:
        """Record a trusted, expiring remote-provider approval for one task hop."""
        self._require(actor, Action.APPROVE)
        if actor.role not in {Role.REVIEWER, Role.OPERATOR, Role.ADMIN}:
            raise PolicyDenied("only a reviewer, operator, or admin can approve remote access")
        if approval.approver != actor.actor_id:
            raise PolicyDenied("remote approval approver must match the acting principal")
        if approval.created_at.tzinfo is None or approval.expires_at.tzinfo is None:
            raise PolicyDenied("remote approval timestamps must be timezone-aware")
        if approval.expires_at <= approval.created_at:
            raise PolicyDenied("remote approval expiry must be after creation")
        with self._lock:
            self._remote_approvals[_remote_key(approval.task_id, approval.provider)] = approval

    def revoke_remote_approval(self, task_id: str, provider: str, actor: Actor) -> None:
        self._require(actor, Action.APPROVE)
        with self._lock:
            self._remote_approvals.pop(_remote_key(task_id, provider), None)

    def remote_approval(
        self,
        task_id: str,
        provider: str,
        *,
        now: datetime,
        paid: bool,
        spec_hash: str | None = None,
        scope_hash: str | None = None,
    ) -> RemoteApproval | None:
        """Return a matching, unexpired approval or ``None`` (fail closed)."""
        with self._lock:
            approval = self._remote_approvals.get(_remote_key(task_id, provider))
        if approval is None or approval.expires_at <= now or approval.paid != paid:
            return None
        if spec_hash is not None and approval.spec_hash is not None:
            if approval.spec_hash != spec_hash:
                return None
        if scope_hash is not None and approval.scope_hash is not None:
            if approval.scope_hash != scope_hash:
                return None
        return approval

    def evaluate(
        self,
        actor: Actor,
        action: str,
        risk: RiskTier,
        task_id: str,
        *,
        estimated_tokens: int = 0,
        estimated_cost: float = 0.0,
        touched_paths: Iterable[str | Path] = (),
        spec_hash: str | None = None,
        scope_hash: str | None = None,
    ) -> PolicyDecision:
        if estimated_tokens < 0 or estimated_cost < 0:
            return PolicyDecision(allowed=False, reason="negative budget estimate", risk=risk)
        if action not in _PERMISSIONS.get(actor.role, frozenset()):
            return PolicyDecision(
                allowed=False, reason="role is not permitted for action", risk=risk
            )
        with self._lock:
            if self._kill_switch and action not in {Action.READ, Action.CANCEL, Action.APPROVE}:
                return PolicyDecision(allowed=False, reason="kill switch is enabled", risk=risk)
            path_error = self._path_error(touched_paths, action)
            if path_error:
                return PolicyDecision(allowed=False, reason=path_error, risk=risk)
            budget_error = self._budget_error(task_id, estimated_tokens, estimated_cost)
            if budget_error:
                return PolicyDecision(allowed=False, reason=budget_error, risk=risk)
            approval_required = (
                action in _MUTATING
                and _RISK_ORDER[risk] >= _RISK_ORDER[self.config.approval_min_risk]
            )
            approval = self._approvals.get(task_id)
            approval_matches = (
                approval is not None
                and (spec_hash is None or approval[1] == spec_hash)
                and (scope_hash is None or approval[2] == scope_hash)
            )
            if approval_required and not approval_matches:
                return PolicyDecision(
                    allowed=False,
                    approval_required=True,
                    reason="human approval required",
                    risk=risk,
                )
            return PolicyDecision(
                allowed=True, approval_required=approval_required, reason="allowed", risk=risk
            )

    def record_usage(self, task_id: str, tokens: int, cost: float) -> Usage:
        if tokens < 0 or cost < 0:
            raise PolicyDenied("usage cannot be negative")
        with self._lock:
            error = self._budget_error(task_id, tokens, cost)
            if error:
                raise PolicyDenied(error)
            current = self._task_usage[task_id]
            current.tokens += tokens
            current.cost += cost
            daily = self._daily_usage[_DayKey(self._today())]
            daily.tokens += tokens
            daily.cost += cost
            return current.model_copy(deep=True)

    def can_afford(self, task_id: str, tokens: int, cost: float) -> str | None:
        """Read-only pre-flight check; returns the first exceeded limit reason."""
        if tokens < 0 or cost < 0:
            return "negative budget estimate"
        with self._lock:
            return self._budget_error(task_id, tokens, cost)

    def charge_usage(self, task_id: str, tokens: int, cost: float) -> Usage:
        """Always record actual usage, then raise if a cumulative limit is exceeded."""
        if tokens < 0 or cost < 0:
            raise PolicyDenied("usage cannot be negative")
        with self._lock:
            current = self._task_usage[task_id]
            current.tokens += tokens
            current.cost += cost
            daily = self._daily_usage[_DayKey(self._today())]
            daily.tokens += tokens
            daily.cost += cost
            recorded = current.model_copy(deep=True)
            error = self._recorded_budget_error(current, daily)
            if error:
                raise PolicyDenied(error)
            return recorded

    def usage(self, task_id: str) -> Usage:
        with self._lock:
            return self._task_usage[task_id].model_copy(deep=True)

    def _require(self, actor: Actor, action: str) -> None:
        if action not in _PERMISSIONS.get(actor.role, frozenset()):
            raise PolicyDenied("role is not permitted for action")

    def _budget_error(self, task_id: str, tokens: int, cost: float) -> str | None:
        task = self._task_usage[task_id]
        daily = self._daily_usage[_DayKey(self._today())]
        if task.tokens + tokens > self.config.per_task_tokens:
            return "per-task token budget exceeded"
        if task.cost + cost > self.config.per_task_cost:
            return "per-task cost budget exceeded"
        if daily.tokens + tokens > self.config.daily_tokens:
            return "daily token budget exceeded"
        if daily.cost + cost > self.config.daily_cost:
            return "daily cost budget exceeded"
        return None

    def _recorded_budget_error(self, task: Usage, daily: Usage) -> str | None:
        if task.tokens > self.config.per_task_tokens:
            return "per-task token budget exceeded"
        if task.cost > self.config.per_task_cost:
            return "per-task cost budget exceeded"
        if daily.tokens > self.config.daily_tokens:
            return "daily token budget exceeded"
        if daily.cost > self.config.daily_cost:
            return "daily cost budget exceeded"
        return None

    def _path_error(self, touched_paths: Iterable[str | Path], action: str) -> str | None:
        if self.config.repo_root is None:
            return None
        root = self.config.repo_root.resolve()
        if not root.is_dir():
            if action in _MUTATING:
                return "approved repository root is unavailable"
            return None
        paths = tuple(touched_paths)
        if action in _MUTATING and not paths:
            return "mutation scope is not specified"
        for raw_path in paths:
            candidate_path = Path(raw_path)
            if not candidate_path.is_absolute():
                candidate_path = root / candidate_path
            candidate = candidate_path.resolve(strict=False)
            try:
                candidate.relative_to(root)
            except ValueError:
                return "path is outside the approved repository root"
        return None
