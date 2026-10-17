from pathlib import Path

import pytest

from astra_coder.policy import (
    Action,
    Actor,
    PolicyConfig,
    PolicyDenied,
    PolicyEngine,
    Role,
)
from astra_coder.runtime import RiskTier


def test_developer_can_read_and_edit_low_risk() -> None:
    engine = PolicyEngine()
    actor = Actor(actor_id="dev", role=Role.DEVELOPER)
    assert engine.evaluate(actor, Action.READ, RiskTier.T0, "task").allowed
    assert engine.evaluate(actor, Action.EDIT, RiskTier.T1, "task").allowed


def test_viewer_cannot_bypass_edit_permission() -> None:
    engine = PolicyEngine()
    decision = engine.evaluate(
        Actor(actor_id="viewer", role=Role.VIEWER), Action.EDIT, RiskTier.T1, "task"
    )
    assert not decision.allowed
    assert "not permitted" in decision.reason


def test_high_risk_edit_requires_reviewer_approval() -> None:
    engine = PolicyEngine()
    developer = Actor(actor_id="dev", role=Role.DEVELOPER)
    decision = engine.evaluate(developer, Action.EDIT, RiskTier.T2, "task")
    assert not decision.allowed
    assert decision.approval_required
    engine.approve("task", Actor(actor_id="reviewer", role=Role.REVIEWER))
    assert engine.evaluate(developer, Action.EDIT, RiskTier.T2, "task").allowed


def test_non_reviewer_cannot_grant_approval() -> None:
    engine = PolicyEngine()
    with pytest.raises(PolicyDenied):
        engine.approve("task", Actor(actor_id="dev", role=Role.DEVELOPER))


def test_kill_switch_denies_mutations_but_allows_status() -> None:
    engine = PolicyEngine()
    admin = Actor(actor_id="admin", role=Role.ADMIN)
    developer = Actor(actor_id="dev", role=Role.DEVELOPER)
    engine.set_kill_switch(admin, True)
    assert engine.evaluate(developer, Action.READ, RiskTier.T0, "task").allowed
    decision = engine.evaluate(developer, Action.EDIT, RiskTier.T1, "task")
    assert not decision.allowed
    assert "kill switch" in decision.reason


def test_non_admin_cannot_toggle_kill_switch() -> None:
    engine = PolicyEngine()
    with pytest.raises(PolicyDenied):
        engine.set_kill_switch(Actor(actor_id="dev", role=Role.OPERATOR), True)


def test_task_and_daily_budgets_are_enforced() -> None:
    engine = PolicyEngine(
        PolicyConfig(per_task_tokens=10, daily_tokens=100, per_task_cost=1, daily_cost=5)
    )
    assert engine.record_usage("task", 8, 0.5).tokens == 8
    with pytest.raises(PolicyDenied, match="per-task token"):
        engine.record_usage("task", 3, 0)


def test_negative_usage_is_rejected() -> None:
    with pytest.raises(PolicyDenied):
        PolicyEngine().record_usage("task", -1, 0)


def test_paths_must_stay_inside_repository_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    engine = PolicyEngine(PolicyConfig(repo_root=root))
    actor = Actor(actor_id="dev", role=Role.DEVELOPER)
    allowed = engine.evaluate(
        actor, Action.READ, RiskTier.T0, "task", touched_paths=[root / "a.py"]
    )
    denied = engine.evaluate(
        actor, Action.READ, RiskTier.T0, "task", touched_paths=[tmp_path / "outside.py"]
    )
    assert allowed.allowed
    assert not denied.allowed


def test_unknown_role_fails_closed() -> None:
    decision = PolicyEngine().evaluate(
        Actor(actor_id="x", role="model"), Action.READ, RiskTier.T0, "task"
    )
    assert not decision.allowed
