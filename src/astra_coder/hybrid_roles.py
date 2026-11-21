"""Data-only role routing for existing cascade and bounded agent hosts."""

from collections.abc import Callable
from typing import Literal

from .agent_orchestrator import AgentRole, AgentTask, AstraAgent
from .hybrid_skill import ExecutionPlan, PatchRequest


class HybridRoleAdapter:
    """Provider callbacks receive text only, with no shell/filesystem tools.

    A host may wrap its existing free_cascade gateway in these callbacks. The
    callbacks are trusted transport code, not executable model-produced code.
    """

    def __init__(self, planner: Callable[[str], str], coder: Callable[[str], str]) -> None:
        self._planner = planner
        self._coder = coder

    def plan(self, prompt: str) -> ExecutionPlan:
        return ExecutionPlan.model_validate_json(self._planner(prompt))

    def patch(self, prompt: str, role: Literal["CLAUDE_CODER", "CODEX_CODER"]) -> PatchRequest:
        agent = AstraAgent(
            "stage07-coder", AgentRole.CODER, lambda task: self._coder(task.description)
        )
        result = agent.execute(AgentTask(description=prompt))
        if not result.succeeded or result.output is None:
            raise ValueError("coding provider failed")
        request = PatchRequest.model_validate_json(result.output)
        if request.role != role:
            raise ValueError("provider role mismatch")
        return request
