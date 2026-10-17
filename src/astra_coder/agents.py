"""Bounded agent roles, prompt-injection defenses, and reproduce-first repair."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .runtime import Task
from .tools import (
    ReadFileInput,
    RunCommandInput,
    SearchInput,
    ToolMesh,
    ToolResult,
    WritePatchInput,
)


class AgentRole(StrEnum):
    ARCHITECT = "architect"
    EDITOR = "editor"
    REVIEWER = "reviewer"
    REPAIR = "repair"


class PromptInjectionDetected(ValueError):
    """Repository content attempted to act as agent control input."""


class PromptInjectionGuard:
    _PATTERNS = (
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I),
        re.compile(r"system\s+(?:message|prompt)\s*:", re.I),
        re.compile(r"(?:send|upload|exfiltrate)\s+.*(?:secret|token|credential)", re.I),
        re.compile(r"disable\s+(?:security|sandbox|verification)", re.I),
        re.compile(r"run\s+(?:curl|wget|nc)\b", re.I),
    )

    def inspect(self, text: str) -> tuple[str, ...]:
        findings: list[str] = []
        for pattern in self._PATTERNS:
            if pattern.search(text):
                findings.append(pattern.pattern)
        return tuple(findings)

    def require_safe(self, text: str) -> str:
        findings = self.inspect(text)
        if findings:
            raise PromptInjectionDetected(
                "untrusted repository content contains agent-control instructions"
            )
        return text


class PlanAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2_000)


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    goal: str = Field(min_length=1, max_length=4_000)
    steps: tuple[PlanAction, ...] = Field(min_length=1, max_length=100)
    requires_approval: bool = False


class EditorResult(BaseModel):
    ok: bool
    results: tuple[ToolResult, ...] = ()
    error: str | None = None


class VerificationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    required_gates_run: bool
    all_gates_passed: bool
    diff_within_workspace: bool
    evidence_hash: str = ""


class ReviewResult(BaseModel):
    accepted: bool
    reason: str


class RepairResult(BaseModel):
    attempted: bool
    attempt: int
    reason: str


PlanBuilder = Callable[[Task, str], Plan]
Reproducer = Callable[[str], bool]
Fixer = Callable[[str], bool]


class ArchitectAgent:
    role = AgentRole.ARCHITECT

    def __init__(self, builder: PlanBuilder, guard: PromptInjectionGuard | None = None) -> None:
        self._builder = builder
        self._guard = guard or PromptInjectionGuard()

    def plan(self, task: Task, repository_context: str) -> Plan:
        safe_context = self._guard.require_safe(repository_context)
        plan = self._builder(task, safe_context)
        if not plan.steps:
            raise ValueError("architect returned an empty plan")
        return plan


class EditorAgent:
    role = AgentRole.EDITOR

    def apply(self, plan: Plan, tools: ToolMesh) -> EditorResult:
        results: list[ToolResult] = []
        for action in plan.steps:
            try:
                result = self._dispatch(action.tool, action.payload, tools)
            except (TypeError, ValueError) as exc:
                return EditorResult(
                    ok=False, results=tuple(results), error=f"invalid tool payload: {exc}"
                )
            results.append(result)
            if not result.ok:
                return EditorResult(ok=False, results=tuple(results), error=result.error)
        return EditorResult(ok=True, results=tuple(results))

    def _dispatch(self, name: str, payload: Mapping[str, Any], tools: ToolMesh) -> ToolResult:
        if name == "read_file":
            return tools.read_file(ReadFileInput.model_validate(payload))
        if name == "write_patch":
            return tools.write_patch(WritePatchInput.model_validate(payload))
        if name == "run_command":
            return tools.run_command(RunCommandInput.model_validate(payload))
        if name == "run_tests":
            return tools.run_tests(RunCommandInput.model_validate(payload))
        if name == "search":
            return tools.search(SearchInput.model_validate(payload))
        raise ValueError(f"unknown or unapproved tool: {name}")


class IndependentReviewerAgent:
    role = AgentRole.REVIEWER

    def review(self, evidence: VerificationEvidence) -> ReviewResult:
        if not evidence.required_gates_run:
            return ReviewResult(accepted=False, reason="required verification gates were not run")
        if not evidence.all_gates_passed:
            return ReviewResult(
                accepted=False, reason="verification evidence contains a failed gate"
            )
        if not evidence.diff_within_workspace:
            return ReviewResult(accepted=False, reason="diff escaped the approved workspace")
        if not evidence.evidence_hash:
            return ReviewResult(accepted=False, reason="evidence hash is missing")
        return ReviewResult(accepted=True, reason="independent evidence is complete")


class RepairAgent:
    role = AgentRole.REPAIR

    def __init__(self, max_attempts: int = 3) -> None:
        if max_attempts < 0:
            raise ValueError("max_attempts cannot be negative")
        self.max_attempts = max_attempts
        self.attempts = 0

    def repair(self, failure: str, reproduce: Reproducer, fix: Fixer) -> RepairResult:
        if self.attempts >= self.max_attempts:
            return RepairResult(
                attempted=False, attempt=self.attempts, reason="repair budget exhausted"
            )
        if not reproduce(failure):
            return RepairResult(
                attempted=False, attempt=self.attempts, reason="failure did not reproduce"
            )
        self.attempts += 1
        if not fix(failure):
            return RepairResult(attempted=True, attempt=self.attempts, reason="repair failed")
        return RepairResult(attempted=True, attempt=self.attempts, reason="repair applied")
