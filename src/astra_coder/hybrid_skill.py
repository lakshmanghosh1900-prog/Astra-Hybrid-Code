"""Stage 07 contracts and a single-file, audited patch executor."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .rea.enforcement import require_stage05b_execution
from .rea.receipt import append_audit_event

SKILL = "rea-hybrid-braining-coding"
PROTECTED = (
    "authorization.json",
    "evidence-index.json",
    "rea-verification.json",
    "reports/worker-smoke.json",
    "src/astra_coder/rea",
    ".git",
    ".tools",
)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Step(Contract):
    step_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    target_path: str = Field(min_length=1)
    verification_commands: list[str] = Field(default_factory=list)


class ExecutionPlan(Contract):
    plan_id: str = Field(min_length=1)
    role: Literal["GPT_BRAINING_PLANNER"]
    read_only: Literal[True]
    requires_rea_gate: Literal[True]
    risk_checks: list[str] = Field(min_length=1)
    allowed_target_paths: list[str] = Field(min_length=1)
    excluded_paths: list[str]
    steps: list[Step] = Field(min_length=1)


class SkillBinding(Contract):
    skill: Literal["rea-hybrid-braining-coding"]
    gate: Literal["rea-gate"]
    fail_closed: Literal[True]


class PatchRequest(Contract):
    role: Literal["CLAUDE_CODER", "CODEX_CODER"]
    plan_id: str
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    step_id: str
    diff_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    diff: str = Field(min_length=1)
    rea_skill_binding: SkillBinding


def plan_digest(plan: ExecutionPlan) -> str:
    return hashlib.sha256(
        json.dumps(plan.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def contained(root: Path, name: str) -> Path:
    if (
        not name
        or "\\" in name
        or ":" in name
        or PureWindowsPath(name).is_absolute()
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError("invalid relative path")
    target = (root / name).resolve()
    if not target.is_relative_to(root) or target == root:
        raise ValueError("path escapes root")
    if target != root / name:
        raise ValueError("symlink aliases are not permitted")
    if any(
        part.casefold().startswith((".mypy_cache", ".pytest_cache", "__pycache__"))
        for part in name.split("/")
    ):
        raise ValueError("cache targets are forbidden")
    return target


def patched_text(original: str, diff: str, name: str) -> str:
    """Accept only plain unified single-file patches; reject all other syntax."""
    lines = diff.splitlines(keepends=True)
    if lines[:2] != [f"--- a/{name}\n", f"+++ b/{name}\n"]:
        raise ValueError("patch headers do not match approved target")
    source = original.splitlines(keepends=True)
    output: list[str] = []
    cursor = 0
    index = 2
    hunks = 0
    while index < len(lines):
        match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n", lines[index])
        if match is None:
            raise ValueError("unsupported hunk")
        start, old_count, new_start, new_count = map(int, match.groups())
        offset = start - 1 if old_count else start
        if offset < cursor or offset > len(source):
            raise ValueError("overlapping or invalid hunk")
        output.extend(source[cursor:offset])
        cursor = offset
        if new_start != (len(output) + 1 if new_count else len(output)):
            raise ValueError("invalid new hunk offset")
        index += 1
        removed = added = 0
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            if line[:1] not in {" ", "+", "-"}:
                raise ValueError("unsupported patch line")
            if line[0] in " -":
                if cursor >= len(source) or source[cursor] != line[1:]:
                    raise ValueError("patch context mismatch")
                cursor += 1
                removed += 1
            if line[0] in " +":
                output.append(line[1:])
                added += 1
            index += 1
        if (removed, added) != (old_count, new_count):
            raise ValueError("hunk count mismatch")
        hunks += 1
    if not hunks:
        raise ValueError("empty patch")
    return "".join(output + source[cursor:])


def execute_patch(
    *,
    repo_root: Path,
    plan: ExecutionPlan,
    request: PatchRequest,
    approved_plan_sha256: str,
    actor_id: str,
    approver_id: str,
    audit_log: Path,
) -> None:
    """Approval digest comes from the trusted host, never provider output.

    The host must serialize writers and exclude untrusted local filesystem writers.
    Verification command strings are proposals only and are never executed here.
    """
    root = repo_root.resolve()
    plan = ExecutionPlan.model_validate_json(plan.model_dump_json())
    request = PatchRequest.model_validate_json(request.model_dump_json())
    digest = plan_digest(plan)
    if digest != approved_plan_sha256 or digest != request.plan_sha256:
        raise ValueError("unapproved plan digest")
    if request.plan_id != plan.plan_id or actor_id == approver_id:
        raise ValueError("plan or identity mismatch")
    if hashlib.sha256(request.diff.encode()).hexdigest() != request.diff_sha256:
        raise ValueError("diff digest mismatch")
    if len({s.step_id for s in plan.steps}) != len(plan.steps):
        raise ValueError("duplicate step IDs")
    steps = [s for s in plan.steps if s.step_id == request.step_id]
    if len(steps) != 1:
        raise ValueError("unknown step")
    name = steps[0].target_path
    target = contained(root, name)
    for p in plan.allowed_target_paths + plan.excluded_paths:
        contained(root, p)
    if name not in plan.allowed_target_paths:
        raise ValueError("target not explicitly allowed")
    for excluded in (*PROTECTED, *plan.excluded_paths):
        if name.casefold() == excluded.casefold() or name.casefold().startswith(
            excluded.casefold() + "/"
        ):
            raise ValueError("excluded target")
    # Audit destination must be external: never overwrite code or evidence as a log.
    if audit_log.resolve().is_relative_to(root):
        raise ValueError("audit log must be external")
    result = require_stage05b_execution(
        repo_root=root,
        actor_id=actor_id,
        role="SYSTEM_VERIFIER",
        approver_id=approver_id,
        audit_log_path=audit_log,
    )
    if not result.allowed:
        raise PermissionError("rea-gate denied: " + "; ".join(result.blocking_reasons))
    original = target.read_bytes()
    updated = patched_text(original.decode("utf-8"), request.diff, name).encode()
    append_audit_event(
        audit_log,
        event_id=f"stage07-{uuid.uuid4().hex}",
        event_type="STAGE07_PATCH_INTENT",
        actor_type="SYSTEM_VERIFIER",
        actor_identity=actor_id,
        authorization_id=None,
        decision="APPROVED",
        evidence_reference=f"{digest}:{request.step_id}:{request.diff_sha256}",
    )
    if contained(root, name) != target or target.read_bytes() != original:
        raise ValueError("target changed during authorization")
    target.write_bytes(updated)
