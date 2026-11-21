"""Governed Phase 2 entry point. Provider outputs never invoke host tools."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Literal

from .hybrid_approval import ApprovalEnvelope, ApprovalStore, verify_approval
from .hybrid_routing import HybridProviderRouter
from .hybrid_skill import (
    Contract,
    ExecutionPlan,
    PatchRequest,
    SkillBinding,
    atomic_replace,
    contained,
    execute_patch,
    plan_digest,
)
from .rea.filelock import exclusive_file_lock
from .rea.receipt import append_audit_event
from .sandbox import DockerSandbox, SandboxRequest
from .sandbox_tools import SandboxToolCall, validate_tool_call
from .tools import RunCommandInput


class EnterpriseReport(Contract):
    authorization_id: str
    status: Literal["COMPLETED", "SKIPPED_NO_SANDBOX"]
    target_sha256: str


class HybridEnterpriseRunner:
    """Trusted host selects workspace/log/store/sandbox and provisions R1/R2/R3.

    Approval is supplied externally, never minted by this runner. A pre-coding
    envelope must already bind the exact intended diff; otherwise two-phase human
    review is needed. No new R1/registries are written by production code.
    """

    def __init__(
        self,
        *,
        router: HybridProviderRouter,
        repo_root: Path,
        audit_log: Path,
        approval_store: ApprovalStore,
        executor: str,
        sandbox: DockerSandbox | None = None,
        image: str | None = None,
    ) -> None:
        if audit_log.resolve().is_relative_to(repo_root.resolve()):
            raise ValueError("audit must be external")
        self.router, self.root, self.log = router, repo_root.resolve(), audit_log
        self.store, self.executor = approval_store, executor
        self.sandbox, self.image = sandbox, image

    def plan(self, prompt: str) -> ExecutionPlan:
        result = self.router.generate("GPT_BRAINING_PLANNER", prompt)
        if not isinstance(result, ExecutionPlan):
            raise ValueError("planner contract")
        return result

    def _event(
        self, envelope: ApprovalEnvelope, kind: str, evidence: str, failed: bool = False
    ) -> None:
        append_audit_event(
            self.log,
            event_id=f"phase2-{uuid.uuid4().hex}",
            event_type=kind,
            actor_type="SYSTEM_VERIFIER",
            actor_identity=self.executor,
            authorization_id=envelope.authorization_id,
            decision="REJECTED" if failed else "APPROVED",
            evidence_reference=evidence,
        )

    def run(
        self,
        *,
        plan: ExecutionPlan,
        approval: ApprovalEnvelope,
        coder_role: Literal["CLAUDE_CODER", "CODEX_CODER"],
        step_id: str,
        prompt: str,
        verification: RunCommandInput | None = None,
    ) -> EnterpriseReport:
        # One authoritative store/log pair per workspace is mandatory.
        with exclusive_file_lock(self.log.with_name(self.log.name + ".enterprise.lock")):
            proposed = PatchRequest(
                role=coder_role,
                plan_id=plan.plan_id,
                plan_sha256=plan_digest(plan),
                step_id=step_id,
                diff_sha256=approval.diff_sha256,
                diff="pending transport output",
                rea_skill_binding=SkillBinding(
                    skill="rea-hybrid-braining-coding", gate="rea-gate", fail_closed=True
                ),
            )
            verify_approval(
                approval, executor=self.executor, plan=plan, request=proposed, repo_root=self.root
            )
            patch = self.router.generate(
                coder_role, prompt + "\nApproved plan: " + plan.model_dump_json()
            )
            if not isinstance(patch, PatchRequest):
                raise ValueError("coder contract")
            verify_approval(
                approval, executor=self.executor, plan=plan, request=patch, repo_root=self.root
            )
            step = next(s for s in plan.steps if s.step_id == patch.step_id)
            target = contained(self.root, step.target_path)
            original = target.read_bytes()
            if verification is not None:
                verification = RunCommandInput.model_validate_json(verification.model_dump_json())
                call = SandboxToolCall(tool="run_command", arguments=verification.model_dump())
                validate_tool_call(call)
            else:
                call = None
            self.store.consume(approval)
            applied = False
            try:
                execute_patch(
                    repo_root=self.root,
                    plan=plan,
                    request=patch,
                    approved_plan_sha256=approval.plan_sha256,
                    actor_id=self.executor,
                    approver_id=approval.approver_id,
                    audit_log=self.log,
                )
                applied = True
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
                self._event(approval, "STAGE07_PATCH_APPLIED", digest)
                status: Literal["COMPLETED", "SKIPPED_NO_SANDBOX"] = "SKIPPED_NO_SANDBOX"
                if call is not None and self.sandbox is not None and self.sandbox.available:
                    if not self.image:
                        raise ValueError("sandbox image required")
                    result = self.sandbox.run(
                        SandboxRequest(
                            image=self.image,
                            workspace=self.root,
                            read_only_workspace=True,
                            argv=["python", "-I", "-m", "astra_coder.sandbox_tools"],
                            stdin=call.model_dump_json(),
                            timeout_seconds=verification.timeout_seconds if verification else 30,
                        )
                    )
                    tool = json.loads(result.output) if result.ok else {}
                    if not result.ok or tool.get("ok") is not True:
                        raise ValueError("sandbox verification failed")
                    status = "COMPLETED"
                self._event(approval, "STAGE07_VERIFICATION_RESULT", status)
                if status == "COMPLETED":
                    self._event(approval, "STAGE07_EXECUTION_COMPLETED", digest)
                else:
                    self._event(approval, "STAGE07_EXECUTION_FAILED", status, failed=True)
                return EnterpriseReport(
                    authorization_id=approval.authorization_id, status=status, target_sha256=digest
                )
            except Exception:
                if applied:
                    atomic_replace(target, original)
                try:
                    self._event(approval, "STAGE07_EXECUTION_FAILED", "execution denied", True)
                except Exception:
                    raise RuntimeError("execution failed; failure audit unavailable") from None
                raise RuntimeError("hybrid execution failed; reconciliation required") from None
