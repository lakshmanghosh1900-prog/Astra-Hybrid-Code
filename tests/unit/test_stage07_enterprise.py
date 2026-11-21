"""Stub HTTP/container transports, real approval signatures and REA authority."""

import base64
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_stage07_hybrid import case, real_case  # noqa: F401

from astra_coder.config import Settings
from astra_coder.hybrid_approval import (
    ApprovalEnvelope,
    ApprovalStore,
    approval_payload,
    verify_approval,
)
from astra_coder.hybrid_enterprise import HybridEnterpriseRunner
from astra_coder.hybrid_routing import HybridProviderRouter, HybridRoutingError, HybridRoutingPolicy
from astra_coder.hybrid_skill import plan_digest
from astra_coder.policy import Actor, PolicyEngine, RemoteApproval
from astra_coder.runtime import Task, TaskLimits
from astra_coder.sandbox import DockerSandbox, SandboxResult
from astra_coder.tools import RunCommandInput


@pytest.fixture
def enterprise(real_case: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:  # noqa: F811
    key = Ed25519PrivateKey.generate()
    key_path = Path(os.environ["ASTRA_REA_TRUSTED_KEYS_PATH"])
    keys = json.loads(key_path.read_text())
    keys["keys"]["human-approval-key"] = {
        "public_key_pem": key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        "status": "ACTIVE",
    }
    key_path.write_text(json.dumps(keys))
    approvers = Path(os.environ["ASTRA_REA_APPROVER_REGISTRY_PATH"])
    obj = json.loads(approvers.read_text())
    obj["approvers"]["human"]["approval_signing_key_ids"] = ["human-approval-key"]
    approvers.write_text(json.dumps(obj))
    now = datetime.now(UTC)
    envelope = ApprovalEnvelope.model_validate_json(
        json.dumps(
            {
                "authorization_id": "auth-05b-20261119-01",
                "approver_id": "human",
                "key_id": "human-approval-key",
                "plan_id": real_case["plan"].plan_id,
                "plan_sha256": plan_digest(real_case["plan"]),
                "diff_sha256": real_case["request"].diff_sha256,
                "target_paths": ["sample.txt"],
                "issued_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "nonce": "test-only-single-use-nonce",
                "signature_base64": "pending",
            }
        )
    )
    envelope = envelope.model_copy(
        update={"signature_base64": base64.b64encode(key.sign(approval_payload(envelope))).decode()}
    )
    journal = tmp_path / "approval-journal.json"
    journal.write_text("[]")
    settings = Settings(
        planner_model="configured-gpt",
        codex_model="configured-codex",
        claude_model="configured-claude",
        openai_base_url="https://test.invalid/v1",
        claude_base_url="https://claude.invalid/v1",
        openai_api_key="test-only-key",
        claude_api_key="test-only-claude-key",
        allow_paid_remote=True,
        retry_backoff_seconds=0,
    )
    task = Task(
        prompt="implement",
        repo_path=str(real_case["repo_root"]),
        limits=TaskLimits(max_tokens=100000, max_seconds=60),
    )
    policy = PolicyEngine()
    actor = Actor(actor_id="network-admin", role="admin")
    for provider in ["gpt_braining_planner", "codex_coder", "claude_coder"]:
        policy.record_remote_approval(
            actor,
            RemoteApproval(
                approval_id=provider,
                approver=actor.actor_id,
                task_id=str(task.id),
                provider=provider,
                created_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=10),
                paid=True,
            ),
        )
    calls: list[str] = []
    state = {"status": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        model = data["model"]
        calls.append(model)
        result = real_case["plan"] if model == "configured-gpt" else real_case["request"]
        if model == "configured-claude":
            result = result.model_copy(update={"role": "CLAUDE_CODER"})
        return httpx.Response(
            state["status"],
            json={
                "choices": [{"message": {"content": result.model_dump_json()}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 20},
            },
        )

    audits = []
    router = HybridProviderRouter(
        settings,
        HybridRoutingPolicy(0.01, 0.02, 512),
        task=task,
        policy=policy,
        actor=actor,
        audit_sink=lambda *args: audits.append(args),
        clients={
            role: httpx.Client(transport=httpx.MockTransport(handler))
            for role in ["GPT_BRAINING_PLANNER", "CODEX_CODER", "CLAUDE_CODER"]
        },
    )

    class ContainerTransport:
        def run(self, argv, timeout_seconds, stdin=None):
            assert "--network=none" in argv
            assert "--read-only" in argv
            call = json.loads(stdin)
            assert call["tool"] == "run_command"
            return SandboxResult(ok=True, output='{"ok": true, "exit_code": 0}')

    sandbox = DockerSandbox(runner=ContainerTransport(), docker_binary="docker")
    runner = HybridEnterpriseRunner(
        router=router,
        repo_root=real_case["repo_root"],
        audit_log=real_case["audit_log"],
        approval_store=ApprovalStore(journal, real_case["repo_root"]),
        executor="executor",
        sandbox=sandbox,
        image="test-image",
    )
    return dict(
        case=real_case,
        envelope=envelope,
        key=key,
        runner=runner,
        router=router,
        calls=calls,
        state=state,
        journal=journal,
        audits=audits,
    )


def test_enterprise_real_rea(enterprise: dict) -> None:
    runner = enterprise["runner"]
    plan = runner.plan("generate plan")
    report = runner.run(
        plan=plan,
        approval=enterprise["envelope"],
        coder_role="CODEX_CODER",
        step_id="s1",
        prompt="generate patch",
        verification=RunCommandInput(argv=["pytest", "-q"]),
    )
    assert report.status == "COMPLETED"
    assert enterprise["calls"] == ["configured-gpt", "configured-codex"]
    root = enterprise["case"]["repo_root"]
    assert (root / "sample.txt").read_bytes() == b"new\n"
    from astra_coder.rea.receipt import verify_event_chain

    events = verify_event_chain(json.loads(enterprise["case"]["audit_log"].read_text())["events"])
    assert events[-1]["event_type"] == "STAGE07_EXECUTION_COMPLETED"


@pytest.mark.parametrize("role", ["GPT_BRAINING_PLANNER", "CODEX_CODER", "CLAUDE_CODER"])
def test_role_selection(enterprise: dict, role: str) -> None:
    enterprise["router"].generate(role, "generate")
    assert len(enterprise["calls"]) == 1


@pytest.mark.parametrize("status,calls", [(401, 1), (403, 1), (429, 1), (500, 3)])
def test_provider_errors(enterprise: dict, status: int, calls: int) -> None:
    enterprise["state"]["status"] = status
    with pytest.raises(HybridRoutingError):
        enterprise["router"].generate("CODEX_CODER", "generate")
    assert len(enterprise["calls"]) == calls
    assert set(enterprise["calls"]) == {"configured-codex"}


@pytest.mark.parametrize("failure", ["missing-key", "missing-model", "remote", "budget", "kill"])
def test_network_denials(enterprise: dict, failure: str) -> None:
    router = enterprise["router"]
    if failure == "missing-key":
        router.settings = replace(router.settings, openai_api_key=None)
    if failure == "missing-model":
        router.settings = replace(router.settings, codex_model=None)
    if failure == "remote":
        router.settings = replace(router.settings, allow_paid_remote=False)
    if failure == "budget":
        router.task.limits = TaskLimits(max_tokens=1)
    if failure == "kill":
        router.policy.set_kill_switch(Actor(actor_id="admin", role="admin"), True)
    with pytest.raises(HybridRoutingError):
        router.generate("CODEX_CODER", "generate")
    assert not enterprise["calls"]


@pytest.mark.parametrize(
    "failure",
    [
        "signature",
        "expired",
        "self",
        "plan",
        "patch",
        "binding",
        "ambiguous",
        "inactive",
        "replay",
        "missing-journal",
    ],
)
def test_approval_denials(enterprise: dict, failure: str) -> None:
    envelope = enterprise["envelope"]
    fixture_case = enterprise["case"]
    executor = "executor"
    if failure == "signature":
        envelope = envelope.model_copy(update={"signature_base64": "invalid"})
    if failure == "expired":
        envelope = envelope.model_copy(update={"expires_at": datetime(2000, 1, 1, tzinfo=UTC)})
    if failure == "self":
        executor = "human"
    if failure == "plan":
        envelope = envelope.model_copy(update={"plan_sha256": "0" * 64})
    if failure == "patch":
        envelope = envelope.model_copy(update={"diff_sha256": "0" * 64})
    if failure in {"binding", "ambiguous", "inactive"}:
        path = Path(os.environ["ASTRA_REA_APPROVER_REGISTRY_PATH"])
        doc = json.loads(path.read_text())
        if failure == "binding":
            doc["approvers"]["human"].pop("approval_signing_key_ids")
        if failure == "ambiguous":
            doc["approvers"]["other"] = doc["approvers"]["human"]
        if failure == "inactive":
            doc["approvers"]["human"]["status"] = "INACTIVE"
        path.write_text(json.dumps(doc))
    with pytest.raises((PermissionError, OSError)):
        verify_approval(
            envelope,
            executor=executor,
            plan=fixture_case["plan"],
            request=fixture_case["request"],
            repo_root=fixture_case["repo_root"],
        )
        store = enterprise["runner"].store
        if failure == "missing-journal":
            enterprise["journal"].unlink()
        store.consume(envelope)
        store.consume(envelope)
    assert (fixture_case["repo_root"] / "sample.txt").read_bytes() == b"old\n"


def test_audit_failure_rollback(enterprise: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    from astra_coder import hybrid_enterprise

    original = hybrid_enterprise.append_audit_event

    def append(*args, **kwargs):
        if kwargs["event_type"] == "STAGE07_PATCH_APPLIED":
            raise OSError("disk")
        return original(*args, **kwargs)

    monkeypatch.setattr(hybrid_enterprise, "append_audit_event", append)
    with pytest.raises(RuntimeError):
        enterprise["runner"].run(
            plan=enterprise["case"]["plan"],
            approval=enterprise["envelope"],
            coder_role="CODEX_CODER",
            step_id="s1",
            prompt="patch",
        )
    assert (enterprise["case"]["repo_root"] / "sample.txt").read_bytes() == b"old\n"


@pytest.mark.parametrize("argv", [["bash", "-c", "x"], ["python", "-c", "x"], ["curl", "x"]])
def test_verification_escape(argv: list[str]) -> None:
    with pytest.raises(ValueError):
        RunCommandInput(argv=argv)


def test_circuit_and_deadline(enterprise: dict) -> None:
    router = enterprise["router"]
    enterprise["state"]["status"] = 500
    with pytest.raises(HybridRoutingError):
        router.generate("CODEX_CODER", "generate")
    assert len(enterprise["calls"]) == 3
    with pytest.raises(HybridRoutingError):
        router.generate("CODEX_CODER", "generate")
    assert len(enterprise["calls"]) == 3
    runner = router._runner("GPT_BRAINING_PLANNER")
    runner.started_at = runner.clock() - 1000
    with pytest.raises(HybridRoutingError):
        router.generate("GPT_BRAINING_PLANNER", "generate")
    assert len(enterprise["calls"]) == 3


def test_usage_and_redaction(enterprise: dict) -> None:
    router = enterprise["router"]
    router.generate("CODEX_CODER", "generate test-only-key")
    assert router.policy.usage(str(router.task.id)).tokens == 40
    assert "test-only-key" not in json.dumps(enterprise["audits"])


def test_missing_network_approval(enterprise: dict) -> None:
    router = enterprise["router"]
    router.policy.revoke_remote_approval(str(router.task.id), "codex_coder", router.actor)
    with pytest.raises(HybridRoutingError):
        router.generate("CODEX_CODER", "generate")
    assert not enterprise["calls"]


def test_no_sandbox_is_not_completion(enterprise: dict) -> None:
    runner = enterprise["runner"]
    runner.sandbox = None
    report = runner.run(
        plan=enterprise["case"]["plan"],
        approval=enterprise["envelope"],
        coder_role="CODEX_CODER",
        step_id="s1",
        prompt="patch",
        verification=RunCommandInput(argv=["pytest", "-q"]),
    )
    assert report.status == "SKIPPED_NO_SANDBOX"
    events = json.loads(enterprise["case"]["audit_log"].read_text())["events"]
    assert events[-1]["event_type"] == "STAGE07_EXECUTION_FAILED"


def test_phase2_schemas(enterprise: dict) -> None:
    from jsonschema import Draft202012Validator

    from astra_coder.hybrid_enterprise import EnterpriseReport

    root = Path(__file__).resolve().parents[2]
    for name, model, sample in [
        ("approval-envelope", ApprovalEnvelope, enterprise["envelope"]),
        (
            "execution-report",
            EnterpriseReport,
            EnterpriseReport(authorization_id="test", status="COMPLETED", target_sha256="0" * 64),
        ),
    ]:
        schema = json.loads((root / f"docs/schemas/stage07-{name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(sample.model_dump(mode="json"))
        assert schema == model.model_json_schema()
