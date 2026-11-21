import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from astra_coder import hybrid_skill as skill
from astra_coder.hybrid_roles import HybridRoleAdapter


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "sample.txt").write_bytes(b"old\n")
    plan = skill.ExecutionPlan(
        plan_id="p1",
        role="GPT_BRAINING_PLANNER",
        read_only=True,
        requires_rea_gate=True,
        risk_checks=["bounded"],
        allowed_target_paths=["sample.txt"],
        excluded_paths=[],
        steps=[skill.Step(step_id="s1", description="edit", target_path="sample.txt")],
    )
    diff = "--- a/sample.txt\n+++ b/sample.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    request = skill.PatchRequest(
        role="CODEX_CODER",
        plan_id="p1",
        plan_sha256=skill.plan_digest(plan),
        step_id="s1",
        diff_sha256=hashlib.sha256(diff.encode()).hexdigest(),
        diff=diff,
        rea_skill_binding=skill.SkillBinding(skill=skill.SKILL, gate="rea-gate", fail_closed=True),
    )
    (root / "authorization.json").write_text(
        json.dumps(
            {
                "bundle_sha256": skill.execution_bundle_digest(plan, request),
                "authorization": {"authorization_id": "isolated-mock-test"},
            }
        )
    )
    monkeypatch.setattr(skill, "require_stage05b_execution", Mock(return_value=Mock(allowed=True)))
    return dict(
        repo_root=root,
        plan=plan,
        request=request,
        approved_plan_sha256=skill.plan_digest(plan),
        actor_id="executor",
        approver_id="human",
        audit_log=tmp_path / "audit.json",
    )


def test_allowed(case: dict) -> None:
    skill.execute_patch(**case)
    assert (case["repo_root"] / "sample.txt").read_bytes() == b"new\n"
    events = json.loads(case["audit_log"].read_text())["events"]
    assert skill.append_audit_event is not None
    assert events[0]["event_type"] == "STAGE07_PATCH_INTENT"


@pytest.mark.parametrize("failure", ["approval", "hash", "gate", "audit", "diff", "step"])
def test_denies(case: dict, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    if failure == "approval":
        case["approved_plan_sha256"] = "0" * 64
    elif failure == "hash":
        case["request"] = case["request"].model_copy(update={"plan_sha256": "0" * 64})
    elif failure == "gate":
        monkeypatch.setattr(
            skill,
            "require_stage05b_execution",
            Mock(return_value=Mock(allowed=False, blocking_reasons=["denied"])),
        )
    elif failure == "audit":
        monkeypatch.setattr(skill, "append_audit_event", Mock(side_effect=OSError("disk")))
    elif failure == "diff":
        case["request"] = case["request"].model_copy(update={"diff_sha256": "0" * 64})
    else:
        case["request"] = case["request"].model_copy(update={"step_id": "unknown"})
    with pytest.raises((ValueError, PermissionError, OSError)):
        skill.execute_patch(**case)
    assert (case["repo_root"] / "sample.txt").read_bytes() == b"old\n"


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "C:\\astramind-dev\\x",
        "authorization.json",
        "src/astra_coder/rea/gate.py",
        "sample.txt",
    ],
)
def test_paths(case: dict, name: str) -> None:
    plan = case["plan"].model_copy(
        update={
            "allowed_target_paths": [name],
            "excluded_paths": ["sample.txt"],
            "steps": [skill.Step(step_id="s1", description="edit", target_path=name)],
        }
    )
    case["plan"] = plan
    case["approved_plan_sha256"] = skill.plan_digest(plan)
    case["request"] = case["request"].model_copy(update={"plan_sha256": skill.plan_digest(plan)})
    with pytest.raises(ValueError):
        skill.execute_patch(**case)


def test_role_adapter(case: dict) -> None:
    adapter = HybridRoleAdapter(
        lambda _: case["plan"].model_dump_json(), lambda _: case["request"].model_dump_json()
    )
    assert adapter.plan("plan") == case["plan"]
    assert adapter.patch("patch", "CODEX_CODER") == case["request"]
    with pytest.raises(ValueError):
        adapter.patch("patch", "CLAUDE_CODER")


@pytest.mark.parametrize(
    ("source", "body", "expected"),
    [
        ("a\nb\n", "@@ -1,1 +0,0 @@\n-a\n", "b\n"),
        ("a\n", "@@ -1,0 +2,1 @@\n+b\n", "a\nb\n"),
        ("a\n", "@@ -1 +1 @@\n-a\n+b\n", "b\n"),
        ("a\n", "@@ -0,0 +1,1 @@\n+b\n", "b\na\n"),
        ("a\nb\n", "@@ -2,1 +1,0 @@\n-b\n", "a\n"),
        ("a\nb\nc\n", "@@ -1 +1 @@\n-a\n+x\n@@ -3 +3 @@\n-c\n+z\n", "x\nb\nz\n"),
        ("a\nb\n", "@@ -1 +1 @@\n-a\n+x\n@@ -2 +2 @@\n-b\n+y\n", "x\ny\n"),
        ("a\nb\nc\n", "@@ -1,3 +1,3 @@\n a\n-b\n+x\n c\n", "a\nx\nc\n"),
        ("a\r\n", "@@ -1 +1 @@\r\n-a\r\n+b\r\n", "b\r\n"),
        ("a", "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n", "b\n"),
        ("a\n", "@@ -1 +1 @@\n-a\n+b\n\\ No newline at end of file\n", "b"),
        (
            "a",
            "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n",
            "b",
        ),
        ("a\nb", "@@ -1 +1 @@\n-a\n+x\n", "x\nb"),
    ],
)
def test_parser_exact(source: str, body: str, expected: str) -> None:
    framing = "\r\n" if "\r\n" in body else "\n"
    diff = f"--- a/f{framing}+++ b/f{framing}" + body
    assert skill.patched_text(source, diff, "f").encode() == expected.encode()


@pytest.mark.parametrize(
    "body",
    [
        "",
        "@@ -3 +1 @@\n-a\n+b\n",
        "@@ -1 +3 @@\n-a\n+b\n",
        "@@ -0 +1 @@\n-a\n+b\n",
        "@@ -1,2 +1 @@\n-a\n+b\n",
        "@@ -1 +1,2 @@\n-a\n+b\n",
        "@@ -1 +1 @@\n-z\n+b\n",
        "@@ -1 +1 @@\n?a\n",
        "garbage\n",
        "GIT binary patch\n",
        "rename from f\n",
        "@@ -1 +1 @@\n-a\n+b\n@@ -1 +1 @@\n-a\n+c\n",
        "@@ -1 +1 @@\n-a\n+b",
        "@@ -1 +1 @@\n-a\n+b\n--- a/g\n+++ b/g\n",
        "\\ No newline at end of file\n",
    ],
)
def test_parser_rejects(body: str) -> None:
    with pytest.raises(ValueError):
        skill.patched_text("a\n", "--- a/f\n+++ b/f\n" + body, "f")


@pytest.mark.parametrize(
    "headers",
    [
        "",
        "--- a/f\n",
        "--- a/g\n+++ b/g\n",
        "--- /dev/null\n+++ b/f\n",
        "--- a/f\n+++ /dev/null\n",
        "diff --git a/f b/f\n--- a/f\n+++ b/f\n",
    ],
)
def test_parser_headers(headers: str) -> None:
    with pytest.raises(ValueError):
        skill.patched_text("a\n", headers + "@@ -1 +1 @@\n-a\n+b\n", "f")


@pytest.fixture
def real_case(
    case: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> dict:
    """Reuse real REA fixture builders; generated private key stays in memory."""
    import importlib.util

    from astra_coder.rea.enforcement import require_stage05b_execution

    spec = importlib.util.spec_from_file_location(
        "stage07_existing_rea_fixtures", Path(__file__).parent / "rea/test_rea_enforcement.py"
    )
    assert spec is not None and spec.loader is not None
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    monkeypatch.setenv("ASTRA_REA_TRUSTED_KEYS_PATH", str(tmp_path / "keys.json"))
    if getattr(request, "param", None) == "malformed":
        diff = "--- a/sample.txt\n+++ b/sample.txt\n@@ -1 +1 @@\n-wrong\n+new\n"
        case["request"] = case["request"].model_copy(
            update={
                "diff": diff,
                "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
            }
        )
    bundle = skill.execution_bundle_digest(case["plan"], case["request"])
    root = fixtures._build_gate_fixture(
        tmp_path,
        repo_name="real-repo",
        auth_mutator=lambda auth: auth.update(bundle_sha256=bundle),
    )
    (root / "sample.txt").write_bytes(b"old\n")
    fixtures._edit_manifest(
        root,
        lambda manifest: manifest.update(
            bundle_sha256=bundle,
            inputs=[
                {
                    "source_path_or_uri": "sample.txt",
                    "sha256": hashlib.sha256(b"old\n").hexdigest(),
                }
            ],
        ),
    )
    fixtures._write_trusted_approver(
        tmp_path,
        monkeypatch,
        approver_id="human",
        binding_root=root,
        bundle_sha256=bundle,
    )
    monkeypatch.setattr(skill, "require_stage05b_execution", require_stage05b_execution)
    case["repo_root"] = root
    return case


def test_real_execution(real_case: dict) -> None:
    from astra_coder.rea import enforce_rea_gate, verify_event_chain

    result = enforce_rea_gate(
        repo_root=real_case["repo_root"], actor_id="executor", role="EXECUTOR", approver_id="human"
    )
    assert result.allowed, result.blocking_reasons
    assert all(result.checks.values())
    skill.execute_patch(**real_case)
    assert (real_case["repo_root"] / "sample.txt").read_bytes() == b"new\n"
    log = json.loads(real_case["audit_log"].read_text())
    events = verify_event_chain(log["events"])
    assert [e["event_type"] for e in events] == ["STAGE_05B_GATE_EVALUATED", "STAGE07_PATCH_INTENT"]
    assert events[-1]["authorization_id"] == "auth-05b-20261119-01"


@pytest.mark.parametrize("real_case", ["malformed"], indirect=True)
def test_real_signed_patch_context_denial(real_case: dict) -> None:
    with pytest.raises(ValueError, match="context mismatch"):
        skill.execute_patch(**real_case)
    assert (real_case["repo_root"] / "sample.txt").read_bytes() == b"old\n"
    events = json.loads(real_case["audit_log"].read_text())["events"]
    assert [e["event_type"] for e in events] == ["STAGE_05B_GATE_EVALUATED"]


@pytest.mark.parametrize(
    "failure",
    [
        "unknown-role",
        "agent-role",
        "missing-auth",
        "signature",
        "expired",
        "r1",
        "r2",
        "r3",
        "approver",
        "self",
        "approval",
        "patch",
        "bundle",
        "unauthorized",
        "traversal",
        "protected",
        "audit",
        "rejected-patch",
        "replay",
    ],
)
def test_real_denials(real_case: dict, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    import os

    root = real_case["repo_root"]
    if failure in {"unknown-role", "agent-role"}:
        real_case["execution_role"] = "UNKNOWN" if failure == "unknown-role" else "AGENT"
    elif failure == "missing-auth":
        (root / "authorization.json").unlink()
    elif failure in {"signature", "expired", "r1"}:
        path = root / "authorization.json"
        auth = json.loads(path.read_text())
        if failure == "signature":
            auth["signature"]["signature_base64"] = "invalid"
        elif failure == "expired":
            auth["authorization"]["expires_at_utc"] = "2000-01-01T00:00:00Z"
        else:
            auth["artifact_status"] = "DRAFT"
        path.write_text(json.dumps(auth))
    elif failure == "r2":
        path = root / "license-check.json"
        obj = json.loads(path.read_text())
        obj["result"]["status"] = "FAIL"
        path.write_text(json.dumps(obj))
    elif failure == "r3":
        path = root / "rea-input-manifest.json"
        obj = json.loads(path.read_text())
        obj["inputs"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(obj))
    elif failure == "approver":
        Path(os.environ["ASTRA_REA_APPROVER_REGISTRY_PATH"]).write_text('{"approvers":{}}')
    elif failure == "self":
        real_case["self_certified"] = True
    elif failure == "approval":
        real_case["approved_plan_sha256"] = "0" * 64
    elif failure == "patch":
        real_case["request"] = real_case["request"].model_copy(update={"diff_sha256": "0" * 64})
    elif failure == "bundle":
        plan = real_case["plan"].model_copy(update={"risk_checks": ["changed"]})
        real_case["plan"] = plan
        real_case["approved_plan_sha256"] = skill.plan_digest(plan)
        real_case["request"] = real_case["request"].model_copy(
            update={"plan_sha256": skill.plan_digest(plan)}
        )
    elif failure in {"unauthorized", "traversal", "protected"}:
        name = {
            "unauthorized": "other.txt",
            "traversal": "../escape",
            "protected": "src/astra_coder/rea/gate.py",
        }[failure]
        plan = real_case["plan"].model_copy(
            update={"steps": [skill.Step(step_id="s1", description="edit", target_path=name)]}
        )
        real_case["plan"] = plan
        real_case["approved_plan_sha256"] = skill.plan_digest(plan)
        real_case["request"] = real_case["request"].model_copy(
            update={"plan_sha256": skill.plan_digest(plan)}
        )
    elif failure == "audit":
        monkeypatch.setattr(skill, "append_audit_event", Mock(side_effect=OSError("disk")))
    elif failure == "rejected-patch":
        # Malformed diff invalidates the signed bundle before parser execution.
        real_case["request"] = real_case["request"].model_copy(update={"diff": "invalid"})
    elif failure == "replay":
        skill.execute_patch(**real_case)
        # Restore fixture bytes to prove consumed intent, independently of R3.
        (root / "sample.txt").write_bytes(b"old\n")
    with pytest.raises((ValueError, PermissionError, OSError)):
        skill.execute_patch(**real_case)
    assert (root / "sample.txt").read_bytes() == b"old\n"


def test_real_concurrent_execution(real_case: dict) -> None:
    from concurrent.futures import ThreadPoolExecutor

    def run() -> bool:
        try:
            skill.execute_patch(**real_case)
            return True
        except PermissionError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sorted(results) == [False, True]
    assert (real_case["repo_root"] / "sample.txt").read_bytes() == b"new\n"


def test_schemas(case: dict) -> None:
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[2]
    for name, obj in [("execution-plan", case["plan"]), ("coding-patch-request", case["request"])]:
        schema = json.loads((root / f"docs/schemas/stage07-{name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(obj.model_dump())
        with pytest.raises(ValueError):
            type(obj).model_validate_json(json.dumps({**obj.model_dump(), "unknown": True}))
