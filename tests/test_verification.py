from collections.abc import Sequence
from pathlib import Path

import pytest

from astra_coder.verification import (
    GateName,
    GateSpec,
    GateStatus,
    ProcessResult,
    VerificationEngine,
    VerificationIncomplete,
)


class FakeRunner:
    def __init__(self, results: list[ProcessResult]) -> None:
        self.results = results
        self.calls: list[tuple[tuple[str, ...], Path]] = []

    def run(self, argv: Sequence[str], cwd: Path, timeout_seconds: float) -> ProcessResult:
        del timeout_seconds
        self.calls.append((tuple(argv), cwd))
        return self.results.pop(0)


def gates() -> tuple[GateSpec, ...]:
    return tuple(GateSpec(name=name, argv=(name.value,)) for name in GateName)


def test_all_gates_pass_and_have_evidence_hashes(tmp_path: Path) -> None:
    runner = FakeRunner(
        [ProcessResult(exit_code=0, stdout=f"{name.value} ok") for name in GateName]
    )
    summary = VerificationEngine(runner, gates()).run(tmp_path)
    assert summary.passed
    assert len(summary.evidence_hash) == 64
    assert all(gate.status is GateStatus.PASSED for gate in summary.gates)
    VerificationEngine(runner, gates()).require_success(summary)


def test_failed_gate_prevents_false_success(tmp_path: Path) -> None:
    results = [ProcessResult(exit_code=0) for _ in GateName]
    results[1] = ProcessResult(exit_code=1, stderr="lint error")
    runner = FakeRunner(results)
    summary = VerificationEngine(runner, gates()).run(tmp_path)
    assert not summary.passed
    assert summary.gates[1].status is GateStatus.FAILED
    assert "lint error" in summary.gates[1].findings
    with pytest.raises(VerificationIncomplete):
        VerificationEngine(runner, gates()).require_success(summary)


def test_unavailable_and_timeout_are_not_passes(tmp_path: Path) -> None:
    results = [ProcessResult(exit_code=0) for _ in GateName]
    results[2] = ProcessResult(unavailable=True)
    results[3] = ProcessResult(timed_out=True)
    summary = VerificationEngine(FakeRunner(results), gates()).run(tmp_path)
    assert summary.gates[2].status is GateStatus.UNAVAILABLE
    assert summary.gates[3].status is GateStatus.TIMED_OUT
    assert not summary.passed


def test_default_runner_fails_closed(tmp_path: Path) -> None:
    summary = VerificationEngine(gates=gates()).run(tmp_path)
    assert not summary.passed
    assert all(gate.status is GateStatus.UNAVAILABLE for gate in summary.gates)
