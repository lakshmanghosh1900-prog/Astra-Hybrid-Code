"""Deterministic 70-case benchmark harness with explicit evaluator provenance."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .runtime import RiskTier

CATEGORIES = (
    "small_edit",
    "bug_fix",
    "multi_file",
    "repair",
    "security",
    "adversarial",
    "policy",
    "context",
    "provider",
    "recovery",
)


class BenchmarkTask(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_id: str
    category: str
    prompt: str
    risk: RiskTier


class BenchmarkResult(BaseModel):
    task_id: str
    category: str
    success: bool
    tokens: int = Field(default=0, ge=0)
    repairs: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0)
    failure_class: str | None = None


class BenchmarkReport(BaseModel):
    mode: str
    generated_at: datetime
    total: int
    verified_successes: int
    false_successes: int
    total_tokens: int
    total_repairs: int
    by_category: dict[str, dict[str, int]]
    results: tuple[BenchmarkResult, ...]

    @property
    def success_rate(self) -> float:
        return self.verified_successes / self.total if self.total else 0.0


Evaluator = Callable[[BenchmarkTask], BenchmarkResult]


def build_tasks() -> tuple[BenchmarkTask, ...]:
    tasks: list[BenchmarkTask] = []
    for category in CATEGORIES:
        for number in range(1, 8):
            risk = RiskTier.T2 if category in {"security", "policy", "adversarial"} else RiskTier.T1
            tasks.append(
                BenchmarkTask(
                    task_id=f"{category}-{number:02d}",
                    category=category,
                    prompt=f"[{category}] deterministic fixture task {number}",
                    risk=risk,
                )
            )
    return tuple(tasks)


def contract_smoke_evaluator(task: BenchmarkTask) -> BenchmarkResult:
    """Verify harness plumbing without claiming model/code-solving capability."""
    return BenchmarkResult(
        task_id=task.task_id, category=task.category, success=True, tokens=0, repairs=0
    )


def no_agent_evaluator(task: BenchmarkTask) -> BenchmarkResult:
    """Honest baseline for a checkout without an integrated autonomous executor."""
    return BenchmarkResult(
        task_id=task.task_id,
        category=task.category,
        success=False,
        failure_class="agent_executor_not_integrated",
    )


class BenchmarkHarness:
    def __init__(self, tasks: tuple[BenchmarkTask, ...] | None = None) -> None:
        self.tasks = tasks or build_tasks()
        if len(self.tasks) != 70:
            raise ValueError("the internal suite must contain exactly 70 tasks")

    def run(self, evaluator: Evaluator, mode: str) -> BenchmarkReport:
        results = tuple(evaluator(task) for task in self.tasks)
        if {result.task_id for result in results} != {task.task_id for task in self.tasks}:
            raise ValueError("evaluator returned an unknown or duplicate task id")
        by_category: dict[str, dict[str, int]] = {}
        for category in CATEGORIES:
            category_results = [result for result in results if result.category == category]
            by_category[category] = {
                "total": len(category_results),
                "successes": sum(result.success for result in category_results),
                "failures": sum(not result.success for result in category_results),
            }
        return BenchmarkReport(
            mode=mode,
            generated_at=datetime.now(UTC),
            total=len(results),
            verified_successes=sum(result.success for result in results),
            false_successes=0,
            total_tokens=sum(result.tokens for result in results),
            total_repairs=sum(result.repairs for result in results),
            by_category=by_category,
            results=results,
        )


def write_report(report: BenchmarkReport, json_path: str | Path, markdown_path: str | Path) -> None:
    Path(json_path).write_text(report.model_dump_json(indent=2), encoding="utf-8")
    lines = [
        f"# Benchmark Report — {report.mode}",
        "",
        "> This report is a deterministic harness/contract smoke run.",
        "> It is not a model quality or SWE-bench score.",
        "",
        f"- Total tasks: {report.total}",
        f"- Verified successes: {report.verified_successes}",
        f"- Success rate: {report.success_rate:.1%}",
        f"- Tokens: {report.total_tokens}",
        f"- Repairs: {report.total_repairs}",
        "",
        "| Category | Total | Successes | Failures |",
        "|---|---:|---:|---:|",
    ]
    lines.extend(
        f"| {category} | {values['total']} | {values['successes']} | {values['failures']} |"
        for category, values in report.by_category.items()
    )
    Path(markdown_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    report = BenchmarkHarness().run(contract_smoke_evaluator, "contract_smoke")
    write_report(
        report,
        root / "docs/benchmarks/stage-15-contract-smoke.json",
        root / "docs/benchmarks/stage-15-contract-smoke.md",
    )
    baseline = BenchmarkHarness().run(no_agent_evaluator, "agent_baseline_not_integrated")
    write_report(
        baseline,
        root / "docs/benchmarks/stage-15-agent-baseline.json",
        root / "docs/benchmarks/stage-15-agent-baseline.md",
    )


if __name__ == "__main__":
    main()
