from pathlib import Path

from astra_coder.benchmark import (
    CATEGORIES,
    BenchmarkHarness,
    build_tasks,
    contract_smoke_evaluator,
    no_agent_evaluator,
    write_report,
)


def test_internal_suite_has_70_tasks_in_ten_categories() -> None:
    tasks = build_tasks()
    assert len(tasks) == 70
    assert {task.category for task in tasks} == set(CATEGORIES)
    assert len({task.task_id for task in tasks}) == 70


def test_contract_smoke_report_is_complete(tmp_path: Path) -> None:
    report = BenchmarkHarness().run(contract_smoke_evaluator, "contract_smoke")
    assert report.total == 70
    assert report.verified_successes == 70
    write_report(report, tmp_path / "report.json", tmp_path / "report.md")
    assert "contract_smoke" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_missing_agent_is_not_reported_as_success() -> None:
    report = BenchmarkHarness().run(no_agent_evaluator, "agent_baseline")
    assert report.verified_successes == 0
    assert all(result.failure_class == "agent_executor_not_integrated" for result in report.results)
