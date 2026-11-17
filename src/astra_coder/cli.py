"""Typer CLI for task intake and control."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

import typer

from . import __version__
from .config import load_settings
from .free_cascade import build_free_cascade_gateway
from .persistence import AuditLog, StateStore
from .policy import Actor, PolicyConfig, PolicyEngine
from .runtime import RiskTier, Task
from .service import ServiceError, SubmitRequest, TaskService

app = typer.Typer(help="Evidence-first autonomous coding agent.")


def service() -> TaskService:
    settings = load_settings()
    store = StateStore(settings.database_url)
    audit = AuditLog(store)
    store.recover_after_restart(audit)
    policy = PolicyEngine(PolicyConfig(repo_root=settings.repo_root))
    return TaskService(
        store,
        policy,
        audit,
        gateway=build_free_cascade_gateway(settings),
    )


def actor(role: str | None = None) -> Actor:
    selected_role = role or os.environ.get("ASTRA_ACTOR_ROLE") or "developer"
    return Actor(
        actor_id=os.environ.get("ASTRA_ACTOR_ID", "local-user"),
        role=selected_role,
    )


def output(value: Task, as_json: bool) -> None:
    if as_json:
        typer.echo(value.model_dump_json())
    else:
        typer.echo(f"{value.id} {value.state.value} risk={value.risk.value}")


@app.command()
def doctor() -> None:
    """Print safe local configuration diagnostics."""
    settings = load_settings()
    typer.echo(f"astra {__version__}")
    typer.echo(f"bind={settings.bind_host}:{settings.bind_port}")
    typer.echo(f"database={settings.database_url}")
    typer.echo(f"default_model={settings.default_model}")
    typer.echo(f"remote_provider={'configured' if settings.openai_api_key else 'not configured'}")


@app.command()
def submit(
    repo: Path = typer.Option(..., "--repo", exists=True, file_okay=False),  # noqa: B008
    task: str = typer.Option(..., "--task"),
    risk: RiskTier = typer.Option(RiskTier.T1, "--risk"),  # noqa: B008
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Submit a bounded task to the local control plane."""
    try:
        result = service().submit(
            actor(), SubmitRequest(prompt=task, repo_path=str(repo), risk=risk)
        )
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc
    output(result, as_json)


@app.command()
def status(task_id: UUID, as_json: bool = typer.Option(False, "--json")) -> None:
    """Show durable task state."""
    try:
        output(service().get(actor(), task_id), as_json)
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command(name="diff")
def show_diff(task_id: UUID) -> None:
    """Show task diff/status evidence."""
    try:
        typer.echo(service().diff(actor(), task_id))
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def approve(task_id: UUID) -> None:
    """Approve an approval-gated task."""
    try:
        output(service().approve(actor(), task_id), False)
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def execute(task_id: UUID) -> None:
    """Authorize and queue a task for the dedicated worker."""
    try:
        output(service().request_execution(actor(), task_id), False)
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def deny(task_id: UUID, reason: str = typer.Option(..., "--reason")) -> None:
    """Deny an approval-gated task."""
    try:
        output(service().deny(actor(), task_id, reason), False)
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def cancel(task_id: UUID) -> None:
    """Cancel a task without touching repository files."""
    try:
        output(service().cancel(actor(), task_id), False)
    except ServiceError as exc:
        raise typer.BadParameter(str(exc)) from exc


if __name__ == "__main__":
    app()
