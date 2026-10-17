"""Initial CLI surface."""

from __future__ import annotations

import typer

from . import __version__
from .config import load_settings

app = typer.Typer(help="Evidence-first autonomous coding agent.")


@app.command()
def doctor() -> None:
    """Print safe local configuration diagnostics."""
    settings = load_settings()
    typer.echo(f"astra {__version__}")
    typer.echo(f"bind={settings.bind_host}:{settings.bind_port}")
    typer.echo(f"database={settings.database_url}")
    typer.echo(f"default_model={settings.default_model}")
    typer.echo(f"remote_provider={'configured' if settings.openai_api_key else 'not configured'}")


if __name__ == "__main__":
    app()
