"""Minimal health API; task routes arrive in later stages."""

from fastapi import FastAPI

from . import __version__

app = FastAPI(title="Astra Coder", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
