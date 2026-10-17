"""Environment-only application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_DATABASE_URL = "sqlite:///./astra.db"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8000
DEFAULT_MODEL = "ollama/qwen2.5-coder"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = DEFAULT_DATABASE_URL
    log_level: str = DEFAULT_LOG_LEVEL
    bind_host: str = DEFAULT_BIND_HOST
    bind_port: int = DEFAULT_BIND_PORT
    default_model: str = DEFAULT_MODEL
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    openai_base_url: str | None = None
    openai_api_key: str | None = None


def load_settings(environ: dict[str, str] | None = None) -> Settings:
    """Load non-secret defaults and optional values from environment variables only."""
    values = os.environ if environ is None else environ
    raw_port = values.get("ASTRA_BIND_PORT", "8000")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError("ASTRA_BIND_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("ASTRA_BIND_PORT must be between 1 and 65535")
    return Settings(
        database_url=values.get("ASTRA_DATABASE_URL", DEFAULT_DATABASE_URL),
        log_level=values.get("ASTRA_LOG_LEVEL", DEFAULT_LOG_LEVEL).upper(),
        bind_host=values.get("ASTRA_BIND_HOST", DEFAULT_BIND_HOST),
        bind_port=port,
        default_model=values.get("ASTRA_DEFAULT_MODEL", DEFAULT_MODEL),
        ollama_base_url=values.get("ASTRA_OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL),
        openai_base_url=values.get("ASTRA_OPENAI_BASE_URL"),
        openai_api_key=values.get("ASTRA_OPENAI_API_KEY"),
    )
