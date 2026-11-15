"""Environment-only application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DATABASE_URL = "sqlite:///./astra.db"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8000
DEFAULT_MODEL = "ollama/qwen2.5-coder"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_AUTH_MODE = "required"
DEFAULT_LOCAL_ACTOR_ID = "local-user"
DEFAULT_LOCAL_ROLE = "developer"
AUTH_MODES = frozenset({"required", "local", "tokens"})


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = DEFAULT_DATABASE_URL
    repo_root: Path | None = None
    log_level: str = DEFAULT_LOG_LEVEL
    bind_host: str = DEFAULT_BIND_HOST
    bind_port: int = DEFAULT_BIND_PORT
    default_model: str = DEFAULT_MODEL
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    openai_base_url: str | None = None
    openai_api_key: str | None = field(default=None, repr=False)
    auth_mode: str = DEFAULT_AUTH_MODE
    auth_tokens: str | None = field(default=None, repr=False)
    local_actor_id: str = DEFAULT_LOCAL_ACTOR_ID
    local_actor_role: str = DEFAULT_LOCAL_ROLE


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
    repo_root = values.get("ASTRA_REPO_ROOT")
    auth_mode = values.get("ASTRA_AUTH_MODE", DEFAULT_AUTH_MODE).strip().lower()
    if auth_mode not in AUTH_MODES:
        raise ValueError("ASTRA_AUTH_MODE must be required, local, or tokens")
    return Settings(
        database_url=values.get("ASTRA_DATABASE_URL", DEFAULT_DATABASE_URL),
        repo_root=Path(repo_root).expanduser() if repo_root else None,
        log_level=values.get("ASTRA_LOG_LEVEL", DEFAULT_LOG_LEVEL).upper(),
        bind_host=values.get("ASTRA_BIND_HOST", DEFAULT_BIND_HOST),
        bind_port=port,
        default_model=values.get("ASTRA_DEFAULT_MODEL", DEFAULT_MODEL),
        ollama_base_url=values.get("ASTRA_OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL),
        openai_base_url=values.get("ASTRA_OPENAI_BASE_URL"),
        openai_api_key=values.get("ASTRA_OPENAI_API_KEY"),
        auth_mode=auth_mode,
        auth_tokens=values.get("ASTRA_AUTH_TOKENS"),
        local_actor_id=values.get("ASTRA_LOCAL_ACTOR_ID", DEFAULT_LOCAL_ACTOR_ID),
        local_actor_role=values.get("ASTRA_LOCAL_ROLE", DEFAULT_LOCAL_ROLE),
    )
