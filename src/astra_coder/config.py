"""Environment-only application configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
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
DEFAULT_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_FREE_CASCADE_ORDER = ("ollama", "nvidia_nim", "openrouter", "groq")
DEFAULT_REMOTE_TIMEOUT_SECONDS = 60.0
DEFAULT_RETRY_BACKOFF_SECONDS = 0.5
DEFAULT_NETWORK_APPROVAL_TTL_SECONDS = 900.0
DEFAULT_WORKER_ROLE = "developer"
DEFAULT_WORKER_PLAN_MODE = "llm"
CASCADE_PROVIDERS = frozenset(DEFAULT_FREE_CASCADE_ORDER)
WORKER_ROLES = frozenset({"developer", "reviewer", "operator", "admin"})
WORKER_PLAN_MODES = frozenset({"llm", "structured"})


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
    planner_model: str | None = None
    codex_model: str | None = None
    claude_model: str | None = None
    claude_base_url: str | None = None
    claude_api_key: str | None = field(default=None, repr=False)
    nvidia_base_url: str = DEFAULT_NVIDIA_BASE_URL
    nvidia_api_key: str | None = field(default=None, repr=False)
    openrouter_base_url: str = DEFAULT_OPENROUTER_BASE_URL
    openrouter_api_key: str | None = field(default=None, repr=False)
    groq_base_url: str = DEFAULT_GROQ_BASE_URL
    groq_api_key: str | None = field(default=None, repr=False)
    free_cascade_order: tuple[str, ...] = DEFAULT_FREE_CASCADE_ORDER
    allow_paid_remote: bool = False
    allow_remote_t4: bool = False
    remote_timeout_seconds: float = DEFAULT_REMOTE_TIMEOUT_SECONDS
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
    network_approval_ttl_seconds: float = DEFAULT_NETWORK_APPROVAL_TTL_SECONDS
    worker_role: str = DEFAULT_WORKER_ROLE
    worker_plan_mode: str = DEFAULT_WORKER_PLAN_MODE
    auth_mode: str = DEFAULT_AUTH_MODE
    auth_tokens: str | None = field(default=None, repr=False)
    local_actor_id: str = DEFAULT_LOCAL_ACTOR_ID
    local_actor_role: str = DEFAULT_LOCAL_ROLE

    def secret_values(self) -> tuple[str, ...]:
        """Return configured credential values for redaction, never for logging."""
        values = (
            self.openai_api_key,
            self.claude_api_key,
            self.nvidia_api_key,
            self.openrouter_api_key,
            self.groq_api_key,
            self.auth_tokens,
        )
        return tuple(value for value in values if value)


def _boolean(values: Mapping[str, str], name: str, default: bool) -> bool:
    raw = values.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _number(values: Mapping[str, str], name: str, default: float, minimum: float) -> float:
    raw = values.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _cascade_order(values: Mapping[str, str]) -> tuple[str, ...]:
    raw = values.get("ASTRA_FREE_CASCADE_ORDER")
    if raw is None:
        return DEFAULT_FREE_CASCADE_ORDER
    if not raw.strip():
        raise ValueError("ASTRA_FREE_CASCADE_ORDER must not be empty")
    parts = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not parts:
        raise ValueError("ASTRA_FREE_CASCADE_ORDER must not be empty")
    if len(set(parts)) != len(parts):
        raise ValueError("ASTRA_FREE_CASCADE_ORDER must not contain duplicate providers")
    unknown = sorted(set(parts) - CASCADE_PROVIDERS)
    if unknown:
        raise ValueError(
            "ASTRA_FREE_CASCADE_ORDER contains unknown providers: " + ", ".join(unknown)
        )
    return parts


def load_settings(environ: dict[str, str] | None = None) -> Settings:
    """Load non-secret defaults and optional values from environment variables only."""
    values: Mapping[str, str] = os.environ if environ is None else environ
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
    worker_role = values.get("ASTRA_WORKER_ROLE", DEFAULT_WORKER_ROLE).strip().lower()
    if worker_role not in WORKER_ROLES:
        raise ValueError("ASTRA_WORKER_ROLE must be developer, reviewer, operator, or admin")
    plan_mode = values.get("ASTRA_WORKER_PLAN_MODE", DEFAULT_WORKER_PLAN_MODE).strip().lower()
    if plan_mode not in WORKER_PLAN_MODES:
        raise ValueError("ASTRA_WORKER_PLAN_MODE must be llm or structured")
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
        planner_model=values.get("ASTRA_PLANNER_MODEL"),
        codex_model=values.get("ASTRA_CODEX_MODEL"),
        claude_model=values.get("ASTRA_CLAUDE_MODEL"),
        claude_base_url=values.get("ASTRA_CLAUDE_BASE_URL"),
        claude_api_key=values.get("ASTRA_CLAUDE_API_KEY"),
        nvidia_base_url=values.get("ASTRA_NVIDIA_BASE_URL", DEFAULT_NVIDIA_BASE_URL),
        nvidia_api_key=values.get("ASTRA_NVIDIA_API_KEY"),
        openrouter_base_url=values.get("ASTRA_OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL),
        openrouter_api_key=values.get("ASTRA_OPENROUTER_API_KEY"),
        groq_base_url=values.get("ASTRA_GROQ_BASE_URL", DEFAULT_GROQ_BASE_URL),
        groq_api_key=values.get("ASTRA_GROQ_API_KEY"),
        free_cascade_order=_cascade_order(values),
        allow_paid_remote=_boolean(values, "ASTRA_ALLOW_PAID_REMOTE", False),
        allow_remote_t4=_boolean(values, "ASTRA_ALLOW_REMOTE_T4", False),
        remote_timeout_seconds=_number(
            values, "ASTRA_REMOTE_TIMEOUT_SECONDS", DEFAULT_REMOTE_TIMEOUT_SECONDS, 0.001
        ),
        retry_backoff_seconds=_number(
            values, "ASTRA_RETRY_BACKOFF_SECONDS", DEFAULT_RETRY_BACKOFF_SECONDS, 0.0
        ),
        network_approval_ttl_seconds=_number(
            values,
            "ASTRA_NETWORK_APPROVAL_TTL_SECONDS",
            DEFAULT_NETWORK_APPROVAL_TTL_SECONDS,
            0.001,
        ),
        worker_role=worker_role,
        worker_plan_mode=plan_mode,
        auth_mode=auth_mode,
        auth_tokens=values.get("ASTRA_AUTH_TOKENS"),
        local_actor_id=values.get("ASTRA_LOCAL_ACTOR_ID", DEFAULT_LOCAL_ACTOR_ID),
        local_actor_role=values.get("ASTRA_LOCAL_ROLE", DEFAULT_LOCAL_ROLE),
    )
