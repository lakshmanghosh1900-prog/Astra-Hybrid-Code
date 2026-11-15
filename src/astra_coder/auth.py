"""Trusted principal resolution for API mutation routes.

Role headers are deliberately not accepted as identity.  Production deployments
should inject a resolver backed by their identity provider.  The built-in
resolver supports an explicit, environment-only token map for local or
single-process deployments without placing credentials in source control.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Protocol

from .config import Settings
from .policy import Actor


class AuthenticationError(PermissionError):
    """Raised when a request has no trusted authenticated principal."""


class PrincipalResolver(Protocol):
    def resolve(self, authorization: str | None) -> Actor: ...


class StaticPrincipalResolver:
    """Test-only/in-process resolver supplied explicitly by the application."""

    def __init__(self, principal: Actor | None = None) -> None:
        self.principal = principal

    def resolve(self, authorization: str | None) -> Actor:
        del authorization
        if self.principal is None:
            raise AuthenticationError("authentication required")
        return self.principal


class TokenPrincipalResolver:
    """Resolve bearer tokens from a server-side token map.

    The mapping is loaded by the server process from environment configuration;
    clients never choose the actor or role.  Tokens are intentionally not
    included in error messages or audit metadata.
    """

    def __init__(self, tokens: Mapping[str, Actor]) -> None:
        self._tokens = dict(tokens)

    def resolve(self, authorization: str | None) -> Actor:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationError("authentication required")
        token = authorization.removeprefix("Bearer ").strip()
        if not token or token not in self._tokens:
            raise AuthenticationError("invalid authentication credentials")
        return self._tokens[token]


class LocalEnvironmentPrincipalResolver:
    """Explicit local-development resolver using server environment only."""

    def __init__(self, actor_id: str, role: str) -> None:
        self._principal = Actor(actor_id=actor_id, role=role)

    def resolve(self, authorization: str | None) -> Actor:
        del authorization
        return self._principal


def load_principal_resolver(
    settings: Settings | Mapping[str, str] | None = None,
) -> PrincipalResolver:
    """Load an explicit server-side authentication mode.

    ``required`` is the secure default.  ``local`` is intentionally opt-in and
    takes its identity from server environment variables, never request
    headers.  ``tokens`` expects ``ASTRA_AUTH_TOKENS`` to contain a JSON object
    mapping opaque tokens to ``{"actor_id": ..., "role": ...}`` records.
    """

    if isinstance(settings, Settings):
        mode = settings.auth_mode
        raw_tokens = settings.auth_tokens or ""
        local_actor_id = settings.local_actor_id
        local_role = settings.local_actor_role
    else:
        values = os.environ if settings is None else settings
        mode = values.get("ASTRA_AUTH_MODE", "required").strip().lower()
        raw_tokens = values.get("ASTRA_AUTH_TOKENS", "")
        local_actor_id = values.get("ASTRA_LOCAL_ACTOR_ID", "local-user")
        local_role = values.get("ASTRA_LOCAL_ROLE", "developer")
    if mode == "local":
        return LocalEnvironmentPrincipalResolver(
            actor_id=local_actor_id,
            role=local_role,
        )
    if mode == "tokens":
        try:
            records = json.loads(raw_tokens)
        except json.JSONDecodeError as exc:
            raise ValueError("ASTRA_AUTH_TOKENS must be valid JSON") from exc
        if not isinstance(records, dict) or not records:
            raise ValueError("ASTRA_AUTH_TOKENS must be a non-empty JSON object")
        tokens: dict[str, Actor] = {}
        for token, record in records.items():
            if not isinstance(token, str) or not token or not isinstance(record, dict):
                raise ValueError("ASTRA_AUTH_TOKENS contains an invalid record")
            tokens[token] = Actor.model_validate(record)
        return TokenPrincipalResolver(tokens)
    if mode == "required":
        return StaticPrincipalResolver()
    raise ValueError("ASTRA_AUTH_MODE must be required, local, or tokens")
