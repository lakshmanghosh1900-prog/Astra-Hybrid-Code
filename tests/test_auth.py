import json

import pytest

from astra_coder.auth import AuthenticationError, load_principal_resolver
from astra_coder.config import load_settings
from astra_coder.policy import Actor


def test_settings_wire_server_side_token_resolver() -> None:
    settings = load_settings(
        {
            "ASTRA_AUTH_MODE": "tokens",
            "ASTRA_AUTH_TOKENS": json.dumps(
                {"developer-token": {"actor_id": "dev", "role": "developer"}}
            ),
        }
    )
    resolver = load_principal_resolver(settings)
    assert resolver.resolve("Bearer developer-token") == Actor(actor_id="dev", role="developer")
    with pytest.raises(AuthenticationError):
        resolver.resolve("Bearer unknown-token")


def test_required_auth_is_the_default() -> None:
    resolver = load_principal_resolver(load_settings({}))
    with pytest.raises(AuthenticationError):
        resolver.resolve(None)
