from astra_coder.config import load_settings


def test_settings_are_loaded_from_environment_only() -> None:
    settings = load_settings({"ASTRA_BIND_PORT": "9123", "ASTRA_LOG_LEVEL": "debug"})
    assert settings.bind_port == 9123
    assert settings.log_level == "DEBUG"
    assert settings.openai_api_key is None


def test_invalid_port_is_rejected() -> None:
    try:
        load_settings({"ASTRA_BIND_PORT": "0"})
    except ValueError as exc:
        assert "between 1 and 65535" in str(exc)
    else:
        raise AssertionError("invalid port was accepted")


def test_settings_repr_does_not_expose_provider_key() -> None:
    settings = load_settings({"ASTRA_OPENAI_API_KEY": "not-for-logs"})
    assert "not-for-logs" not in repr(settings)
