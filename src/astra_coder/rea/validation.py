from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from astra_coder.license.verify_digest import parse_sha256_hex


def is_string(value: Any) -> bool:
    return isinstance(value, str)


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def parse_aware_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def strict_sha256(value: Any) -> str | None:
    return parse_sha256_hex(value)
