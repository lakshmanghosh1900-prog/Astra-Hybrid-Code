from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime

ClockFn = Callable[[], datetime]

MAX_CLOCK_SKEW_SECONDS = 300


def system_clock() -> datetime:
    return datetime.now(UTC)


def test_clock_enabled() -> bool:
    return os.environ.get("ASTRA_REA_TEST_CLOCK") == "1"


def resolve_clock(now_utc: object) -> tuple[datetime | None, str | None]:
    if now_utc is None:
        return system_clock(), None
    if not test_clock_enabled():
        return None, "Caller-supplied now_utc is not permitted"
    if not isinstance(now_utc, datetime):
        return None, "now_utc must be a datetime"
    if now_utc.tzinfo is None or now_utc.utcoffset() is None:
        return None, "now_utc must be timezone-aware"
    return now_utc.astimezone(UTC), None


def within_skew(observed: datetime, reference: datetime) -> bool:
    return abs((observed - reference).total_seconds()) <= MAX_CLOCK_SKEW_SECONDS
