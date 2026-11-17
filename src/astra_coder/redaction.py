"""Secret redaction for content that may leave the host.

PromptInjectionGuard screens repository text for injection instructions, but it
does not detect credentials. This module is the last local gate before task
prompts, repository context, or configuration values are sent to a remote
provider.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|authorization)"
        r"\b\s*[:=]\s*['\"]?[^\s'\"]{4,}"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
)


class SecretRedactor:
    """Deterministic redactor for known configuration values and credential shapes."""

    def __init__(self, secret_values: Iterable[str] = ()) -> None:
        values = {value for value in secret_values if value and len(value) >= 4}
        self._values = tuple(sorted(values, key=len, reverse=True))

    def redact(self, text: str) -> str:
        """Return *text* with configured secrets and common credential shapes removed."""
        result = text
        for value in self._values:
            result = result.replace(value, REDACTED)
        for pattern in _PATTERNS:
            result = pattern.sub(REDACTED, result)
        return result

    def contains_secret(self, text: str) -> bool:
        """True when redaction would change *text*."""
        return self.redact(text) != text
