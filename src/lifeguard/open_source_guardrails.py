from __future__ import annotations

import os
from dataclasses import dataclass


_LANGSMITH_KEY_ENV_VARS = (
    "LANGSMITH_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGCHAIN_ENDPOINT",
)
_LANGSMITH_TRACING_ENV_VARS = (
    "LANGCHAIN_TRACING_V2",
    "LANGSMITH_TRACING",
)
_FALSE_LIKE_VALUES = {"", "0", "false", "off", "no"}


@dataclass(frozen=True)
class OpenSourceModeViolation(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


def enforce_open_source_mode() -> None:
    configured = _configured_langsmith_environment()
    if not configured:
        return

    details = ", ".join(sorted(configured))
    raise OpenSourceModeViolation(
        "Open source mode blocks Lang Smith configuration. "
        f"Unset these environment variables: {details}."
    )


def _configured_langsmith_environment() -> tuple[str, ...]:
    configured: list[str] = []
    for key in _LANGSMITH_KEY_ENV_VARS:
        value = os.getenv(key, "").strip()
        if value:
            configured.append(key)

    for key in _LANGSMITH_TRACING_ENV_VARS:
        value = os.getenv(key, "").strip().lower()
        if value not in _FALSE_LIKE_VALUES:
            configured.append(key)

    return tuple(configured)
