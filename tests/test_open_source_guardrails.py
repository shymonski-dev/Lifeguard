from __future__ import annotations

import pytest

from lifeguard.open_source_guardrails import OpenSourceModeViolation, enforce_open_source_mode


_GUARD_ENV_VARS = (
    "LANGSMITH_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGCHAIN_ENDPOINT",
    "LANGCHAIN_TRACING_V2",
    "LANGSMITH_TRACING",
)


def _clear_guard_env(monkeypatch) -> None:
    for key in _GUARD_ENV_VARS:
        monkeypatch.delenv(key, raising=False)


def test_open_source_guard_allows_clean_environment(monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    enforce_open_source_mode()


def test_open_source_guard_blocks_langsmith_api_key(monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    monkeypatch.setenv("LANGSMITH_API_KEY", "secret")
    with pytest.raises(OpenSourceModeViolation):
        enforce_open_source_mode()


def test_open_source_guard_blocks_tracing_enabled(monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    with pytest.raises(OpenSourceModeViolation):
        enforce_open_source_mode()


def test_open_source_guard_allows_tracing_disabled(monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    enforce_open_source_mode()
