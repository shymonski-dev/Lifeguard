from __future__ import annotations

import pytest

from lifeguard.adapters import LifeguardExtractsAdapterLayer


def _status_map(layer: LifeguardExtractsAdapterLayer) -> dict[str, object]:
    return {status.adapter_name: status for status in layer.list_module_status()}


def test_adapter_status_lists_selected_modules() -> None:
    layer = LifeguardExtractsAdapterLayer()
    statuses = _status_map(layer)
    expected_names = {
        "circuit_breaker",
        "retry",
        "json_parser",
        "security_preflight",
        "analyzer_usage",
        "model_registry",
        "ast_guard",
    }
    assert set(statuses) == expected_names


def test_json_parser_adapter_parses_fenced_content() -> None:
    layer = LifeguardExtractsAdapterLayer()
    statuses = _status_map(layer)
    if not statuses["json_parser"].available:
        pytest.skip(statuses["json_parser"].detail)

    parsed = layer.parse_json_response("```json\n{answer: True,}\n```")
    assert parsed == {"answer": True}


def test_retry_adapter_retries_on_timeout() -> None:
    layer = LifeguardExtractsAdapterLayer()
    statuses = _status_map(layer)
    if not statuses["retry"].available:
        pytest.skip(statuses["retry"].detail)

    attempt_counter = {"count": 0}

    def flaky_operation() -> str:
        attempt_counter["count"] += 1
        if attempt_counter["count"] < 3:
            raise TimeoutError("temporary timeout")
        return "ok"

    config = layer.build_retry_config(
        max_retries=3,
        initial_backoff=0.0,
        max_backoff=0.0,
        backoff_multiplier=1.0,
        jitter=0.0,
    )
    result = layer.retry_with_backoff(flaky_operation, config=config)
    assert result == "ok"
    assert attempt_counter["count"] == 3


def test_model_registry_adapter_reads_tier_identifier() -> None:
    layer = LifeguardExtractsAdapterLayer()
    statuses = _status_map(layer)
    if not statuses["model_registry"].available:
        pytest.skip(statuses["model_registry"].detail)

    model_id = layer.get_model_id("sonnet")
    assert isinstance(model_id, str)
    assert model_id
