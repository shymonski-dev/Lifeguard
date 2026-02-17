from __future__ import annotations

import pytest

from lifeguard.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    AdapterActionResult,
    AdapterError,
    AdapterTrustMetadata,
    LifeguardExtractsAdapterLayer,
)


def test_contract_request_and_result_round_trip() -> None:
    trust = AdapterTrustMetadata(
        risk_level="high",
        trust_profile_id="secure_code_review_primary",
        high_trust_domains=("nvd.nist.gov",),
        min_trusted_citations=2,
        min_independent_trusted_domains=2,
    )
    request = AdapterActionRequest(
        action_name="json.parse",
        payload={"content": '{"ok": true}'},
        request_id="req-123",
        tool_name="json_parser",
        trust=trust,
    )
    request_copy = AdapterActionRequest.from_dict(request.to_dict())
    assert request_copy == request

    result = AdapterActionResult(
        action_name="json.parse",
        ok=False,
        errors=(AdapterError(code="invalid_action_payload", message="bad payload", category="validation"),),
        metadata={"request_id": "req-123"},
        trust=trust,
    )
    result_copy = AdapterActionResult.from_dict(result.to_dict())
    assert result_copy == result


def test_adapter_layer_exposes_contract_version_and_tool_schema() -> None:
    layer = LifeguardExtractsAdapterLayer()
    assert layer.contract_version == ADAPTER_CONTRACT_VERSION
    schemas = layer.list_tool_schemas()
    actions = {schema.action_name for schema in schemas}
    assert "json.parse" in actions
    assert "security_preflight.run" in actions
    assert "ast_guard.validate_source" in actions


def test_execute_action_rejects_contract_version_mismatch() -> None:
    layer = LifeguardExtractsAdapterLayer()
    request = AdapterActionRequest(
        action_name="module_status.list",
        payload={},
        contract_version="999.0.0",
    )
    result = layer.execute_action(request)
    assert not result.ok
    assert result.errors[0].code == "contract_version_mismatch"


def test_execute_action_rejects_unknown_action() -> None:
    layer = LifeguardExtractsAdapterLayer()
    request = AdapterActionRequest(action_name="unknown.action", payload={})
    result = layer.execute_action(request)
    assert not result.ok
    assert result.errors[0].code == "unknown_action"


def test_execute_action_parses_json_and_carries_trust_metadata() -> None:
    layer = LifeguardExtractsAdapterLayer()
    statuses = {status.adapter_name: status for status in layer.list_module_status()}
    if not statuses["json_parser"].available:
        pytest.skip(statuses["json_parser"].detail)

    trust = AdapterTrustMetadata(risk_level="medium", trust_profile_id="secure_code_review_primary")
    request = AdapterActionRequest(
        action_name="json.parse",
        payload={"content": "```json\n{answer: True,}\n```"},
        trust=trust,
    )
    result = layer.execute_action(request)
    assert result.ok
    assert result.output["data"] == {"answer": True}
    assert result.trust == trust
