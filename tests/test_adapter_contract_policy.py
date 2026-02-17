from __future__ import annotations

import json
from pathlib import Path

from lifeguard.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    AdapterActionResult,
)


_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "adapter_contract"
_MIGRATION_POLICY_PATH = Path(__file__).resolve().parents[1] / "docs" / "ADAPTER_MIGRATION_POLICY.md"


def _load_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _parse_semantic_version(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        raise AssertionError(f"Invalid semantic version in fixture: {version}")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def test_adapter_contract_backward_compatibility_fixtures_round_trip() -> None:
    request_payload = _load_json(_FIXTURE_ROOT / "v1" / "request.json")
    request = AdapterActionRequest.from_dict(request_payload)
    assert request.to_dict() == request_payload

    result_payload = _load_json(_FIXTURE_ROOT / "v1" / "result.json")
    result = AdapterActionResult.from_dict(result_payload)
    assert result.to_dict() == result_payload


def test_adapter_contract_version_policy_fixture_is_current() -> None:
    policy_payload = _load_json(_FIXTURE_ROOT / "version_policy.json")
    expected_version = str(policy_payload["expected_contract_version"])
    minimum_version = str(policy_payload["minimum_supported_contract_version"])

    assert ADAPTER_CONTRACT_VERSION == expected_version
    assert _parse_semantic_version(ADAPTER_CONTRACT_VERSION) >= _parse_semantic_version(
        minimum_version
    )


def test_adapter_migration_policy_document_mentions_current_contract_version() -> None:
    policy_text = _MIGRATION_POLICY_PATH.read_text(encoding="utf-8")
    assert "Current contract version:" in policy_text
    assert ADAPTER_CONTRACT_VERSION in policy_text
