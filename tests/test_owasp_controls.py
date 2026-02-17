from __future__ import annotations

import json

from lifeguard.owasp_controls import (
    build_badge_material,
    evaluate_control_matrix_file,
)


def test_default_control_matrix_has_required_mappings() -> None:
    summary = evaluate_control_matrix_file()
    assert summary.passed is True
    assert summary.coverage_percent == 100.0
    assert summary.missing_ids == ()


def test_control_matrix_fails_when_required_mapping_is_missing(tmp_path) -> None:
    matrix_file = tmp_path / "matrix.json"
    payload = {
        "framework_version": "test",
        "controls": [
            {
                "id": "LLM01",
                "name": "Prompt Injection",
                "mapped_by": ["runtime_policy_middleware"],
                "tests": ["tests/test_runtime_policy_middleware.py"],
            }
        ],
    }
    matrix_file.write_text(json.dumps(payload), encoding="utf-8")
    summary = evaluate_control_matrix_file(matrix_file)
    assert summary.passed is False
    assert "LLM02" in summary.missing_ids


def test_badge_material_includes_evidence_identifier() -> None:
    summary = evaluate_control_matrix_file()
    badge = build_badge_material(summary=summary, evidence_run_id="run-123")
    assert badge["passed"] is True
    assert badge["coverage_percent"] == 100.0
    assert badge["evidence_run_id"] == "run-123"
