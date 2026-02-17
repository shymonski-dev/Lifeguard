from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_LLM_TOP_TEN_IDS = tuple(f"LLM{index:02d}" for index in range(1, 11))
REQUIRED_AGENTIC_IDS = tuple(f"AGENT{index:02d}" for index in range(1, 9))


@dataclass(frozen=True)
class ControlMatrixSummary:
    passed: bool
    coverage_percent: float
    required_count: int
    mapped_count: int
    missing_ids: tuple[str, ...]
    matrix_path: str
    framework_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "coverage_percent": self.coverage_percent,
            "required_count": self.required_count,
            "mapped_count": self.mapped_count,
            "missing_ids": list(self.missing_ids),
            "matrix_path": self.matrix_path,
            "framework_version": self.framework_version,
        }


def default_control_matrix_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "compliance" / "owasp_control_matrix.json"


def evaluate_control_matrix_file(path: str | Path | None = None) -> ControlMatrixSummary:
    target = default_control_matrix_path() if path is None else Path(path)
    if not target.exists():
        required_total = len(REQUIRED_LLM_TOP_TEN_IDS) + len(REQUIRED_AGENTIC_IDS)
        return ControlMatrixSummary(
            passed=False,
            coverage_percent=0.0,
            required_count=required_total,
            mapped_count=0,
            missing_ids=tuple(REQUIRED_LLM_TOP_TEN_IDS + REQUIRED_AGENTIC_IDS),
            matrix_path=str(target),
            framework_version="",
        )

    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Control matrix payload must be an object.")

    controls_payload = payload.get("controls")
    if not isinstance(controls_payload, list):
        raise ValueError("Control matrix controls must be a list.")

    control_index: dict[str, dict[str, Any]] = {}
    for item in controls_payload:
        if not isinstance(item, dict):
            continue
        control_id = str(item.get("id", "")).strip().upper()
        if not control_id:
            continue
        control_index[control_id] = item

    required_ids = tuple(REQUIRED_LLM_TOP_TEN_IDS + REQUIRED_AGENTIC_IDS)
    mapped: list[str] = []
    missing: list[str] = []
    for control_id in required_ids:
        item = control_index.get(control_id)
        if item is None:
            missing.append(control_id)
            continue
        mapped_by = item.get("mapped_by")
        tests = item.get("tests")
        if not isinstance(mapped_by, list) or not mapped_by:
            missing.append(control_id)
            continue
        if not isinstance(tests, list) or not tests:
            missing.append(control_id)
            continue
        mapped.append(control_id)

    coverage_percent = round((len(mapped) / len(required_ids)) * 100.0, 2) if required_ids else 100.0
    return ControlMatrixSummary(
        passed=not missing,
        coverage_percent=coverage_percent,
        required_count=len(required_ids),
        mapped_count=len(mapped),
        missing_ids=tuple(missing),
        matrix_path=str(target),
        framework_version=str(payload.get("framework_version", "")).strip(),
    )


def build_badge_material(
    *,
    summary: ControlMatrixSummary,
    evidence_run_id: str,
) -> dict[str, Any]:
    label = "OWASP Control Coverage"
    message = f"{summary.coverage_percent:.2f}% ({summary.mapped_count}/{summary.required_count})"
    color = "brightgreen" if summary.passed else "orange"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "message": message,
        "color": color,
        "passed": summary.passed,
        "coverage_percent": summary.coverage_percent,
        "required_count": summary.required_count,
        "mapped_count": summary.mapped_count,
        "missing_ids": list(summary.missing_ids),
        "framework_version": summary.framework_version,
        "matrix_path": summary.matrix_path,
        "evidence_run_id": evidence_run_id,
    }
