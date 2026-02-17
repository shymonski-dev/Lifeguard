from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adversarial_validation import AdversarialValidationReport
from .spec_schema import AgentSpec


@dataclass(frozen=True)
class AdversarialRunRecord:
    run_id: str
    generated_at: str
    agent_name: str
    risk_level: str
    profile_id: str
    pass_rate: float
    threshold: float
    passed: bool
    passed_cases: int
    total_cases: int
    failed_case_ids: tuple[str, ...]
    artifact_path: Path
    history_path: Path
    history_count: int
    rolling_pass_rate_last_10: float
    pass_rate_delta_from_previous: float | None
    failing_streak: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "agent_name": self.agent_name,
            "risk_level": self.risk_level,
            "profile_id": self.profile_id,
            "pass_rate": self.pass_rate,
            "threshold": self.threshold,
            "passed": self.passed,
            "passed_cases": self.passed_cases,
            "total_cases": self.total_cases,
            "failed_case_ids": list(self.failed_case_ids),
            "artifact_path": str(self.artifact_path),
            "history_path": str(self.history_path),
            "history_count": self.history_count,
            "rolling_pass_rate_last_10": self.rolling_pass_rate_last_10,
            "pass_rate_delta_from_previous": self.pass_rate_delta_from_previous,
            "failing_streak": self.failing_streak,
        }


class AdversarialReportStore:
    def __init__(self, evidence_path: str | Path) -> None:
        self.evidence_path = Path(evidence_path)
        self.report_dir = self.evidence_path.parent / f"{self.evidence_path.stem}.adversarial_reports"
        self.history_path = self.evidence_path.parent / f"{self.evidence_path.stem}.adversarial_history.jsonl"
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def record(self, spec: AgentSpec, report: AdversarialValidationReport) -> AdversarialRunRecord:
        now = datetime.now(timezone.utc)
        generated_at = now.isoformat()
        run_id = _generate_run_id(now)
        agent_slug = _safe_slug(spec.name)
        artifact_filename = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{agent_slug}-{run_id[-6:]}.json"
        artifact_path = self.report_dir / artifact_filename

        artifact_payload = {
            "run_id": run_id,
            "generated_at": generated_at,
            "agent_name": spec.name,
            "risk_level": spec.risk_level,
            "profile_id": spec.profile_id,
            "pass_rate": report.pass_rate,
            "threshold": report.threshold,
            "passed": report.passed,
            "passed_cases": report.passed_cases,
            "total_cases": report.total_cases,
            "failed_case_ids": list(report.failed_case_ids),
            "results": [result.to_dict() for result in report.results],
        }
        artifact_path.write_text(json.dumps(artifact_payload, indent=2) + "\n", encoding="utf-8")

        previous_records = self.load_history()
        previous_pass_rate = (
            float(previous_records[-1].get("pass_rate"))
            if previous_records
            else None
        )

        summary_record: dict[str, Any] = {
            "run_id": run_id,
            "generated_at": generated_at,
            "agent_name": spec.name,
            "risk_level": spec.risk_level,
            "profile_id": spec.profile_id,
            "pass_rate": report.pass_rate,
            "threshold": report.threshold,
            "passed": report.passed,
            "passed_cases": report.passed_cases,
            "total_cases": report.total_cases,
            "failed_case_ids": list(report.failed_case_ids),
            "artifact_path": self._safe_relpath(artifact_path),
        }

        combined_records = [*previous_records, summary_record]
        trend = _trend_summary(combined_records)
        summary_record.update(trend)
        with self.history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(summary_record, sort_keys=True) + "\n")

        return AdversarialRunRecord(
            run_id=run_id,
            generated_at=generated_at,
            agent_name=spec.name,
            risk_level=spec.risk_level,
            profile_id=spec.profile_id,
            pass_rate=report.pass_rate,
            threshold=report.threshold,
            passed=report.passed,
            passed_cases=report.passed_cases,
            total_cases=report.total_cases,
            failed_case_ids=report.failed_case_ids,
            artifact_path=artifact_path,
            history_path=self.history_path,
            history_count=len(combined_records),
            rolling_pass_rate_last_10=trend["rolling_pass_rate_last_10"],
            pass_rate_delta_from_previous=(
                report.pass_rate - previous_pass_rate
                if previous_pass_rate is not None
                else None
            ),
            failing_streak=trend["failing_streak"],
        )

    def _safe_relpath(self, path: Path) -> str:
        base_dir = self.evidence_path.parent.resolve()
        try:
            return str(path.resolve().relative_to(base_dir))
        except (OSError, ValueError):
            return str(path)

    def load_history(self, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        records: list[dict[str, Any]] = []
        with self.history_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                parsed = json.loads(stripped)
                if not isinstance(parsed, dict):
                    continue
                records.append(parsed)
        if limit is not None and limit >= 0:
            return records[-limit:]
        return records


def summarize_adversarial_history(
    evidence_path: str | Path,
    limit: int = 10,
) -> dict[str, Any]:
    store = AdversarialReportStore(evidence_path)
    history = store.load_history()
    latest = history[-1] if history else None
    recent = history[-limit:] if limit >= 0 else history
    trend = _trend_summary(history) if history else {
        "history_count": 0,
        "rolling_pass_rate_last_10": 0.0,
        "failing_streak": 0,
    }
    return {
        "history_path": str(store.history_path),
        "report_directory": str(store.report_dir),
        "count": len(history),
        "latest": latest,
        "recent": recent,
        "trend": trend,
    }


def _generate_run_id(now: datetime) -> str:
    return f"adv-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def _safe_slug(value: str) -> str:
    lowered = value.strip().lower()
    candidate = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return candidate or "agent"


def _trend_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {
            "history_count": 0,
            "rolling_pass_rate_last_10": 0.0,
            "failing_streak": 0,
        }

    last_ten = records[-10:]
    rolling = sum(float(item.get("pass_rate", 0.0)) for item in last_ten) / float(len(last_ten))
    failing_streak = 0
    for item in reversed(records):
        if bool(item.get("passed", False)):
            break
        failing_streak += 1

    return {
        "history_count": len(records),
        "rolling_pass_rate_last_10": rolling,
        "failing_streak": failing_streak,
    }
