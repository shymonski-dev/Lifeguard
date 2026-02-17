from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EvidenceEvent:
    timestamp: str
    event_type: str
    status: str
    details: dict[str, Any]
    previous_hash: str
    record_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "status": self.status,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


@dataclass(frozen=True)
class EvidenceChainVerification:
    passed: bool
    record_count: int
    failure_index: int | None = None
    failure_reason: str = ""


class EvidenceStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, status: str, details: dict[str, Any]) -> EvidenceEvent:
        sanitized_details = self._sanitize_value(details)
        timestamp = datetime.now(timezone.utc).isoformat()
        previous_hash = self._last_hash()
        payload = {
            "timestamp": timestamp,
            "event_type": event_type,
            "status": status,
            "details": sanitized_details,
            "previous_hash": previous_hash,
        }
        record_hash = _compute_record_hash(payload)
        event = EvidenceEvent(
            timestamp=timestamp,
            event_type=event_type,
            status=status,
            details=sanitized_details,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return event

    def get_last_hash(self) -> str:
        return self._last_hash()

    def verify_chain(self) -> EvidenceChainVerification:
        if not self.path.exists():
            return EvidenceChainVerification(passed=True, record_count=0)

        previous_hash = "GENESIS"
        record_count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line_index, line in enumerate(handle, start=1):
                cleaned = line.strip()
                if not cleaned:
                    continue
                try:
                    record = json.loads(cleaned)
                except json.JSONDecodeError:
                    return EvidenceChainVerification(
                        passed=False,
                        record_count=record_count,
                        failure_index=line_index,
                        failure_reason="Invalid JSON record.",
                    )
                if not isinstance(record, dict):
                    return EvidenceChainVerification(
                        passed=False,
                        record_count=record_count,
                        failure_index=line_index,
                        failure_reason="Record must be an object.",
                    )

                timestamp = str(record.get("timestamp", ""))
                event_type = str(record.get("event_type", ""))
                status = str(record.get("status", ""))
                details = record.get("details")
                stored_previous_hash = str(record.get("previous_hash", ""))
                stored_record_hash = str(record.get("record_hash", ""))
                if not isinstance(details, dict):
                    return EvidenceChainVerification(
                        passed=False,
                        record_count=record_count,
                        failure_index=line_index,
                        failure_reason="Record details must be an object.",
                    )

                if stored_previous_hash != previous_hash:
                    return EvidenceChainVerification(
                        passed=False,
                        record_count=record_count,
                        failure_index=line_index,
                        failure_reason="Record previous hash does not match chain.",
                    )

                payload = {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "status": status,
                    "details": details,
                    "previous_hash": stored_previous_hash,
                }
                computed_record_hash = _compute_record_hash(payload)
                if stored_record_hash != computed_record_hash:
                    return EvidenceChainVerification(
                        passed=False,
                        record_count=record_count,
                        failure_index=line_index,
                        failure_reason="Record hash does not match payload.",
                    )

                previous_hash = stored_record_hash
                record_count += 1

        return EvidenceChainVerification(
            passed=True,
            record_count=record_count,
        )

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"

        last_line = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    last_line = stripped

        if not last_line:
            return "GENESIS"

        record = json.loads(last_line)
        return str(record.get("record_hash", "GENESIS"))

    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): self._sanitize_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        if isinstance(value, tuple):
            return [self._sanitize_value(v) for v in value]
        if isinstance(value, Path):
            return self._sanitize_path(value)
        if isinstance(value, str):
            return self._sanitize_string(value)
        return value

    def _sanitize_path(self, path: Path) -> str:
        resolved = path
        try:
            resolved = path.resolve()
        except OSError:
            pass
        base_dir = self.path.parent.resolve()
        try:
            return str(resolved.relative_to(base_dir))
        except ValueError:
            return str(resolved)

    def _sanitize_string(self, text: str) -> str:
        # Normalize evidence-local paths to relative so reports do not leak workstation layout.
        candidate = Path(text)
        if not candidate.is_absolute():
            return text
        resolved = candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            pass
        base_dir = self.path.parent.resolve()
        try:
            return str(resolved.relative_to(base_dir))
        except ValueError:
            return str(resolved)


def _compute_record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
