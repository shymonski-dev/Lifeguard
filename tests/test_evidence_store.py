from __future__ import annotations

import json
from pathlib import Path

from lifeguard.evidence_store import EvidenceStore


def test_evidence_store_verify_chain_passes_for_valid_log(tmp_path) -> None:
    path = tmp_path / "evidence" / "events.jsonl"
    store = EvidenceStore(path)
    store.append("check.one", "pass", {"count": 1})
    store.append("check.two", "pass", {"count": 2})

    verification = store.verify_chain()
    assert verification.passed is True
    assert verification.record_count == 2
    assert verification.failure_index is None


def test_evidence_store_verify_chain_detects_tamper(tmp_path) -> None:
    path = tmp_path / "evidence" / "events.jsonl"
    store = EvidenceStore(path)
    store.append("check.one", "pass", {"count": 1})
    store.append("check.two", "pass", {"count": 2})

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    first = json.loads(lines[0])
    first["details"]["count"] = 99
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verification = store.verify_chain()
    assert verification.passed is False
    assert verification.failure_index == 1
    assert "hash" in verification.failure_reason.lower()


def test_evidence_store_sanitizes_absolute_paths_in_details(tmp_path) -> None:
    path = tmp_path / "evidence" / "events.jsonl"
    store = EvidenceStore(path)
    outside_path = Path("/tmp/lifeguard/example.txt")
    inside_path = path.parent / "relative.txt"

    store.append(
        "path.check",
        "pass",
        {
            "outside": str(outside_path),
            "inside": str(inside_path),
            "path_obj": inside_path,
        },
    )
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["details"]["inside"] == "relative.txt"
    assert record["details"]["path_obj"] == "relative.txt"
    assert record["details"]["outside"] == str(outside_path.resolve())
