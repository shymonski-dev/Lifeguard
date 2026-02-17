from __future__ import annotations

import json

from lifeguard.dashboard import build_dashboard_data, write_dashboard


def test_dashboard_data_aggregates_release_and_evidence(tmp_path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "agent_spec": {"risk_level": "high"},
        "verification": {
            "passed": True,
            "checks": [{"name": "runtime_guardrail", "passed": True, "message": "ok"}],
        },
        "signature": {"algorithm": "hmac-sha256"},
    }
    (run_dir / "release_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    events = [
        {
            "event_type": "model_context_protocol_gating.final",
            "status": "pass",
            "details": {},
        },
        {
            "event_type": "live_intelligence_freshness",
            "status": "pass",
            "details": {"citation_count": 3},
        },
    ]
    with (run_dir / "events.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    payload = build_dashboard_data(tmp_path)
    assert payload["release"]["manifest_count"] == 1
    assert payload["release"]["verification_passed_count"] == 1
    assert payload["release"]["signature_algorithms"]["hmac-sha256"] == 1
    assert payload["evidence"]["model_context_protocol_final"]["pass"] == 1
    assert payload["evidence"]["live_intelligence"]["average_citation_count"] == 3.0


def test_write_dashboard_creates_html_file(tmp_path) -> None:
    output = tmp_path / "dashboard.html"
    path = write_dashboard(validation_root=tmp_path, output_path=output)
    assert path == output
    html = output.read_text(encoding="utf-8")
    assert "Lifeguard Verification Dashboard" in html
