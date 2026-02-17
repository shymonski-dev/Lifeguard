from __future__ import annotations

import json

from lifeguard.cli import main

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


def test_cli_dashboard_writes_html(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    run_dir = tmp_path / "validation" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest_payload = {
        "agent_spec": {"risk_level": "low"},
        "verification": {"passed": True, "checks": []},
        "signature": {"algorithm": "hmac-sha256"},
    }
    (run_dir / "release_manifest.json").write_text(json.dumps(manifest_payload), encoding="utf-8")
    (run_dir / "events.jsonl").write_text(
        json.dumps(
            {
                "event_type": "model_context_protocol_gating.final",
                "status": "pass",
                "details": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "dashboard.html"
    exit_code = main(
        [
            "dashboard",
            "--validation-root",
            str(tmp_path / "validation"),
            "--output",
            str(output_path),
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert output_path.exists()
