from __future__ import annotations

import json

from lifeguard.cli import main
from lifeguard.release_workflow import default_release_workflow
from lifeguard.spec_schema import AgentSpec, DataScope, SecurityRequirements, ToolSpec

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


def _write_signing_key(tmp_path) -> str:
    path = tmp_path / "signing.key"
    path.write_text("lifeguard-signing-key-material-123456789", encoding="utf-8")
    return str(path)


def _base_spec() -> AgentSpec:
    return AgentSpec(
        name="anchor-agent",
        description="Emit anchor payload from a signed release manifest.",
        risk_level="low",
        tools=(
            ToolSpec(
                name="review",
                command="python review.py",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=30.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Review source for vulnerabilities.", "Produce signed release evidence."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed manifest", "Verification check log"),
        ),
    )


def test_cli_anchor_outputs_payload(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    key_file = _write_signing_key(tmp_path)

    workflow = default_release_workflow(evidence_path=evidence)
    report = workflow.run(
        spec=_base_spec(),
        output_dir=output_dir,
        signing_key_file=key_file,
    )
    assert report.passed is True
    capsys.readouterr()

    manifest_path = output_dir / "release_manifest.json"
    exit_code = main(["anchor", "--manifest", str(manifest_path)])
    assert exit_code == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["passed"] is True

    anchor = payload["anchor"]
    anchor_file = json.loads((output_dir / "release_anchor.json").read_text(encoding="utf-8"))
    assert anchor == anchor_file


def test_cli_anchor_writes_output_file(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    key_file = _write_signing_key(tmp_path)

    workflow = default_release_workflow(evidence_path=evidence)
    report = workflow.run(
        spec=_base_spec(),
        output_dir=output_dir,
        signing_key_file=key_file,
    )
    assert report.passed is True
    capsys.readouterr()

    manifest_path = output_dir / "release_manifest.json"
    anchor_output = tmp_path / "anchor_out.json"
    exit_code = main(
        [
            "anchor",
            "--manifest",
            str(manifest_path),
            "--output",
            str(anchor_output),
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    written = json.loads(anchor_output.read_text(encoding="utf-8"))
    anchor_file = json.loads((output_dir / "release_anchor.json").read_text(encoding="utf-8"))
    assert written == anchor_file

