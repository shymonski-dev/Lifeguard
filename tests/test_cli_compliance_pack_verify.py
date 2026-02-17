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
        name="compliance-pack-cli-agent",
        description="Verify a compliance pack from the command line.",
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


def test_cli_compliance_pack_verify(tmp_path, monkeypatch, capsys) -> None:
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

    pack_dir = output_dir / "compliance_pack"
    exit_code = main(
        [
            "compliance-pack-verify",
            "--pack",
            str(pack_dir),
            "--signing-key-file",
            key_file,
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True

