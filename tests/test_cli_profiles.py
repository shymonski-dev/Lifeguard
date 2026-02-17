from __future__ import annotations

import json

from lifeguard.cli import main
from lifeguard.spec_schema import AgentSpec, DataScope, ToolSpec, load_spec, write_spec

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


def test_cli_profiles_lists_templates(monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    exit_code = main(["profiles"])
    assert exit_code == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    profile_ids = {item["profile_id"] for item in payload["profiles"]}
    assert "secure_code_review" in profile_ids
    assert "dependency_audit" in profile_ids
    assert "secure_code_review_local" in profile_ids
    secure_profile = next(
        item for item in payload["profiles"] if item["profile_id"] == "secure_code_review"
    )
    assert secure_profile["trust_profile_id"] == "secure_code_review_primary"


def test_cli_init_uses_selected_profile(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    target = tmp_path / "profile_spec.json"
    exit_code = main(
        [
            "init",
            "--path",
            str(target),
            "--profile",
            "dependency_audit",
            "--name",
            "dependency-audit-custom",
        ]
    )
    assert exit_code == 0
    spec = load_spec(target)
    assert spec.name == "dependency-audit-custom"
    assert spec.profile_id == "dependency_audit"
    assert spec.security_requirements.goals


def test_cli_quality_fails_weak_spec(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    target = tmp_path / "weak_spec.json"
    write_spec(
        target,
        AgentSpec(
            name="weak-quality",
            description="Weak specification for quality command test.",
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
                write_paths=(),
                allowed_hosts=(),
            ),
            runtime_environment="container",
            budget_limit_usd=25.0,
            max_runtime_seconds=300,
        ),
    )
    exit_code = main(["quality", "--spec", str(target)])
    assert exit_code == 1
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["passed"] is False
    assert "goals" in payload["missing_requirements"]


def test_cli_adversarial_report_outputs_history(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    spec_path = tmp_path / "spec_local.json"
    evidence_path = tmp_path / "events_local.jsonl"

    init_code = main(
        [
            "init",
            "--path",
            str(spec_path),
            "--profile",
            "secure_code_review_local",
        ]
    )
    assert init_code == 0
    capsys.readouterr()

    verify_code = main(
        [
            "verify",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
        ]
    )
    assert verify_code == 0
    capsys.readouterr()

    report_code = main(
        [
            "adversarial-report",
            "--evidence",
            str(evidence_path),
            "--limit",
            "5",
        ]
    )
    assert report_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] >= 1
    assert payload["latest"] is not None


def test_cli_lists_managed_trust_source_profiles(monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    exit_code = main(["trust-source-profiles"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    profile_ids = {item["profile_id"] for item in payload["profiles"]}
    assert "secure_code_review_primary" in profile_ids
