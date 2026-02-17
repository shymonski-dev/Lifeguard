from __future__ import annotations

import json

from lifeguard.cli import main
from lifeguard.live_intelligence import Citation, LiveDataReport
from lifeguard.spec_schema import (
    AgentSpec,
    DataScope,
    LegalContext,
    LegislativeReviewSettings,
    LiveDataSettings,
    SecurityRequirements,
    ToolSpec,
    write_spec,
)
from lifeguard.verification_pipeline import default_pipeline

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


class _FakeIntelligenceClient:
    def collect_latest(self, query, settings, risk_level="low"):
        del settings, risk_level
        query_text = str(query)
        jurisdiction = "United Kingdom" if "United Kingdom" in query_text else "European Union"
        domain = "legislation.gov.uk" if jurisdiction == "United Kingdom" else "eur-lex.europa.eu"
        return LiveDataReport(
            provider="openrouter",
            model="openai/gpt-5.2:online",
            query=query_text,
            summary=f"{jurisdiction} obligations summary.",
            citations=(
                Citation(
                    url=f"https://{domain}/example",
                    title=f"{jurisdiction} source",
                    domain=domain,
                ),
                Citation(
                    url=f"https://{domain}/example2",
                    title=f"{jurisdiction} source 2",
                    domain=domain,
                ),
            ),
            fetched_at="2026-02-17T00:00:00+00:00",
        )


def _spec() -> AgentSpec:
    return AgentSpec(
        name="legislative-review-agent",
        description="Design and verify a secure agent.",
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
            goals=("Review source for vulnerabilities.", "Produce deterministic evidence."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed summary", "Evidence log"),
        ),
        legal_context=LegalContext(
            jurisdictions=("United Kingdom", "European Union"),
            intended_use="tax administration assistant",
            sector="administrative",
            decision_impact_level="medium",
            compliance_target_date="2026-08-02",
            data_categories=("personal data",),
        ),
        legislative_review=LegislativeReviewSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=6,
            min_citations=2,
            timeout_seconds=60,
            strict=True,
            require_human_decision=True,
            decision_file="",
        ),
        live_data=LiveDataSettings(enabled=False),
    )


def test_cli_legislative_review_creates_decision_template(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    spec_path = tmp_path / "spec.json"
    evidence_path = tmp_path / "events.jsonl"
    write_spec(spec_path, _spec())

    fake_intelligence = _FakeIntelligenceClient()

    def patched_default_pipeline(evidence_path_value: str, repo_path=None):
        return default_pipeline(
            evidence_path_value,
            repo_path=repo_path,
            intelligence_client=fake_intelligence,  # type: ignore[arg-type]
        )

    monkeypatch.setattr("lifeguard.cli.default_pipeline", patched_default_pipeline)

    exit_code = main(
        [
            "legislative-review",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
        ]
    )
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert tmp_path.joinpath("legislative_review_pack.json").exists()
    assert tmp_path.joinpath("legislative_review_decision.json").exists()


def test_cli_legislative_review_passes_with_accept_decision(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    spec = _spec()
    spec_path = tmp_path / "spec.json"
    evidence_path = tmp_path / "events.jsonl"
    write_spec(spec_path, spec)

    fake_intelligence = _FakeIntelligenceClient()

    def patched_default_pipeline(evidence_path_value: str, repo_path=None):
        return default_pipeline(
            evidence_path_value,
            repo_path=repo_path,
            intelligence_client=fake_intelligence,  # type: ignore[arg-type]
        )

    monkeypatch.setattr("lifeguard.cli.default_pipeline", patched_default_pipeline)

    # First run creates the decision template (expected failure).
    first_code = main(
        [
            "legislative-review",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
        ]
    )
    assert first_code == 1
    capsys.readouterr()

    decision_path = tmp_path / "legislative_review_decision.json"
    decision_payload = json.loads(decision_path.read_text(encoding="utf-8"))
    decision_payload.update(
        {
            "decision": "accept",
            "reviewed_by": "compliance-reviewer",
            "review_id": "leg-approval-001",
            "reviewed_at": "2026-02-17T00:00:00+00:00",
            "notes": "Reviewed and approved for administrative use.",
        }
    )
    decision_path.write_text(json.dumps(decision_payload, indent=2) + "\n", encoding="utf-8")

    second_code = main(
        [
            "legislative-review",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
        ]
    )
    assert second_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True

