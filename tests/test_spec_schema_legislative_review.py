from __future__ import annotations

import pytest

from lifeguard.spec_schema import (
    AgentSpec,
    ConfigValidationError,
    DataScope,
    LegalContext,
    LegislativeReviewSettings,
    SecurityRequirements,
    ToolSpec,
    evaluate_spec_quality,
)


def _base_spec(*, intended_use: str, enabled: bool) -> AgentSpec:
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
            intended_use=intended_use,
            sector="administrative",
            decision_impact_level="medium",
            compliance_target_date="2026-08-02",
            data_categories=("personal data",),
        ),
        legislative_review=LegislativeReviewSettings(
            enabled=enabled,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=6,
            min_citations=2,
            timeout_seconds=60,
            strict=True,
            require_human_decision=True,
            decision_file="",
        ),
    )


def test_agent_spec_round_trips_legal_and_legislative_fields() -> None:
    spec = _base_spec(intended_use="tax administration assistant", enabled=True)
    payload = spec.to_dict()
    loaded = AgentSpec.from_dict(payload)
    assert loaded.legal_context.intended_use == spec.legal_context.intended_use
    assert loaded.legislative_review.enabled is True
    assert loaded.legislative_review.provider == "openrouter"


def test_quality_gate_requires_intended_use_when_legislative_review_enabled() -> None:
    spec = _base_spec(intended_use="", enabled=True)
    report = evaluate_spec_quality(spec)
    assert report.passed is False
    assert "legal_context.intended_use" in report.missing_requirements


def test_legal_context_rejects_non_iso_target_date() -> None:
    with pytest.raises(ConfigValidationError):
        LegalContext(
            jurisdictions=("United Kingdom",),
            intended_use="administrative agent",
            compliance_target_date="02/08/2026",
        )

