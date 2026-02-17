from __future__ import annotations

import pytest

from lifeguard.spec_schema import (
    AgentSpec,
    ConfigValidationError,
    DataScope,
    LiveDataSettings,
    SecurityRequirements,
    ToolSpec,
    create_spec_from_profile,
    evaluate_spec_quality,
    list_security_profiles,
)


def test_profile_library_has_required_fields() -> None:
    profiles = list_security_profiles()
    assert profiles
    profile_ids = {profile.profile_id for profile in profiles}
    assert "secure_code_review" in profile_ids
    assert "secure_code_review_local" in profile_ids
    for profile in profiles:
        assert profile.security_requirements.goals
        assert profile.security_requirements.threat_actors
        assert profile.security_requirements.evidence_requirements


def test_create_spec_from_profile_sets_profile_metadata() -> None:
    spec = create_spec_from_profile(
        "dependency_audit",
        name="dependency-audit-agent",
        risk_level="high",
    )
    assert spec.name == "dependency-audit-agent"
    assert spec.profile_id == "dependency_audit"
    assert spec.risk_level == "high"
    assert spec.security_requirements.goals
    assert spec.security_requirements.threat_actors
    assert spec.security_requirements.evidence_requirements


def test_spec_quality_fails_when_required_sections_are_missing() -> None:
    weak_spec = AgentSpec(
        name="weak-agent",
        description="Minimal specification with missing security requirements.",
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
        budget_limit_usd=20.0,
        max_runtime_seconds=300,
    )
    report = evaluate_spec_quality(weak_spec)
    assert report.passed is False
    assert "goals" in report.missing_requirements
    assert "threat_actors" in report.missing_requirements
    assert "evidence_requirements" in report.missing_requirements


def test_spec_quality_passes_for_profile_spec() -> None:
    spec = create_spec_from_profile("secure_code_review")
    report = evaluate_spec_quality(spec)
    assert report.passed is True
    assert report.score >= report.threshold
    assert spec.live_data.trust_profile_id == "secure_code_review_primary"


def test_local_profile_disables_live_intelligence_for_smoke_runs() -> None:
    spec = create_spec_from_profile("secure_code_review_local")
    assert spec.live_data.enabled is False


def test_tool_spec_rejects_multiline_command() -> None:
    with pytest.raises(ConfigValidationError):
        ToolSpec(
            name="review",
            command="python review.py\npython extra.py",
            can_write_files=False,
            can_access_network=False,
            timeout_seconds=30,
        )


def test_data_scope_rejects_relative_paths() -> None:
    with pytest.raises(ConfigValidationError):
        DataScope(
            read_paths=("workspace",),
            write_paths=(),
            allowed_hosts=(),
        )


def test_live_data_settings_rejects_overlap_between_trust_tiers() -> None:
    with pytest.raises(ConfigValidationError):
        LiveDataSettings(
            enabled=True,
            provider="openrouter",
            high_trust_domains=("openai.com",),
            medium_trust_domains=("openai.com",),
        )
