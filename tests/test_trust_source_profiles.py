from __future__ import annotations

import json

import pytest

from lifeguard.spec_schema import LiveDataSettings
from lifeguard.trust_source_profiles import (
    TrustSourceProfileError,
    apply_managed_trust_source_profile,
    default_trust_source_profile_path,
    load_managed_trust_source_profiles,
)


def _write_profile_file(path) -> None:
    payload = {
        "version": 1,
        "profiles": [
            {
                "profile_id": "managed-primary",
                "display_name": "Managed Primary",
                "description": "Managed trust profile for tests.",
                "policy_version": "2026-02-14",
                "approved_by": "security-team",
                "approval_id": "approval-123",
                "approved_at": "2026-02-14T00:00:00+00:00",
                "high_trust_domains": ["trusted.example"],
                "medium_trust_domains": ["reference.example"],
                "allowed_domains": ["trusted.example", "reference.example"],
                "min_trusted_citations_by_risk": {"low": 1, "medium": 2, "high": 3},
                "min_independent_trusted_domains_by_risk": {"low": 1, "medium": 2, "high": 2},
                "enforce_freshness": True,
                "require_publication_dates": False,
                "freshness_days_news": 30,
                "freshness_days_official_docs": 365,
                "freshness_days_security_advisory": 180,
                "freshness_days_general": 120,
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_load_managed_profiles_from_file(tmp_path) -> None:
    profile_file = tmp_path / "trust_profiles.json"
    _write_profile_file(profile_file)
    profiles = load_managed_trust_source_profiles(profile_file)
    assert len(profiles) == 1
    assert profiles[0].profile_id == "managed-primary"


def test_apply_managed_profile_overrides_runtime_settings(tmp_path) -> None:
    profile_file = tmp_path / "trust_profiles.json"
    _write_profile_file(profile_file)
    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=5,
        min_citations=1,
        trust_profile_id="managed-primary",
        trust_profile_file=str(profile_file),
        timeout_seconds=15,
    )
    resolved_settings, resolution = apply_managed_trust_source_profile(settings, "high")
    assert resolution is not None
    assert resolution.profile_id == "managed-primary"
    assert "trusted.example" in resolved_settings.high_trust_domains
    assert resolved_settings.min_trusted_citations == 3
    assert resolved_settings.min_independent_trusted_domains == 2


def test_apply_managed_profile_raises_when_missing(tmp_path) -> None:
    profile_file = tmp_path / "trust_profiles.json"
    _write_profile_file(profile_file)
    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=5,
        min_citations=1,
        trust_profile_id="missing-profile",
        trust_profile_file=str(profile_file),
        timeout_seconds=15,
    )
    with pytest.raises(TrustSourceProfileError):
        apply_managed_trust_source_profile(settings, "medium")


def test_builtin_profiles_include_legislation_profiles() -> None:
    profiles = load_managed_trust_source_profiles(default_trust_source_profile_path())
    profile_ids = {profile.profile_id for profile in profiles}
    assert "legislation_united_kingdom_primary" in profile_ids
    assert "legislation_european_union_primary" in profile_ids
