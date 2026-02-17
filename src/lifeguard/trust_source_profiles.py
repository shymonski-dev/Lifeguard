from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .spec_schema import LiveDataSettings

_VALID_RISK_LEVELS = {"low", "medium", "high"}


class TrustSourceProfileError(ValueError):
    """Raised when managed trust source profile configuration is invalid."""


@dataclass(frozen=True)
class ManagedTrustSourceProfile:
    profile_id: str
    display_name: str
    description: str
    policy_version: str
    approved_by: str
    approval_id: str
    approved_at: str
    high_trust_domains: tuple[str, ...]
    medium_trust_domains: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    min_trusted_citations_by_risk: dict[str, int]
    min_independent_trusted_domains_by_risk: dict[str, int]
    enforce_freshness: bool
    require_publication_dates: bool
    freshness_days_news: int
    freshness_days_official_docs: int
    freshness_days_security_advisory: int
    freshness_days_general: int

    def __post_init__(self) -> None:
        for value in (
            self.profile_id,
            self.display_name,
            self.policy_version,
            self.approved_by,
            self.approval_id,
            self.approved_at,
        ):
            if not value.strip():
                raise TrustSourceProfileError("Managed trust source profile metadata must be set.")

        for domain in (
            *self.high_trust_domains,
            *self.medium_trust_domains,
            *self.allowed_domains,
        ):
            cleaned = domain.strip()
            if not cleaned or " " in cleaned:
                raise TrustSourceProfileError(
                    f"Invalid domain in managed trust source profile '{self.profile_id}': {domain!r}."
                )

        overlap = set(self.high_trust_domains) & set(self.medium_trust_domains)
        if overlap:
            raise TrustSourceProfileError(
                f"Managed trust source profile '{self.profile_id}' has overlapping high and medium trust domains."
            )

        _validate_risk_mapping(
            self.min_trusted_citations_by_risk,
            f"{self.profile_id}.min_trusted_citations_by_risk",
        )
        _validate_risk_mapping(
            self.min_independent_trusted_domains_by_risk,
            f"{self.profile_id}.min_independent_trusted_domains_by_risk",
        )


@dataclass(frozen=True)
class ManagedTrustSourceResolution:
    profile_id: str
    profile_version: str
    approved_by: str
    approval_id: str
    approved_at: str
    source_path: str
    risk_level: str

    def to_dict(self) -> dict[str, str]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "approved_by": self.approved_by,
            "approval_id": self.approval_id,
            "approved_at": self.approved_at,
            "source_path": self.source_path,
            "risk_level": self.risk_level,
        }


def default_trust_source_profile_path() -> Path:
    from_lifeguard = Path(__file__).resolve().parents[2] / "trust_profiles" / "managed_trust_profiles.json"
    if from_lifeguard.exists():
        return from_lifeguard
    return Path(__file__).resolve().parent / "trust_profiles" / "managed_trust_profiles.json"


def load_managed_trust_source_profiles(
    profile_file: str | Path | None = None,
) -> tuple[ManagedTrustSourceProfile, ...]:
    resolved_path = _resolve_profile_path(profile_file)
    payload = json.loads(resolved_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TrustSourceProfileError("Managed trust source profile file root must be an object.")

    profiles_payload = payload.get("profiles")
    if not isinstance(profiles_payload, list):
        raise TrustSourceProfileError("Managed trust source profile file must include a profiles list.")

    profiles: list[ManagedTrustSourceProfile] = []
    seen_ids: set[str] = set()
    for item in profiles_payload:
        if not isinstance(item, dict):
            raise TrustSourceProfileError("Each managed trust source profile entry must be an object.")
        profile = ManagedTrustSourceProfile(
            profile_id=str(item.get("profile_id", "")).strip(),
            display_name=str(item.get("display_name", "")).strip(),
            description=str(item.get("description", "")).strip(),
            policy_version=str(item.get("policy_version", "")).strip(),
            approved_by=str(item.get("approved_by", "")).strip(),
            approval_id=str(item.get("approval_id", "")).strip(),
            approved_at=str(item.get("approved_at", "")).strip(),
            high_trust_domains=tuple(str(v).strip() for v in item.get("high_trust_domains", [])),
            medium_trust_domains=tuple(str(v).strip() for v in item.get("medium_trust_domains", [])),
            allowed_domains=tuple(str(v).strip() for v in item.get("allowed_domains", [])),
            min_trusted_citations_by_risk={
                str(k): int(v)
                for k, v in dict(item.get("min_trusted_citations_by_risk", {})).items()
            },
            min_independent_trusted_domains_by_risk={
                str(k): int(v)
                for k, v in dict(item.get("min_independent_trusted_domains_by_risk", {})).items()
            },
            enforce_freshness=bool(item.get("enforce_freshness", True)),
            require_publication_dates=bool(item.get("require_publication_dates", False)),
            freshness_days_news=int(item.get("freshness_days_news", 30)),
            freshness_days_official_docs=int(item.get("freshness_days_official_docs", 365)),
            freshness_days_security_advisory=int(item.get("freshness_days_security_advisory", 180)),
            freshness_days_general=int(item.get("freshness_days_general", 120)),
        )
        if profile.profile_id in seen_ids:
            raise TrustSourceProfileError(
                f"Duplicate managed trust source profile id: {profile.profile_id!r}."
            )
        seen_ids.add(profile.profile_id)
        profiles.append(profile)
    return tuple(profiles)


def list_managed_trust_source_profiles(
    profile_file: str | Path | None = None,
) -> tuple[dict[str, Any], ...]:
    source_path = _resolve_profile_path(profile_file)
    profiles = load_managed_trust_source_profiles(source_path)
    return tuple(
        {
            "profile_id": profile.profile_id,
            "display_name": profile.display_name,
            "description": profile.description,
            "policy_version": profile.policy_version,
            "approved_by": profile.approved_by,
            "approval_id": profile.approval_id,
            "approved_at": profile.approved_at,
            "high_trust_domains": list(profile.high_trust_domains),
            "medium_trust_domains": list(profile.medium_trust_domains),
            "allowed_domains": list(profile.allowed_domains),
        }
        for profile in profiles
    )


def apply_managed_trust_source_profile(
    settings: LiveDataSettings,
    risk_level: str,
) -> tuple[LiveDataSettings, ManagedTrustSourceResolution | None]:
    if risk_level not in _VALID_RISK_LEVELS:
        raise TrustSourceProfileError(f"Invalid risk level: {risk_level!r}.")

    profile_id = settings.trust_profile_id.strip()
    if not profile_id:
        return settings, None

    source_path = _resolve_profile_path(settings.trust_profile_file or None)
    profiles = load_managed_trust_source_profiles(source_path)
    profile = next((item for item in profiles if item.profile_id == profile_id), None)
    if profile is None:
        raise TrustSourceProfileError(
            f"Managed trust source profile '{profile_id}' not found in {source_path}."
        )

    managed_allowed = tuple(
        sorted(
            {
                *profile.allowed_domains,
                *profile.high_trust_domains,
                *profile.medium_trust_domains,
            }
        )
    )

    resolved_settings = replace(
        settings,
        allowed_domains=managed_allowed,
        high_trust_domains=profile.high_trust_domains,
        medium_trust_domains=profile.medium_trust_domains,
        min_trusted_citations=max(
            settings.min_trusted_citations,
            profile.min_trusted_citations_by_risk[risk_level],
        ),
        min_independent_trusted_domains=max(
            settings.min_independent_trusted_domains,
            profile.min_independent_trusted_domains_by_risk[risk_level],
        ),
        enforce_freshness=profile.enforce_freshness,
        require_publication_dates=profile.require_publication_dates,
        freshness_days_news=profile.freshness_days_news,
        freshness_days_official_docs=profile.freshness_days_official_docs,
        freshness_days_security_advisory=profile.freshness_days_security_advisory,
        freshness_days_general=profile.freshness_days_general,
    )
    resolution = ManagedTrustSourceResolution(
        profile_id=profile.profile_id,
        profile_version=profile.policy_version,
        approved_by=profile.approved_by,
        approval_id=profile.approval_id,
        approved_at=profile.approved_at,
        source_path=_display_source_path(source_path),
        risk_level=risk_level,
    )
    return resolved_settings, resolution


def _display_source_path(source_path: Path) -> str:
    """Return a stable path label without leaking workstation-specific prefixes."""
    resolved = source_path.expanduser()
    try:
        resolved = resolved.resolve()
    except OSError:
        pass

    lifeguard_root = Path(__file__).resolve().parents[2]
    repo_root = lifeguard_root.parent
    for base in (repo_root, lifeguard_root):
        try:
            return str(resolved.relative_to(base))
        except ValueError:
            continue
    return str(resolved)


def _resolve_profile_path(profile_file: str | Path | None) -> Path:
    if profile_file is not None and str(profile_file).strip():
        resolved = Path(str(profile_file)).expanduser()
    else:
        env_path = os.getenv("LIFEGUARD_TRUST_SOURCE_PROFILE_FILE", "").strip()
        if env_path:
            resolved = Path(env_path).expanduser()
        else:
            resolved = default_trust_source_profile_path()

    if not resolved.exists():
        raise TrustSourceProfileError(
            f"Managed trust source profile file does not exist: {resolved}"
        )
    return resolved


def _validate_risk_mapping(mapping: dict[str, int], label: str) -> None:
    keys = set(mapping.keys())
    if keys != _VALID_RISK_LEVELS:
        raise TrustSourceProfileError(
            f"{label} must contain exactly the keys {sorted(_VALID_RISK_LEVELS)}."
        )
    for key, value in mapping.items():
        if value < 0:
            raise TrustSourceProfileError(f"{label}.{key} must be non-negative.")
