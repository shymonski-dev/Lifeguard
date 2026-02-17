from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .live_intelligence import LiveDataReport
from .spec_schema import AgentSpec

_VALID_DECISIONS = {"accept", "reject", "defer"}


class LegislativeReviewError(ValueError):
    """Raised when legislative review artifacts are missing or invalid."""


@dataclass(frozen=True)
class LegislativeReviewArtifacts:
    pack_path: Path
    decision_path: Path


def spec_sha256(spec: AgentSpec) -> str:
    payload = spec.to_dict()
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def payload_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def resolve_legislative_review_artifacts(
    *,
    spec: AgentSpec,
    evidence_path: str | Path,
) -> LegislativeReviewArtifacts:
    evidence_file = Path(evidence_path)
    base_dir = evidence_file.parent

    decision_raw = spec.legislative_review.decision_file.strip()
    if decision_raw:
        decision_path = Path(decision_raw)
        if not decision_path.is_absolute():
            decision_path = base_dir / decision_path
    else:
        decision_path = base_dir / "legislative_review_decision.json"

    pack_path = decision_path.parent / "legislative_review_pack.json"
    return LegislativeReviewArtifacts(
        pack_path=pack_path,
        decision_path=decision_path,
    )


def build_legislative_review_pack(
    *,
    spec: AgentSpec,
    jurisdiction_reports: tuple[tuple[str, LiveDataReport], ...],
) -> dict[str, Any]:
    spec_hash = spec_sha256(spec)
    jurisdictions_payload: list[dict[str, Any]] = []
    for jurisdiction, report in jurisdiction_reports:
        jurisdictions_payload.append(
            {
                "jurisdiction": jurisdiction,
                "provider": report.provider,
                "model": report.model,
                "query": report.query,
                "fetched_at": report.fetched_at,
                "summary": report.summary,
                "citation_count": len(report.citations),
                "attempts": [item.to_dict() for item in report.attempts],
                "trust_assessment": report.assessment.to_dict(),
                "citations": [
                    {
                        "url": citation.url,
                        "title": citation.title,
                        "domain": citation.domain,
                        "trust_tier": citation.trust_tier,
                        "source_type": citation.source_type,
                        "published_at": citation.published_at,
                        "freshness_window_days": citation.freshness_window_days,
                        "age_days": citation.age_days,
                        "is_fresh": citation.is_fresh,
                    }
                    for citation in report.citations
                ],
            }
        )

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "spec_name": spec.name,
        "spec_sha256": spec_hash,
        "legal_context": {
            "jurisdictions": list(spec.legal_context.jurisdictions),
            "intended_use": spec.legal_context.intended_use,
            "sector": spec.legal_context.sector,
            "decision_impact_level": spec.legal_context.decision_impact_level,
            "compliance_target_date": spec.legal_context.compliance_target_date,
            "data_categories": list(spec.legal_context.data_categories),
        },
        "legislative_review_settings": {
            "provider": spec.legislative_review.provider,
            "model": spec.legislative_review.model,
            "max_results": spec.legislative_review.max_results,
            "min_citations": spec.legislative_review.min_citations,
            "timeout_seconds": spec.legislative_review.timeout_seconds,
            "united_kingdom_trust_profile_id": spec.legislative_review.united_kingdom_trust_profile_id,
            "european_union_trust_profile_id": spec.legislative_review.european_union_trust_profile_id,
            "trust_profile_file": spec.legislative_review.trust_profile_file,
            "strict": spec.legislative_review.strict,
            "require_human_decision": spec.legislative_review.require_human_decision,
        },
        "jurisdictions": jurisdictions_payload,
        "decision_support": {
            "jurisdiction_count": len(jurisdictions_payload),
            "total_citations": sum(item.get("citation_count", 0) for item in jurisdictions_payload),
            "trusted_citations": sum(
                int(item.get("trust_assessment", {}).get("trusted_citation_count", 0))
                for item in jurisdictions_payload
            ),
            "independent_trusted_domains": sorted(
                {
                    domain
                    for item in jurisdictions_payload
                    for domain in item.get("trust_assessment", {}).get(
                        "independent_trusted_domains", []
                    )
                }
            ),
        },
        "review_guidance": (
            "This pack is generated for human review. Confirm applicability to the intended use, "
            "confirm effective dates, and record a decision with rationale."
        ),
    }


def build_legislative_decision_template(
    *,
    spec: AgentSpec,
    pack_sha256: str,
    jurisdictions: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "version": 1,
        "decision": "",
        "reviewed_by": "",
        "review_id": "",
        "reviewed_at": "",
        "notes": "",
        "spec_name": spec.name,
        "spec_sha256": spec_sha256(spec),
        "pack_sha256": pack_sha256,
        "jurisdictions": list(jurisdictions),
    }


def load_json_file(path: Path) -> object:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LegislativeReviewError(f"Failed to read file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LegislativeReviewError(f"File is not valid JSON: {exc}") from exc
    return payload


def validate_legislative_decision(
    *,
    payload: object,
    spec: AgentSpec,
    required_jurisdictions: tuple[str, ...],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise LegislativeReviewError("Legislative decision payload must be a JSON object.")

    decision = str(payload.get("decision", "")).strip().lower()
    reviewed_by = str(payload.get("reviewed_by", "")).strip()
    review_id = str(payload.get("review_id", "")).strip()
    reviewed_at = str(payload.get("reviewed_at", "")).strip()
    notes = str(payload.get("notes", "")).strip()
    spec_name = str(payload.get("spec_name", "")).strip()
    spec_hash = str(payload.get("spec_sha256", "")).strip()
    pack_hash = str(payload.get("pack_sha256", "")).strip()

    jurisdictions_raw = payload.get("jurisdictions", [])
    jurisdictions: list[str] = []
    if isinstance(jurisdictions_raw, list):
        jurisdictions = [str(item).strip() for item in jurisdictions_raw if str(item).strip()]

    errors: list[str] = []
    if decision not in _VALID_DECISIONS:
        errors.append(f"decision must be one of {sorted(_VALID_DECISIONS)}.")
    if not reviewed_by:
        errors.append("reviewed_by must not be empty.")
    if not review_id:
        errors.append("review_id must not be empty.")
    if not reviewed_at:
        errors.append("reviewed_at must not be empty.")
    if not spec_name:
        errors.append("spec_name must not be empty.")
    if spec_name and spec_name != spec.name:
        errors.append("spec_name does not match the current specification.")
    expected_spec_hash = spec_sha256(spec)
    if spec_hash and spec_hash != expected_spec_hash:
        errors.append("spec_sha256 does not match the current specification.")
    if required_jurisdictions:
        missing = sorted(set(required_jurisdictions) - set(jurisdictions))
        if missing:
            errors.append("jurisdictions is missing: " + ", ".join(missing))

    if errors:
        raise LegislativeReviewError("Legislative decision validation failed: " + "; ".join(errors))

    return {
        "version": int(payload.get("version", 1) or 1),
        "decision": decision,
        "reviewed_by": reviewed_by,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "notes": notes,
        "spec_name": spec_name,
        "spec_sha256": expected_spec_hash,
        "pack_sha256": pack_hash,
        "jurisdictions": jurisdictions,
    }

